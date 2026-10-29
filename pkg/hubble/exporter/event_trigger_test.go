// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/time"
)

var eventTriggerTestBaseTime = time.Unix(1_700_000_000, 0)

func flowEventAt(t *testing.T, uuid string, recv time.Time, dropped bool, flowTime time.Time) *v1.Event {
	t.Helper()
	verdict := flowpb.Verdict_FORWARDED
	if dropped {
		verdict = flowpb.Verdict_DROPPED
	}
	return &v1.Event{
		Timestamp: timestamppb.New(recv),
		Event: &flowpb.Flow{
			Uuid:    uuid,
			Verdict: verdict,
			Time:    timestamppb.New(flowTime),
		},
	}
}

func sourceFlowEventAt(t *testing.T, uuid, namespace string, recv time.Time, dropped bool) *v1.Event {
	t.Helper()
	ev := flowEventAt(t, uuid, recv, dropped, recv)
	ev.Event.(*flowpb.Flow).Source = &flowpb.Endpoint{Namespace: namespace, PodName: "pod"}
	return ev
}

func newTriggerExporter(t *testing.T, buf *bytesWriteCloser, pre, post time.Duration, bufferMaxEvents int) *exporter {
	t.Helper()
	return newTriggerExporterWithFilters(t, buf, pre, post, bufferMaxEvents, nil, nil)
}

func newTriggerExporterWithFilters(t *testing.T, buf *bytesWriteCloser, pre, post time.Duration, bufferMaxEvents int, include, exclude []*flowpb.FlowFilter) *exporter {
	t.Helper()
	log := hivetest.Logger(t)
	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}
	triggerConfig := &EventTriggerConfig{
		TriggerFilters: FlowFilters{
			{Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED}},
		},
		PreTriggerDuration:  Duration(pre),
		PostTriggerDuration: Duration(post),
		BufferMaxEvents:     bufferMaxEvents,
	}
	for _, opt := range []Option{
		WithAllowList(log, include),
		WithDenyList(log, exclude),
		WithEventTrigger(log, triggerConfig),
	} {
		require.NoError(t, opt(&opts))
	}
	ex, err := newExporter(log, opts)
	require.NoError(t, err)
	return ex
}

// emittedUUIDs parses JSON lines written to the buffer and returns the uuid of
// every emitted flow in write order.
func emittedUUIDs(t *testing.T, content string) []string {
	t.Helper()
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	var uuids []string
	for _, line := range strings.Split(content, "\n") {
		var envelope struct {
			Flow struct {
				Uuid string `json:"uuid"`
			} `json:"flow"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &envelope), "invalid json line: %s", line)
		uuids = append(uuids, envelope.Flow.Uuid)
	}
	return uuids
}

func TestEventTriggerBuffersUntilTrigger(t *testing.T) {
	buf := &bytesWriteCloser{}
	// 10s of pre-trigger context, 5s of post-trigger capture, cap of 100.
	ex := newTriggerExporter(t, buf, 10*time.Second, 5*time.Second, 100)

	base := eventTriggerTestBaseTime
	at := func(sec int64) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	// Candidate events are buffered without producing any output.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "a", at(1), false, at(1))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "b", at(2), false, at(2))))
	assert.Empty(t, buf.String(), "candidate events must not be exported before a trigger")
	assert.Len(t, ex.eventTrigger.buffer, 2)

	// Trigger flushes the retained context (in receive order) followed by the
	// trigger event itself.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "c", at(10), true, at(10))))
	assert.Equal(t, []string{"a", "b", "c"}, emittedUUIDs(t, buf.String()))

	// Candidate events within the post-trigger window are exported directly.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "d", at(11), false, at(11))))

	// Event arriving after the window closes is buffered silently again.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "e", at(16), false, at(16))))
	assert.Len(t, ex.eventTrigger.buffer, 1)

	// A new trigger flushes the retained event as context, then reopens a
	// window. Event "e" must be emitted exactly once.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "f", at(20), true, at(20))))
	// The deadline is inclusive.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "g", at(25), false, at(25))))
	// After the extended window closes, events are buffered again.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "h", at(26), false, at(26))))

	assert.Equal(t, []string{"a", "b", "c", "d", "e", "f", "g"}, emittedUUIDs(t, buf.String()))
}

func TestEventTriggerRepeatedTriggerExtendsWindow(t *testing.T) {
	buf := &bytesWriteCloser{}
	ex := newTriggerExporter(t, buf, 10*time.Second, 5*time.Second, 100)

	base := eventTriggerTestBaseTime
	at := func(sec int64) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "a", at(1), false, at(1))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "b", at(10), true, at(10)))) // deadline 15
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "c", at(12), true, at(12)))) // extends to 17
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "d", at(16), false, at(16))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "e", at(18), false, at(18)))) // after extended window

	assert.Equal(t, []string{"a", "b", "c", "d"}, emittedUUIDs(t, buf.String()))
}

func TestEventTriggerZeroDurations(t *testing.T) {
	buf := &bytesWriteCloser{}
	ex := newTriggerExporter(t, buf, 0, 0, 100)

	base := eventTriggerTestBaseTime
	at := func(sec int64) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "a", at(1), false, at(1))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "b", at(2), false, at(2))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "c", at(10), true, at(10))))
	// With a zero post-trigger window, subsequent events are not captured.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "d", at(11), false, at(11))))

	// With a zero pre-trigger duration, no prior context is written.
	assert.Equal(t, []string{"c"}, emittedUUIDs(t, buf.String()))
}

func TestEventTriggerBufferCapEvictsEarliest(t *testing.T) {
	buf := &bytesWriteCloser{}
	ex := newTriggerExporter(t, buf, time.Hour, 0, 2)

	base := eventTriggerTestBaseTime
	at := func(sec int64) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "a", at(1), false, at(1))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "b", at(2), false, at(2))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "c", at(3), false, at(3))))
	assert.Len(t, ex.eventTrigger.buffer, 2, "earliest event must be evicted once the cap is reached")

	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "d", at(10), true, at(10))))

	assert.Equal(t, []string{"b", "c", "d"}, emittedUUIDs(t, buf.String()))
}

func TestEventTriggerPreWindowExpiry(t *testing.T) {
	buf := &bytesWriteCloser{}
	ex := newTriggerExporter(t, buf, 5*time.Second, 0, 100)

	base := eventTriggerTestBaseTime
	at := func(sec int64) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "a", at(1), false, at(1))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "b", at(8), false, at(8))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "c", at(10), true, at(10))))

	// "a" is outside the 5s pre-trigger retention window.
	assert.Equal(t, []string{"b", "c"}, emittedUUIDs(t, buf.String()))
}

func TestEventTriggerRespectsExcludeFilters(t *testing.T) {
	buf := &bytesWriteCloser{}
	ex := newTriggerExporterWithFilters(t, buf, 10*time.Second, 0, 100,
		nil,
		[]*flowpb.FlowFilter{{SourcePod: []string{"bad/"}}},
	)

	base := eventTriggerTestBaseTime
	at := func(sec int64) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	require.NoError(t, ex.Export(t.Context(), sourceFlowEventAt(t, "excluded", "bad", at(1), false)))
	require.NoError(t, ex.Export(t.Context(), sourceFlowEventAt(t, "kept", "good", at(2), false)))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "trigger", at(10), true, at(10))))

	uuids := emittedUUIDs(t, buf.String())
	assert.Equal(t, []string{"kept", "trigger"}, uuids)
	assert.NotContains(t, uuids, "excluded")
	assert.Empty(t, ex.eventTrigger.buffer, "excluded events must never enter the buffer")
}

func TestEventTriggerUsesReceiveTimeNotFlowTime(t *testing.T) {
	buf := &bytesWriteCloser{}
	ex := newTriggerExporter(t, buf, 5*time.Second, 0, 100)

	base := eventTriggerTestBaseTime
	at := func(sec int64) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	// Flow timestamps arrive deliberately out of order (future and past). The
	// capture windows must use the node receive time instead.
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "a", at(1), false, at(100000))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "b", at(8), false, at(-100000))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "c", at(10), true, at(0))))

	// Judged by receive time, "a" (@1) is outside the 5s window while "b" (@8) is in it.
	assert.Equal(t, []string{"b", "c"}, emittedUUIDs(t, buf.String()))
}

func TestEventTriggerStopDiscardsBuffer(t *testing.T) {
	buf := &bytesWriteCloser{}
	ex := newTriggerExporter(t, buf, time.Minute, time.Minute, 100)

	base := eventTriggerTestBaseTime
	at := func(sec int64) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "a", at(1), false, at(1))))
	require.NoError(t, ex.Export(t.Context(), flowEventAt(t, "b", at(2), false, at(2))))
	assert.Len(t, ex.eventTrigger.buffer, 2)
	assert.Empty(t, buf.String())

	require.NoError(t, ex.Stop())

	assert.Nil(t, ex.eventTrigger.buffer, "untriggered buffered events must be discarded and released")
	assert.Empty(t, buf.String(), "buffered events must not be written on stop")
}

func TestEventTriggerEndTimeTakesPrecedence(t *testing.T) {
	file := createEmptyLogFile(t).Name()
	end := time.Now().Add(-time.Hour)
	config := &FlowLogConfig{
		Name:     "trigger-ended",
		FilePath: file,
		End:      &end,
		EventTrigger: &EventTriggerConfig{
			TriggerFilters: FlowFilters{
				{Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED}},
			},
			PreTriggerDuration:  Duration(time.Minute),
			PostTriggerDuration: Duration(time.Minute),
			BufferMaxEvents:     100,
		},
	}

	factory := &exporterFactory{hivetest.Logger(t)}
	exporter, err := factory.Create(config)
	require.NoError(t, err)
	defer func() { _ = exporter.Stop() }()

	base := eventTriggerTestBaseTime
	require.NoError(t, exporter.Export(t.Context(), flowEventAt(t, "a", base, false, base)))
	require.NoError(t, exporter.Export(t.Context(), flowEventAt(t, "trigger", base.Add(time.Second), true, base.Add(time.Second))))

	content, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Empty(t, string(content), "nothing must be buffered or written once the global end time passed")
}

func TestEventTriggerRejectedTogetherWithFieldAggregate(t *testing.T) {
	log := hivetest.Logger(t)
	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return &bytesWriteCloser{}, nil
	}
	for _, opt := range []Option{
		WithFieldAggregate([]string{"verdict"}),
		WithEventTrigger(log, &EventTriggerConfig{
			TriggerFilters:      FlowFilters{{Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED}}},
			PreTriggerDuration:  Duration(time.Second),
			PostTriggerDuration: Duration(time.Second),
			BufferMaxEvents:     10,
		}),
	} {
		require.NoError(t, opt(&opts))
	}

	_, err := newExporter(log, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "field aggregation")
}

func TestEventTriggerInvalidOption(t *testing.T) {
	log := hivetest.Logger(t)

	for _, tc := range []struct {
		name   string
		config *EventTriggerConfig
	}{
		{
			name: "missing trigger filters",
			config: &EventTriggerConfig{
				PreTriggerDuration:  Duration(time.Second),
				PostTriggerDuration: Duration(time.Second),
				BufferMaxEvents:     10,
			},
		},
		{
			name: "negative pre-trigger duration",
			config: &EventTriggerConfig{
				TriggerFilters:      FlowFilters{{Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED}}},
				PreTriggerDuration:  Duration(-time.Second),
				PostTriggerDuration: Duration(time.Second),
				BufferMaxEvents:     10,
			},
		},
		{
			name: "negative post-trigger duration",
			config: &EventTriggerConfig{
				TriggerFilters:      FlowFilters{{Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED}}},
				PreTriggerDuration:  Duration(time.Second),
				PostTriggerDuration: Duration(-time.Second),
				BufferMaxEvents:     10,
			},
		},
		{
			name: "zero buffer cap",
			config: &EventTriggerConfig{
				TriggerFilters:      FlowFilters{{Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED}}},
				PreTriggerDuration:  Duration(time.Second),
				PostTriggerDuration: Duration(time.Second),
			},
		},
		{
			name: "negative buffer cap",
			config: &EventTriggerConfig{
				TriggerFilters:      FlowFilters{{Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED}}},
				PreTriggerDuration:  Duration(time.Second),
				PostTriggerDuration: Duration(time.Second),
				BufferMaxEvents:     -3,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts Options
			assert.Error(t, WithEventTrigger(log, tc.config)(&opts))
			assert.Nil(t, opts.eventTrigger)
		})
	}

	assert.NoError(t, WithEventTrigger(log, nil)(&Options{}), "nil config must leave continuous export enabled")
}

func TestEventTriggerConfigValidation(t *testing.T) {
	// flowLogYAML builds a flowlog entry with every nested line indented under
	// the sequence item so that eventTrigger belongs to the flowlog entry.
	flowLogYAML := func(extraFlowLogLines, eventTriggerLines []string) string {
		var b strings.Builder
		b.WriteString("flowLogs:\n")
		b.WriteString("- name: \"trigger\"\n")
		b.WriteString("  filePath: \"/var/log/trigger.log\"\n")
		for _, l := range extraFlowLogLines {
			b.WriteString("  " + l + "\n")
		}
		if eventTriggerLines != nil {
			b.WriteString("  eventTrigger:\n")
			for _, l := range eventTriggerLines {
				b.WriteString("    " + l + "\n")
			}
		}
		return b.String()
	}
	triggerFilter := "- verdict: [\"DROPPED\"]"

	for _, tc := range []struct {
		name                string
		extraFlowLogLines   []string
		eventTriggerLines   []string
		errContains         string
		wantPreDuration     Duration
		wantBufferMaxEvents int
	}{
		{
			name: "valid",
			eventTriggerLines: []string{
				"triggerFilters:",
				triggerFilter,
				"preTriggerDuration: \"10s\"",
				"postTriggerDuration: \"5s\"",
				"bufferMaxEvents: 100",
			},
			wantPreDuration:     Duration(10 * time.Second),
			wantBufferMaxEvents: 100,
		},
		{
			name: "zero durations are valid",
			eventTriggerLines: []string{
				"triggerFilters:",
				triggerFilter,
				"preTriggerDuration: \"0s\"",
				"postTriggerDuration: \"0s\"",
				"bufferMaxEvents: 1",
			},
			wantPreDuration:     0,
			wantBufferMaxEvents: 1,
		},
		{
			name: "negative pre-trigger duration",
			eventTriggerLines: []string{
				"triggerFilters:",
				triggerFilter,
				"preTriggerDuration: \"-5s\"",
				"postTriggerDuration: \"5s\"",
				"bufferMaxEvents: 100",
			},
			errContains: "preTriggerDuration",
		},
		{
			name: "negative post-trigger duration",
			eventTriggerLines: []string{
				"triggerFilters:",
				triggerFilter,
				"preTriggerDuration: \"5s\"",
				"postTriggerDuration: \"-1s\"",
				"bufferMaxEvents: 100",
			},
			errContains: "postTriggerDuration",
		},
		{
			name: "zero buffer cap",
			eventTriggerLines: []string{
				"triggerFilters:",
				triggerFilter,
				"preTriggerDuration: \"5s\"",
				"postTriggerDuration: \"5s\"",
				"bufferMaxEvents: 0",
			},
			errContains: "bufferMaxEvents",
		},
		{
			name: "negative buffer cap",
			eventTriggerLines: []string{
				"triggerFilters:",
				triggerFilter,
				"preTriggerDuration: \"5s\"",
				"postTriggerDuration: \"5s\"",
				"bufferMaxEvents: -2",
			},
			errContains: "bufferMaxEvents",
		},
		{
			name: "missing buffer cap",
			eventTriggerLines: []string{
				"triggerFilters:",
				triggerFilter,
				"preTriggerDuration: \"5s\"",
				"postTriggerDuration: \"5s\"",
			},
			errContains: "bufferMaxEvents",
		},
		{
			name: "missing trigger filters",
			eventTriggerLines: []string{
				"preTriggerDuration: \"5s\"",
				"postTriggerDuration: \"5s\"",
				"bufferMaxEvents: 100",
			},
			errContains: "triggerFilters",
		},
		{
			name: "combined with field aggregate",
			extraFlowLogLines: []string{
				"fieldAggregate: [\"verdict\"]",
			},
			eventTriggerLines: []string{
				"triggerFilters:",
				triggerFilter,
				"preTriggerDuration: \"5s\"",
				"postTriggerDuration: \"5s\"",
				"bufferMaxEvents: 100",
			},
			errContains: "fieldAggregate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parser := &exporterConfigParser{}
			configs, err := parser.Parse(strings.NewReader(
				flowLogYAML(tc.extraFlowLogLines, tc.eventTriggerLines),
			))
			if tc.errContains != "" {
				require.Error(t, err)
				assert.Nil(t, configs)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}
			require.NoError(t, err)
			require.Contains(t, configs, "trigger")
			cfg := configs["trigger"].(*FlowLogConfig)
			require.NotNil(t, cfg.EventTrigger)
			assert.Equal(t, tc.wantPreDuration, cfg.EventTrigger.PreTriggerDuration)
			assert.Equal(t, tc.wantBufferMaxEvents, cfg.EventTrigger.BufferMaxEvents)
		})
	}
}

func TestEventTriggerDisabledKeepsContinuousExport(t *testing.T) {
	config, err := (&exporterConfigParser{}).Parse(strings.NewReader(`flowLogs:
- name: "plain"
  filePath: "/var/log/plain.log"
`))
	require.NoError(t, err)
	cfg := config["plain"].(*FlowLogConfig)
	assert.Nil(t, cfg.EventTrigger, "event trigger must stay disabled when unconfigured")
}
