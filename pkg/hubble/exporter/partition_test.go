// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/lumberjack/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	timestamp "google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/time"
)

// realPartitionWriter returns production-like lumberjack writers for a
// partition file.
func realPartitionWriter(filename string) (io.WriteCloser, error) {
	return FileWriter(FileWriterConfig{
		Filename:   filename,
		MaxSize:    10,
		MaxBackups: 2,
		Compress:   false,
	})()
}

func partitionTestOptions(t *testing.T, dir string, field PartitionField, maxOpenFiles int,
	newWriter func(string) (io.WriteCloser, error), opts ...Option,
) Options {
	t.Helper()
	options := DefaultOptions
	all := append([]Option{WithPartitionedOutput(PartitionOutputConfig{
		Field:              field,
		Directory:          dir,
		MaxOpenFiles:       maxOpenFiles,
		NewPartitionWriter: newWriter,
	})}, opts...)
	for _, o := range all {
		require.NoError(t, o(&options))
	}
	return options
}

func readPartitionFile(t *testing.T, dir, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	return string(content)
}

func dirEntryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSanitizePartitionKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		expected  string
	}{
		{name: "empty maps to default by caller", namespace: "", expected: ""},
		{name: "plain kubernetes namespace", namespace: "kube-system", expected: "kube-system"},
		{name: "dot is encoded", namespace: "a.b", expected: "a%2Eb"},
		{name: "path traversal is encoded", namespace: "../../etc/passwd", expected: "%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"},
		{name: "backslash is encoded", namespace: `a\b`, expected: "a%5Cb"},
		{name: "uppercase is encoded", namespace: "UPPER", expected: "%55%50%50%45%52"},
		{name: "underscore cannot collide with default key", namespace: defaultPartitionKey, expected: "%5Fno%5Fnamespace"},
		{name: "unicode is encoded", namespace: "namé", expected: "nam%C3%A9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, sanitizePartitionKey(tc.namespace))
		})
	}

	t.Run("long namespaces are replaced by a stable hash", func(t *testing.T) {
		long := strings.Repeat("a", maxPartitionKeyLength+50)
		got := sanitizePartitionKey(long)
		assert.Len(t, got, len(hashedPartitionKeyPrefix)+32)
		assert.True(t, strings.HasPrefix(got, hashedPartitionKeyPrefix))
		// stable across calls
		assert.Equal(t, got, sanitizePartitionKey(long))
		// cannot collide with regular names
		assert.NotEqual(t, got, sanitizePartitionKey(got))
	})
}

func TestPartitionFilePath(t *testing.T) {
	dir := t.TempDir()

	filename, err := partitionFilePath(dir, "kube-system")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "kube-system.log"), filename)

	// Default key is allowed even though it contains an underscore.
	filename, err = partitionFilePath(dir, defaultPartitionKey)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, defaultPartitionKey+".log"), filename)

	for _, key := range []string{"", "..", "../evil", "a/b", `a\b`, "a b", "_other"} {
		_, err := partitionFilePath(dir, key)
		assert.Error(t, err, "key %q must be rejected", key)
	}
}

func TestPartitionedExportRoutingBySourceNamespace(t *testing.T) {
	dir := t.TempDir()
	opts := partitionTestOptions(t, dir, PartitionFieldSourceNamespace, 4, realPartitionWriter)
	ex, err := newExporter(hivetest.Logger(t), opts)
	require.NoError(t, err)

	events := []*v1.Event{
		{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-a", PodName: "pod-a1"}, Verdict: flowpb.Verdict_FORWARDED}},
		{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-b", PodName: "pod-b1"}, Verdict: flowpb.Verdict_FORWARDED}},
		// missing source namespace, destination namespace must not matter
		{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{Namespace: "ns-c", PodName: "pod-c1"}, Verdict: flowpb.Verdict_DROPPED}},
		{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-a", PodName: "pod-a2"}, Verdict: flowpb.Verdict_FORWARDED}},
		// non-flow events lack a namespace and go to the default partition too
		{Timestamp: &timestamp.Timestamp{Seconds: 42}, Event: &flowpb.AgentEvent{}},
	}
	for _, ev := range events {
		require.NoError(t, ex.Export(t.Context(), ev))
	}
	require.NoError(t, ex.Stop())

	assert.ElementsMatch(t,
		[]string{"ns-a.log", "ns-b.log", "_no_namespace.log"},
		dirEntryNames(t, dir),
	)

	nsA := readPartitionFile(t, dir, "ns-a.log")
	assert.Contains(t, nsA, "pod-a1")
	assert.Contains(t, nsA, "pod-a2")
	assert.NotContains(t, nsA, "pod-b1")
	assert.NotContains(t, nsA, "pod-c1")

	nsB := readPartitionFile(t, dir, "ns-b.log")
	assert.Contains(t, nsB, "pod-b1")
	assert.NotContains(t, nsB, "pod-a1")

	def := readPartitionFile(t, dir, "_no_namespace.log")
	assert.Contains(t, def, `"verdict":"DROPPED"`)
	assert.Contains(t, def, "agent_event")
	assert.NotContains(t, def, "pod-a1")
	assert.NotContains(t, def, "pod-b1")
}

func TestPartitionedExportRoutingByDestinationNamespace(t *testing.T) {
	dir := t.TempDir()
	opts := partitionTestOptions(t, dir, PartitionFieldDestinationNamespace, 4, realPartitionWriter)
	ex, err := newExporter(hivetest.Logger(t), opts)
	require.NoError(t, err)

	events := []*v1.Event{
		// source ns-a, destination ns-b: must land in ns-b
		{Event: &flowpb.Flow{
			Source:      &flowpb.Endpoint{Namespace: "ns-a", PodName: "pod-a1"},
			Destination: &flowpb.Endpoint{Namespace: "ns-b", PodName: "pod-b1"},
		}},
		// no destination namespace: default partition
		{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-a", PodName: "pod-a2"}}},
	}
	for _, ev := range events {
		require.NoError(t, ex.Export(t.Context(), ev))
	}
	require.NoError(t, ex.Stop())

	assert.ElementsMatch(t,
		[]string{"ns-b.log", "_no_namespace.log"},
		dirEntryNames(t, dir),
	)
	assert.Contains(t, readPartitionFile(t, dir, "ns-b.log"), "pod-b1")
	assert.Contains(t, readPartitionFile(t, dir, "_no_namespace.log"), "pod-a2")
}

func TestPartitionedExportFiltersAndMaskDoNotChangeRouting(t *testing.T) {
	dir := t.TempDir()
	log := hivetest.Logger(t)
	// Filters select ns-a on the original event. The field mask excludes all
	// namespace fields, so routing must happen before masking.
	opts := partitionTestOptions(t, dir, PartitionFieldSourceNamespace, 4, realPartitionWriter,
		WithAllowList(log, []*flowpb.FlowFilter{{SourcePod: []string{"ns-a/"}}}),
		WithFieldMask([]string{"verdict"}),
	)
	ex, err := newExporter(log, opts)
	require.NoError(t, err)

	require.NoError(t, ex.Export(t.Context(), &v1.Event{
		Event: &flowpb.Flow{
			Source:  &flowpb.Endpoint{Namespace: "ns-a", PodName: "pod-a1"},
			Verdict: flowpb.Verdict_FORWARDED,
		},
	}))
	// Filtered out: must not create a partition file even though it is
	// processed before field masking.
	require.NoError(t, ex.Export(t.Context(), &v1.Event{
		Event: &flowpb.Flow{
			Source:  &flowpb.Endpoint{Namespace: "ns-b", PodName: "pod-b1"},
			Verdict: flowpb.Verdict_FORWARDED,
		},
	}))
	require.NoError(t, ex.Stop())

	assert.ElementsMatch(t, []string{"ns-a.log"}, dirEntryNames(t, dir))
	content := readPartitionFile(t, dir, "ns-a.log")
	assert.Contains(t, content, `"verdict":"FORWARDED"`)
	assert.NotContains(t, content, "namespace", "namespace field is masked out")
	assert.NotContains(t, content, "pod-a1")
}

func TestPartitionedExportAggregationIsolation(t *testing.T) {
	dir := t.TempDir()
	opts := partitionTestOptions(t, dir, PartitionFieldSourceNamespace, 4, realPartitionWriter,
		WithAggregationInterval(50*time.Millisecond),
		WithFieldAggregate([]string{"verdict"}),
	)
	ex, err := newExporter(hivetest.Logger(t), opts)
	require.NoError(t, err)

	// Two flows with identical aggregation key apart from their source
	// namespace: they must never be merged into one aggregate record.
	for _, ns := range []string{"ns-a", "ns-b"} {
		require.NoError(t, ex.Export(t.Context(), &v1.Event{
			Event: &flowpb.Flow{
				Source:  &flowpb.Endpoint{Namespace: ns, PodName: "pod"},
				Verdict: flowpb.Verdict_FORWARDED,
			},
		}))
	}

	require.Eventually(t, func() bool {
		entries := dirEntryNames(t, dir)
		return len(entries) == 2
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, ex.Stop())

	for _, name := range []string{"ns-a.log", "ns-b.log"} {
		content := readPartitionFile(t, dir, name)
		count := aggregatedUnknownDirectionCount(t, content)
		assert.Equal(t, 1, count, "partition %s must keep its own aggregate count", name)
		assert.NotContains(t, content, `"unknown_direction_flow_count":2`,
			"different partitions must not be merged")
	}
}

func aggregatedUnknownDirectionCount(t *testing.T, content string) int {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(content))
	count := 0
	for dec.More() {
		var record map[string]any
		require.NoError(t, dec.Decode(&record))
		flow, ok := record["flow"].(map[string]any)
		require.True(t, ok)
		aggregate, ok := flow["aggregate"].(map[string]any)
		require.True(t, ok)
		count += int(aggregate["unknown_direction_flow_count"].(float64))
	}
	return count
}

func TestPartitionLRUEvictionReopensSameFile(t *testing.T) {
	dir := t.TempDir()
	var opens, closes atomic.Int64
	countingWriter := func(filename string) (io.WriteCloser, error) {
		w, err := realPartitionWriter(filename)
		if err != nil {
			return nil, err
		}
		opens.Add(1)
		return &trackingWriteCloser{WriteCloser: w, closes: &closes}, nil
	}

	// Only a single partition file may be open at a time.
	opts := partitionTestOptions(t, dir, PartitionFieldSourceNamespace, 1, countingWriter)
	ex, err := newExporter(hivetest.Logger(t), opts)
	require.NoError(t, err)

	export := func(ns, pod string) {
		require.NoError(t, ex.Export(t.Context(), &v1.Event{
			Event: &flowpb.Flow{
				Source:  &flowpb.Endpoint{Namespace: ns, PodName: pod},
				Verdict: flowpb.Verdict_FORWARDED,
			},
		}))
	}

	export("ns-a", "pod-a1") // opens ns-a
	assert.Equal(t, int64(1), opens.Load())
	export("ns-b", "pod-b1") // evicts (closes) ns-a, opens ns-b
	assert.Equal(t, int64(2), opens.Load())
	assert.Equal(t, int64(1), closes.Load())
	export("ns-a", "pod-a2") // evicts ns-b, reopens the same ns-a file
	assert.Equal(t, int64(3), opens.Load())
	assert.Equal(t, int64(2), closes.Load())

	require.NoError(t, ex.Stop())
	assert.Equal(t, int64(3), closes.Load(), "Stop releases the last open partition file")

	// Reopening appends to the existing file instead of truncating it, so
	// already received data is not lost.
	nsA := readPartitionFile(t, dir, "ns-a.log")
	assert.Contains(t, nsA, "pod-a1")
	assert.Contains(t, nsA, "pod-a2")
	assert.NotContains(t, nsA, "pod-b1")
	nsB := readPartitionFile(t, dir, "ns-b.log")
	assert.Contains(t, nsB, "pod-b1")
}

func TestPartitionLRUEvictionFlushesPendingAggregates(t *testing.T) {
	dir := t.TempDir()
	// Very long interval so that periodic flushing cannot mask the data loss:
	// the only way pending aggregates reach the file is eviction/stop flushing.
	opts := partitionTestOptions(t, dir, PartitionFieldSourceNamespace, 1, realPartitionWriter,
		WithAggregationInterval(time.Hour),
		WithFieldAggregate([]string{"verdict"}),
	)
	ex, err := newExporter(hivetest.Logger(t), opts)
	require.NoError(t, err)

	export := func(ns string) {
		require.NoError(t, ex.Export(t.Context(), &v1.Event{
			Event: &flowpb.Flow{
				Source:  &flowpb.Endpoint{Namespace: ns},
				Verdict: flowpb.Verdict_FORWARDED,
			},
		}))
	}

	export("ns-a") // pending in ns-a aggregator
	export("ns-b") // evicts ns-a and must flush its pending aggregate first

	nsA := readPartitionFile(t, dir, "ns-a.log")
	assert.Equal(t, 1, aggregatedUnknownDirectionCount(t, nsA),
		"aggregated data received before the partition was closed must not be lost")

	require.NoError(t, ex.Stop())
	nsB := readPartitionFile(t, dir, "ns-b.log")
	assert.Equal(t, 1, aggregatedUnknownDirectionCount(t, nsB))
}

type trackingWriteCloser struct {
	io.WriteCloser
	closes *atomic.Int64
}

func (w *trackingWriteCloser) Close() error {
	w.closes.Add(1)
	return w.WriteCloser.Close()
}

func TestPartitionManagerCloseAndRejectAfterStop(t *testing.T) {
	dir := t.TempDir()
	closed := make(map[string]*atomic.Bool)
	newWriter := func(filename string) (io.WriteCloser, error) {
		b := &atomic.Bool{}
		closed[filename] = b
		return &fakePartitionWriteCloser{closed: b}, nil
	}
	opts := partitionTestOptions(t, dir, PartitionFieldSourceNamespace, 4, newWriter)
	ex, err := newExporter(hivetest.Logger(t), opts)
	require.NoError(t, err)

	require.NoError(t, ex.Export(t.Context(), &v1.Event{
		Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-a"}},
	}))
	require.NoError(t, ex.Export(t.Context(), &v1.Event{
		Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-b"}},
	}))
	require.Len(t, closed, 2)
	for _, b := range closed {
		assert.False(t, b.Load())
	}

	require.NoError(t, ex.Stop())
	for filename, b := range closed {
		assert.True(t, b.Load(), "partition file %s must be closed on Stop", filename)
	}
	assert.True(t, ex.partitions.closed)

	// Idempotent stop.
	require.NoError(t, ex.Stop())

	// No new files may be opened after close.
	err = ex.Export(t.Context(), &v1.Event{
		Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-c"}},
	})
	assert.ErrorIs(t, err, errPartitionManagerClosed)
	assert.Len(t, closed, 2)
}

type fakePartitionWriteCloser struct {
	closed *atomic.Bool
}

func (f *fakePartitionWriteCloser) Write(p []byte) (int, error) {
	if f.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (f *fakePartitionWriteCloser) Close() error {
	f.closed.Store(true)
	return nil
}

func TestPartitionFactoryWiresRotationConfig(t *testing.T) {
	dir := t.TempDir()
	factory := &exporterFactory{hivetest.Logger(t)}
	exp, err := factory.Create(&FlowLogConfig{
		Name:           "p1",
		FileMaxSizeMB:  7,
		FileMaxBackups: 9,
		FileCompress:   true,
		Partition: &FlowLogPartitionConfig{
			Field:        "source.namespace",
			Directory:    dir,
			MaxOpenFiles: 3,
		},
	})
	require.NoError(t, err)
	ex := exp.(*exporter)
	require.NotNil(t, ex.partitions)
	assert.Equal(t, 3, ex.opts.partition.MaxOpenFiles)
	// Partition files are opened lazily: nothing is open before the first event.
	assert.Empty(t, ex.partitions.partitions)

	require.NoError(t, ex.Export(t.Context(), &v1.Event{
		Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-a"}},
	}))
	require.Len(t, ex.partitions.partitions, 1)
	writer, ok := ex.partitions.partitions["ns-a"].writer.(*lumberjack.Logger)
	require.True(t, ok)
	assert.Equal(t, 7, writer.MaxSize)
	assert.Equal(t, 9, writer.MaxBackups)
	assert.True(t, writer.Compress)
	require.NoError(t, ex.Stop())
}

func TestPartitionFlowLogConfigValidation(t *testing.T) {
	dir := t.TempDir()
	parser := &exporterConfigParser{hivetest.Logger(t)}

	t.Run("valid partition config", func(t *testing.T) {
		yaml := `
flowLogs:
- name: p1
  partition:
    field: destination.namespace
    directory: ` + dir + `
    maxOpenFiles: 5
`
		configs, err := parser.Parse(strings.NewReader(yaml))
		require.NoError(t, err)
		cfg := configs["p1"].(*FlowLogConfig)
		require.NotNil(t, cfg.Partition)
		assert.Equal(t, "destination.namespace", cfg.Partition.Field)
		assert.Equal(t, dir, cfg.Partition.Directory)
		assert.Equal(t, 5, cfg.Partition.MaxOpenFiles)
		assert.Empty(t, cfg.FilePath)
	})

	for _, tc := range []struct {
		name        string
		yaml        string
		errContains string
	}{
		{
			name: "invalid field",
			yaml: `
flowLogs:
- name: p1
  partition:
    field: source.pod_name
    directory: ` + dir + `
`,
			errContains: "invalid partition field",
		},
		{
			name: "missing directory",
			yaml: `
flowLogs:
- name: p1
  partition:
    field: source.namespace
`,
			errContains: "directory is required",
		},
		{
			name: "filePath and partition are mutually exclusive",
			yaml: `
flowLogs:
- name: p1
  filePath: /tmp/p1.log
  partition:
    field: source.namespace
    directory: ` + dir + `
`,
			errContains: "filePath must be empty",
		},
		{
			name: "negative maxOpenFiles",
			yaml: `
flowLogs:
- name: p1
  partition:
    field: source.namespace
    directory: ` + dir + `
    maxOpenFiles: -1
`,
			errContains: "maxOpenFiles must be >= 0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.Parse(strings.NewReader(tc.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}

	t.Run("duplicated partition directories", func(t *testing.T) {
		yaml := `
flowLogs:
- name: p1
  partition:
    field: source.namespace
    directory: ` + dir + `
- name: p2
  partition:
    field: source.namespace
    directory: ` + dir + `
`
		_, err := parser.Parse(strings.NewReader(yaml))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicated flowlog partition directory")
	})
}

func TestPartitionFlowLogConfigEquals(t *testing.T) {
	a := &FlowLogConfig{Partition: &FlowLogPartitionConfig{
		Field: "source.namespace", Directory: "/tmp/a", MaxOpenFiles: 4,
	}}
	b := &FlowLogConfig{Partition: &FlowLogPartitionConfig{
		Field: "source.namespace", Directory: "/tmp/a", MaxOpenFiles: 4,
	}}
	assert.True(t, a.equals(b))

	b.Partition.MaxOpenFiles = 8
	assert.False(t, a.equals(b))
	b.Partition.MaxOpenFiles = 4
	b.Partition.Field = "destination.namespace"
	assert.False(t, a.equals(b))
	b.Partition.Field = "source.namespace"

	withPartition := &FlowLogConfig{Partition: b.Partition}
	withoutPartition := &FlowLogConfig{FilePath: "/tmp/x.log"}
	assert.False(t, withPartition.equals(withoutPartition))
	assert.False(t, withoutPartition.equals(withPartition))
}

func TestPartitionedFlowLogDynamicReload(t *testing.T) {
	logger := hivetest.Logger(t)
	de := &dynamicExporter{
		logger:           logger,
		exporterFactory:  &exporterFactory{logger},
		managedExporters: make(map[string]*managedExporter),
	}

	dir1 := t.TempDir()
	cfg1 := &FlowLogConfig{
		Name: "p1",
		Partition: &FlowLogPartitionConfig{
			Field: "source.namespace", Directory: dir1, MaxOpenFiles: 2,
		},
	}
	de.onConfigReload(map[string]ExporterConfig{"p1": cfg1}, 1)

	me, ok := de.managedExporters["p1"]
	require.True(t, ok)
	ex := me.exporter.(*exporter)
	require.NotNil(t, ex.partitions)
	oldManager := ex.partitions
	require.NoError(t, ex.Export(t.Context(), &v1.Event{
		Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "ns-a"}},
	}))
	assert.Contains(t, dirEntryNames(t, dir1), "ns-a.log")

	t.Run("replacement stops the old partition manager", func(t *testing.T) {
		dir2 := t.TempDir()
		cfg2 := &FlowLogConfig{
			Name: "p1",
			Partition: &FlowLogPartitionConfig{
				Field: "destination.namespace", Directory: dir2, MaxOpenFiles: 2,
			},
		}
		de.onConfigReload(map[string]ExporterConfig{"p1": cfg2}, 2)

		assert.True(t, oldManager.closed, "replaced partition manager must be closed")
		newME, ok := de.managedExporters["p1"]
		require.True(t, ok)
		newEx := newME.exporter.(*exporter)
		require.NotNil(t, newEx.partitions)
		assert.NotSame(t, oldManager, newEx.partitions)
		assert.False(t, newEx.partitions.closed)
	})

	t.Run("removal stops the partition manager and releases files", func(t *testing.T) {
		de.onConfigReload(map[string]ExporterConfig{}, 3)
		assert.NotContains(t, de.managedExporters, "p1")
	})

	require.NoError(t, de.Stop())
}
