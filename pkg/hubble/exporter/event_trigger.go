// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"sync"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/time"
)

// bufferedEvent is a candidate event kept for the pre-trigger retention
// window together with the time at which it was received by this node.
type bufferedEvent struct {
	receivedAt time.Time
	event      *v1.Event
}

// eventTrigger implements event-triggered capture. Candidate events are
// buffered until an event matching the trigger filters is received, at which
// point the buffered events still within the pre-trigger retention window are
// emitted first, followed by the trigger event and by the subsequent candidate
// events until the post-trigger capture window ends. Trigger events received
// while a capture window is open extend the deadline.
//
// The buffer is drained whenever a capture starts and it is never populated
// while a capture is in progress, therefore an event can never be emitted
// twice, even if multiple triggers fire back to back.
type eventTrigger struct {
	triggerFilters      filters.FilterFuncs
	preTriggerDuration  time.Duration
	postTriggerDuration time.Duration
	bufferMaxEvents     int

	// now is overridable in tests. All window computations use the node
	// receive time of the events, never the timestamps carried by the flows.
	now func() time.Time

	mu        sync.Mutex
	buffer    []*bufferedEvent
	capturing bool
	// deadline is the end of the current post-trigger capture window,
	// inclusive. Its zero value is meaningless while not capturing.
	deadline time.Time
}

func newEventTrigger(triggerFilters filters.FilterFuncs, preTriggerDuration, postTriggerDuration time.Duration, bufferMaxEvents int) *eventTrigger {
	return &eventTrigger{
		triggerFilters:      triggerFilters,
		preTriggerDuration:  preTriggerDuration,
		postTriggerDuration: postTriggerDuration,
		bufferMaxEvents:     bufferMaxEvents,
		now:                 time.Now,
	}
}

// onEvent feeds one candidate event (i.e. an event that already passed the
// flowlog include/exclude filters) and returns the events that must be written
// out, in receive order. The returned slice may be empty when the event is
// only buffered. The returned events must not be retained by the caller beyond
// encoding.
func (t *eventTrigger) onEvent(ev *v1.Event) []*v1.Event {
	receivedAt := eventReceiveTime(ev, t.now())

	t.mu.Lock()
	defer t.mu.Unlock()

	// An event arriving after the deadline ends the previous capture. The
	// event itself is handled below as a regular candidate, which means it
	// may start a brand-new capture if it is a trigger.
	if t.capturing && receivedAt.After(t.deadline) {
		t.endCapture()
	}

	isTrigger := t.triggerFilters.MatchOne(ev)

	if !t.capturing {
		if !isTrigger {
			t.bufferEvent(receivedAt, ev)
			return nil
		}

		// Fire: emit the retained context first (in receive order), then
		// the trigger event itself, and open the post-trigger window.
		emitted := t.flushBuffer(receivedAt.Add(-t.preTriggerDuration))
		t.capturing = true
		t.deadline = receivedAt.Add(t.postTriggerDuration)
		return append(emitted, ev)
	}

	// Repeated triggers within an open window only extend the deadline. The
	// triggering event is emitted exactly once, just like any other event in
	// the window.
	if isTrigger {
		t.deadline = receivedAt.Add(t.postTriggerDuration)
	}
	return []*v1.Event{ev}
}

// bufferEvent keeps the event as pre-trigger context. Events outside the
// retention window are dropped first, then the count cap is enforced by
// evicting the earliest events. A fresh backing slice is used so dropped
// events become unreachable and are released as soon as they leave the
// retention window or the buffer cap forces their eviction.
func (t *eventTrigger) bufferEvent(receivedAt time.Time, ev *v1.Event) {
	cutoff := receivedAt.Add(-t.preTriggerDuration)
	kept := make([]*bufferedEvent, 0, len(t.buffer)+1)
	for _, b := range t.buffer {
		if !b.receivedAt.Before(cutoff) {
			kept = append(kept, b)
		}
	}
	kept = append(kept, &bufferedEvent{
		receivedAt: receivedAt,
		event:      ev,
	})

	if excess := len(kept) - t.bufferMaxEvents; excess > 0 {
		// Drop the earliest events while preserving receive order.
		kept = kept[excess:]
	}
	t.buffer = kept
}

// flushBuffer returns the buffered events still within the retention window
// starting at cutoff, in receive order, and releases the buffer.
func (t *eventTrigger) flushBuffer(cutoff time.Time) []*v1.Event {
	if len(t.buffer) == 0 {
		return nil
	}
	emitted := make([]*v1.Event, 0, len(t.buffer))
	for _, b := range t.buffer {
		if !b.receivedAt.Before(cutoff) {
			emitted = append(emitted, b.event)
		}
	}
	t.buffer = nil
	return emitted
}

// endCapture closes an expired capture window without emitting anything.
func (t *eventTrigger) endCapture() {
	t.capturing = false
	t.deadline = time.Time{}
	t.buffer = nil
}

// stop discards all retained state. It is invoked when the flowlog is deleted,
// replaced or stopped; untriggered buffered events are then released without
// being written.
func (t *eventTrigger) stop() {
	t.mu.Lock()
	t.capturing = false
	t.deadline = time.Time{}
	t.buffer = nil
	t.mu.Unlock()
}

// eventReceiveTime returns the time at which the event was received (observed
// in Hubble) on this node. Capture windows are computed exclusively from this
// clock, so flow timestamps arriving out of order never affect them. Events
// carrying no receive timestamp fall back to the provided current time, i.e.
// the moment they reach the exporter.
func eventReceiveTime(ev *v1.Event, fallback time.Time) time.Time {
	if ev != nil && ev.Timestamp != nil && ev.Timestamp.IsValid() {
		return ev.Timestamp.AsTime()
	}
	return fallback
}
