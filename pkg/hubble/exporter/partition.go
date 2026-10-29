// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// DefaultPartitionMaxOpenFiles is the default cap on simultaneously open
	// per-namespace partition files of a single partitioned flowlog.
	DefaultPartitionMaxOpenFiles = 128

	// PartitionFieldSourceNamespace partitions flows by the source endpoint namespace.
	PartitionFieldSourceNamespace PartitionField = "source.namespace"
	// PartitionFieldDestinationNamespace partitions flows by the destination
	// endpoint namespace.
	PartitionFieldDestinationNamespace PartitionField = "destination.namespace"

	// partitionFileSuffix is the suffix of each per-partition file.
	partitionFileSuffix = ".log"

	// defaultPartitionKey is the base name of the catch-all partition for events
	// that do not carry the selected namespace. It contains a character ('_')
	// that is not allowed in Kubernetes namespace names and never appears in
	// sanitized namespace keys (such bytes are percent-encoded), so it can never
	// collide with a real namespace partition.
	defaultPartitionKey = "_no_namespace"

	// maxPartitionKeyLength caps the length of sanitized partition keys
	// (excluding the file suffix) to keep file names within common filesystem
	// limits.
	maxPartitionKeyLength = 200

	// hashedPartitionKeyPrefix is used for over-long namespace values which are
	// replaced by a stable hash. The leading underscore cannot be produced by
	// sanitizePartitionKey, so hashed keys can never collide with regular ones.
	hashedPartitionKeyPrefix = "_ns-"
)

var errPartitionManagerClosed = errors.New("partition manager is closed")

// PartitionField identifies the flow field whose namespace value is used to
// partition exported events into per-namespace files.
type PartitionField string

// Validate ensures the partition field is one of the supported values.
func (f PartitionField) Validate() error {
	switch f {
	case PartitionFieldSourceNamespace, PartitionFieldDestinationNamespace:
		return nil
	default:
		return fmt.Errorf("invalid partition field %q: must be %q or %q",
			string(f), PartitionFieldSourceNamespace, PartitionFieldDestinationNamespace)
	}
}

// PartitionOutputConfig configures namespace-partitioned file output for a
// single flowlog.
type PartitionOutputConfig struct {
	// Field selects the flow field whose namespace value determines the target
	// partition file.
	Field PartitionField

	// Directory is the directory under which one file per partition is created.
	// Every partition file is guaranteed to reside within this directory.
	Directory string

	// MaxOpenFiles caps the number of partition files kept open simultaneously.
	// Once the cap is reached, the least recently used (idle) partition is
	// closed and transparently reopened (appending to the same file) when
	// traffic for it resumes. A zero value means DefaultPartitionMaxOpenFiles.
	MaxOpenFiles int

	// NewPartitionWriter builds the writer for a single partition file. The
	// filename argument is an absolute path residing within Directory. Each
	// partition gets its own writer and therefore its own independent file
	// rotation and compression configuration.
	NewPartitionWriter func(filename string) (io.WriteCloser, error)
}

// partition holds the per-partition output state.
type partition struct {
	key     string
	element *list.Element
	writer  io.WriteCloser
	encoder Encoder
	// aggregator is lazily created when field aggregation is enabled. Keeping
	// one aggregator per partition guarantees that flows from different
	// partitions are never aggregated together.
	aggregator *Aggregator
}

// partitionManager distributes events across per-namespace files under a
// configured directory. Partition files are opened lazily, reused on access,
// evicted (closed) in least-recently-used order once the open-file cap is
// reached, and reopened on demand.
type partitionManager struct {
	logger *slog.Logger
	opts   Options

	mu         lock.Mutex
	partitions map[string]*partition
	// lru orders partitions by most recent use, most recently used at the front.
	lru    *list.List
	closed bool

	// aggregating is true when field aggregation is active and the aggregation
	// interval is positive.
	aggregating bool
	stop        chan struct{}
	wg          sync.WaitGroup
}

// newPartitionManager creates a partitionManager and ensures the output
// directory exists. No partition files are opened until the first event is
// exported.
func newPartitionManager(logger *slog.Logger, opts Options) (*partitionManager, error) {
	directory := opts.partition.Directory
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create partition directory %q: %w", directory, err)
	}
	pm := &partitionManager{
		logger:     logger.With(slog.String(logfields.LogSubsys, "hubble-flowlog-partitions")),
		opts:       opts,
		partitions: make(map[string]*partition),
		lru:        list.New(),
	}
	pm.aggregating = opts.FieldAggregate.Active() && opts.aggregationInterval > 0
	return pm, nil
}

// startAggregation launches the periodic aggregation flush goroutine. It must
// only be called when field aggregation is active.
func (pm *partitionManager) startAggregation() {
	pm.stop = make(chan struct{})
	pm.wg.Add(1)
	go pm.run()
}

// keyForEvent determines the partition key of an event from the original
// event, before any field masking is applied. Events without the selected
// namespace (including non-flow events) are assigned to the default partition.
func (pm *partitionManager) keyForEvent(ev *v1.Event) string {
	if f := ev.GetFlow(); f != nil {
		var namespace string
		switch pm.opts.partition.Field {
		case PartitionFieldSourceNamespace:
			namespace = f.GetSource().GetNamespace()
		case PartitionFieldDestinationNamespace:
			namespace = f.GetDestination().GetNamespace()
		}
		if key := sanitizePartitionKey(namespace); key != "" {
			return key
		}
	}
	return defaultPartitionKey
}

// addAggregated adds a flow event to the per-partition aggregator. The event is
// expected to carry a *flowpb.Flow.
func (pm *partitionManager) addAggregated(key string, ev *v1.Event) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.closed {
		return errPartitionManagerClosed
	}
	p, err := pm.getOrCreate(key)
	if err != nil {
		return err
	}
	pm.touch(p)
	p.aggregator.Add(ev)
	return nil
}

// encode writes an export event to the file of the given partition.
func (pm *partitionManager) encode(key string, exportEvent *observerpb.ExportEvent) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.closed {
		return errPartitionManagerClosed
	}
	p, err := pm.getOrCreate(key)
	if err != nil {
		return err
	}
	pm.touch(p)
	if err := p.encoder.Encode(exportEvent); err != nil {
		pm.logger.Error("Failed to write partition file; releasing it so it can be reopened",
			logfields.Error, err,
			slog.String("partition", p.key),
		)
		pm.evict(p.element)
		return err
	}
	return nil
}

// close stops aggregation, flushes pending aggregated data, closes all open
// partition files and releases their resources. It is idempotent.
func (pm *partitionManager) close() error {
	// Wait for the aggregation goroutine's final flush before closing files.
	if pm.aggregating && pm.stop != nil {
		close(pm.stop)
		pm.wg.Wait()
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.closed {
		return nil
	}
	pm.closed = true

	var errs error
	for el := pm.lru.Front(); el != nil; el = el.Next() {
		p := el.Value.(*partition)
		// The aggregation goroutine already performed a final flush, but flush
		// again in case the manager was created without the runner; an empty
		// aggregator is a no-op and cannot produce duplicate records.
		if p.aggregator != nil {
			p.aggregator.Export(p.encoder)
		}
		if err := p.writer.Close(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to close partition file for %q: %w", p.key, err))
		}
	}
	pm.lru.Init()
	pm.partitions = make(map[string]*partition)
	return errs
}

// getOrCreate returns the partition for key, lazily opening its file. When the
// open-file cap is reached, idle (least recently used) partitions are closed
// first. Caller must hold pm.mu.
func (pm *partitionManager) getOrCreate(key string) (*partition, error) {
	if p, ok := pm.partitions[key]; ok {
		return p, nil
	}

	// Enforce the cap on simultaneously open files by closing idle partitions.
	for pm.lru.Len() >= pm.opts.partition.MaxOpenFiles {
		if !pm.evict(pm.lru.Back()) {
			break
		}
	}

	filename, err := partitionFilePath(pm.opts.partition.Directory, key)
	if err != nil {
		return nil, err
	}
	writer, err := pm.opts.partition.NewPartitionWriter(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open partition file %q: %w", filename, err)
	}
	encoder, err := pm.opts.NewEncoderFunc()(writer)
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("failed to create encoder for partition file %q: %w", filename, err)
	}

	p := &partition{
		key:     key,
		writer:  writer,
		encoder: encoder,
	}
	if pm.aggregating {
		p.aggregator = NewAggregatorWithFields(pm.opts.FieldAggregate, pm.logger)
	}
	p.element = pm.lru.PushFront(p)
	pm.partitions[key] = p
	return p, nil
}

// touch marks the partition as most recently used. Caller must hold pm.mu.
func (pm *partitionManager) touch(p *partition) {
	pm.lru.MoveToFront(p.element)
}

// evict flushes and closes the given partition and removes it from the active
// set. Already received data is flushed (aggregated records) and persisted
// before the file is closed; a later event for the partition reopens the same
// file and appends to it. It returns false when the element was not an active
// partition. Caller must hold pm.mu.
func (pm *partitionManager) evict(el *list.Element) bool {
	if el == nil {
		return false
	}
	p, ok := el.Value.(*partition)
	if !ok {
		return false
	}
	if p.aggregator != nil {
		p.aggregator.Export(p.encoder)
	}
	if err := p.writer.Close(); err != nil {
		pm.logger.Error("Failed to close idle partition file",
			logfields.Error, err,
			slog.String("partition", p.key),
		)
	}
	pm.lru.Remove(el)
	delete(pm.partitions, p.key)
	return true
}

// run periodically flushes per-partition aggregators; it performs a final
// flush when stopped.
func (pm *partitionManager) run() {
	defer pm.wg.Done()
	ticker := time.NewTicker(pm.opts.aggregationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stop:
			pm.flushAll()
			return
		case <-ticker.C:
			pm.flushAll()
		}
	}
}

// flushAll exports aggregated flows of every open partition to its own file.
func (pm *partitionManager) flushAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for el := pm.lru.Front(); el != nil; el = el.Next() {
		p := el.Value.(*partition)
		if p.aggregator != nil {
			p.aggregator.Export(p.encoder)
		}
	}
}

// sanitizePartitionKey converts a namespace name into a stable file name
// component. Kubernetes namespace names already only contain lowercase
// letters, digits and '-' and pass through unchanged; all other bytes are
// percent-encoded, which makes the mapping injective and prevents directory
// traversal or separator injection. An empty namespace yields an empty key,
// which callers map to the default partition.
func sanitizePartitionKey(namespace string) string {
	if namespace == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(namespace))
	for i := 0; i < len(namespace); i++ {
		c := namespace[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	key := b.String()
	if len(key) > maxPartitionKeyLength {
		sum := sha256.Sum256([]byte(namespace))
		return hashedPartitionKeyPrefix + hex.EncodeToString(sum[:])[:32]
	}
	return key
}

// partitionFilePath joins the partition directory and key into a file path and
// guarantees the result stays within the directory.
func partitionFilePath(directory, key string) (string, error) {
	if !validPartitionKey(key) {
		return "", fmt.Errorf("invalid partition key %q", key)
	}
	dir := filepath.Clean(directory)
	filename := filepath.Join(dir, key+partitionFileSuffix)

	// Defense in depth: ensure the resolved file cannot escape the configured
	// directory even on platforms with multiple separator semantics.
	rel, err := filepath.Rel(dir, filename)
	if err != nil {
		return "", fmt.Errorf("failed to resolve partition file path %q: %w", filename, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("partition file %q would escape directory %q", filename, dir)
	}
	return filename, nil
}

// validPartitionKey reports whether key has the shape produced by
// sanitizePartitionKey or is the default partition key.
func validPartitionKey(key string) bool {
	if key == "" {
		return false
	}
	if key == defaultPartitionKey || strings.HasPrefix(key, hashedPartitionKeyPrefix) {
		return true
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '%', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
