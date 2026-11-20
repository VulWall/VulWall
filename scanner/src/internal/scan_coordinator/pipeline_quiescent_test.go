package scan_coordinator

import (
	"context"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
)

// fakeStreams is an in-memory view of streams and groups. onRead, when set, runs before each
// read of a stream, so a test can change the state between two reads.
type fakeStreams struct {
	lastID  map[string]string
	groupz  map[string]map[string]redis.XInfoGroup
	onRead  func(stream string)
	pending map[StreamGroup][]time.Duration
}

func (f *fakeStreams) lastGeneratedID(_ context.Context, stream string) (string, error) {
	if f.onRead != nil {
		f.onRead(stream)
	}
	if id, ok := f.lastID[stream]; ok {
		return id, nil
	}
	return "0-0", nil
}

func (f *fakeStreams) groups(_ context.Context, stream string) (map[string]redis.XInfoGroup, error) {
	return f.groupz[stream], nil
}

// drainedPipeline returns every scan-pipeline group caught up at id 5-0 with nothing pending.
func drainedPipeline() *fakeStreams {
	f := &fakeStreams{lastID: map[string]string{}, groupz: map[string]map[string]redis.XInfoGroup{}}
	for _, sg := range scanPipelineGroups() {
		f.lastID[sg.Stream] = "5-0"
		if f.groupz[sg.Stream] == nil {
			f.groupz[sg.Stream] = map[string]redis.XInfoGroup{}
		}
		f.groupz[sg.Stream][sg.Group] = redis.XInfoGroup{Name: sg.Group, LastDeliveredID: "5-0"}
	}
	return f
}

func TestPipelineQuiescent_DrainedPipeline(t *testing.T) {
	ok, err := pipelineQuiescent(context.Background(), drainedPipeline(), scanPipelineGroups())
	if err != nil || !ok {
		t.Fatalf("pipelineQuiescent() = %v, %v; want true", ok, err)
	}
}

// The bug from the e2e run: domain discovery held its one job (pending=1) while it resolved
// thousands of names; every downstream group was idle and the scan was closed.
func TestPipelineQuiescent_DiscoveryJobInFlightBlocks(t *testing.T) {
	for _, sg := range []StreamGroup{
		{shared.StreamDomainDiscoveryQueue, "domain_discovery_service"},
		{shared.StreamIPDiscoveryQueue, "port_discovery_service"},
	} {
		t.Run(sg.Group, func(t *testing.T) {
			f := drainedPipeline()
			g := f.groupz[sg.Stream][sg.Group]
			g.Pending = 1
			f.groupz[sg.Stream][sg.Group] = g

			ok, err := pipelineQuiescent(context.Background(), f, scanPipelineGroups())
			if err != nil || ok {
				t.Fatalf("pipelineQuiescent() = %v, %v; want false while %s has a pending job", ok, err, sg.Group)
			}
		})
	}
}

func TestPipelineQuiescent_UndeliveredDiscoveryJobBlocks(t *testing.T) {
	f := drainedPipeline()
	f.lastID[shared.StreamDomainDiscoveryQueue] = "6-0" // queued, not read yet

	ok, err := pipelineQuiescent(context.Background(), f, scanPipelineGroups())
	if err != nil || ok {
		t.Fatalf("pipelineQuiescent() = %v, %v; want false", ok, err)
	}
}

// Discovery publishes its last result and then ACKs its job while the monitor is between two
// reads. Whatever read the event lands before, the upstream-first order never reports the
// pipeline quiescent: either the queue is read before the ACK (pending=1), or after it, and
// then the results stream is read after the publish too. The same event in the reverse order
// does produce a false "quiescent", which is why the order is part of the contract.
func TestPipelineQuiescent_PublishThenAckBetweenReads(t *testing.T) {
	run := func(groups []StreamGroup, eventBeforeRead int) bool {
		f := drainedPipeline()
		q := f.groupz[shared.StreamDomainDiscoveryQueue]["domain_discovery_service"]
		q.Pending = 1
		f.groupz[shared.StreamDomainDiscoveryQueue]["domain_discovery_service"] = q

		reads := 0
		f.onRead = func(string) {
			if reads == eventBeforeRead {
				f.lastID[shared.StreamDomainDiscoveryResults] = "6-0" // publish ...
				q.Pending = 0                                         // ... then ACK
				f.groupz[shared.StreamDomainDiscoveryQueue]["domain_discovery_service"] = q
			}
			reads++
		}
		ok, err := pipelineQuiescent(context.Background(), f, groups)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	forward := scanPipelineGroups()
	for k := 0; k <= len(forward); k++ {
		if run(forward, k) {
			t.Errorf("upstream-first order: event before read %d reported quiescent", k)
		}
	}

	reversed := make([]StreamGroup, len(forward))
	for i, sg := range forward {
		reversed[len(forward)-1-i] = sg
	}
	falsePositive := false
	for k := 0; k <= len(reversed); k++ {
		falsePositive = falsePositive || run(reversed, k)
	}
	if !falsePositive {
		t.Error("reverse order never reported quiescent; the test no longer models the race")
	}
}
