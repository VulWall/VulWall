package scan_coordinator

import (
	"context"
	"errors"
	"testing"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type fakeConsumerAdmin struct {
	byGroup map[StreamGroup][]redis.XInfoConsumer
	listErr map[StreamGroup]error
	deleted []string
}

func (f *fakeConsumerAdmin) consumers(_ context.Context, stream, group string) ([]redis.XInfoConsumer, error) {
	key := StreamGroup{stream, group}
	if err := f.listErr[key]; err != nil {
		return nil, err
	}
	return f.byGroup[key], nil
}

func (f *fakeConsumerAdmin) deleteConsumer(_ context.Context, stream, group, name string) error {
	f.deleted = append(f.deleted, stream+"/"+group+"/"+name)
	return nil
}

func TestReleaseOrphanedPendingDeletesEveryConsumerOfEveryGroup(t *testing.T) {
	a := StreamGroup{"s1", "g1"}
	b := StreamGroup{"s2", "g2"}
	missing := StreamGroup{"s3", "g3"}
	admin := &fakeConsumerAdmin{
		byGroup: map[StreamGroup][]redis.XInfoConsumer{
			a: {{Name: "old-1", Pending: 2}, {Name: "old-2"}},
			b: {{Name: "old-3", Pending: 1}},
		},
		listErr: map[StreamGroup]error{missing: errors.New("NOGROUP No such key 's3' or consumer group 'g3'")},
	}

	if err := releaseOrphanedPending(context.Background(), admin, []StreamGroup{a, missing, b}, zap.NewNop()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"s1/g1/old-1", "s1/g1/old-2", "s2/g2/old-3"}
	if len(admin.deleted) != len(want) {
		t.Fatalf("deleted %v, want %v", admin.deleted, want)
	}
	for i := range want {
		if admin.deleted[i] != want[i] {
			t.Fatalf("deleted %v, want %v", admin.deleted, want)
		}
	}
}

func TestReleaseOrphanedPendingReturnsOtherErrors(t *testing.T) {
	g := StreamGroup{"s1", "g1"}
	admin := &fakeConsumerAdmin{listErr: map[StreamGroup]error{g: errors.New("connection refused")}}

	if err := releaseOrphanedPending(context.Background(), admin, []StreamGroup{g}, zap.NewNop()); err == nil {
		t.Fatal("expected an error")
	}
}
