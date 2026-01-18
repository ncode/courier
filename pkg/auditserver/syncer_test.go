package auditserver

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

type fakeLogical struct {
	readData    map[string]*api.Secret
	writes      []writeRecord
	deleteCount int
}

type writeRecord struct {
	Path string
	Data map[string]interface{}
}

func (f *fakeLogical) Read(path string) (*api.Secret, error) {
	if sec, ok := f.readData[path]; ok {
		return sec, nil
	}
	return nil, nil
}

func (f *fakeLogical) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	f.writes = append(f.writes, writeRecord{Path: path, Data: data})
	return nil, nil
}

func (f *fakeLogical) Delete(path string) (*api.Secret, error) {
	f.deleteCount++
	return nil, nil
}

func TestVaultSyncer_WriteToDestinations(t *testing.T) {
	sourceLogical := &fakeLogical{
		readData: map[string]*api.Secret{
			"secret/data/demo": {
				Data: map[string]interface{}{
					"data": map[string]interface{}{"foo": "bar"},
				},
			},
		},
	}
	dest1 := &fakeLogical{}
	dest2 := &fakeLogical{}

	syncer := &VaultSyncer{
		logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})),
		source: sourceLogical,
		destinations: []clientWithAddress{
			{address: "dest1", client: dest1},
			{address: "dest2", client: dest2},
		},
	}

	if err := syncer.Handle(UpdateEvent{Kind: UpdateKindKV, Path: "secret/data/demo", Operation: "update"}); err != nil {
		t.Fatalf("syncer returned error: %v", err)
	}

	if len(dest1.writes) != 1 || len(dest2.writes) != 1 {
		t.Fatalf("expected writes on both destinations, got %d and %d", len(dest1.writes), len(dest2.writes))
	}

	if dest1.writes[0].Data["data"].(map[string]interface{})["foo"] != "bar" {
		t.Fatalf("unexpected payload in dest1: %#v", dest1.writes[0].Data)
	}
	if dest2.writes[0].Data["data"].(map[string]interface{})["foo"] != "bar" {
		t.Fatalf("unexpected payload in dest2: %#v", dest2.writes[0].Data)
	}
}

func TestVaultSyncer_DeleteFromDestinations(t *testing.T) {
	sourceLogical := &fakeLogical{
		readData: map[string]*api.Secret{
			"secret/data/demo": {
				Data: map[string]interface{}{
					"data": map[string]interface{}{"foo": "bar"},
				},
			},
		},
	}
	dest1 := &fakeLogical{}
	dest2 := &fakeLogical{}

	syncer := &VaultSyncer{
		logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})),
		source: sourceLogical,
		destinations: []clientWithAddress{
			{address: "dest1", client: dest1},
			{address: "dest2", client: dest2},
		},
	}

	if err := syncer.Handle(UpdateEvent{Kind: UpdateKindKV, Path: "secret/data/demo", Operation: "delete"}); err != nil {
		t.Fatalf("syncer returned error: %v", err)
	}

	// Allow any async logs to flush
	time.Sleep(10 * time.Millisecond)

	if dest1.deleteCount != 1 || dest2.deleteCount != 1 {
		t.Fatalf("expected delete on both destinations, got %d and %d", dest1.deleteCount, dest2.deleteCount)
	}
}
