package sys

import (
	"net"
	"sync"
	"testing"
	"time"
)

// A Cancel issued while the Run frame is still being written reaches the
// listener after the Run frame, never before it.
func TestMonitorClientCancelDuringWriteFollowsRun(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	mc := NewMonitorClient(client)
	go func() {
		_, _ = mc.Run([]string{"elevate", "status"}, MonitorStdinNone, nil, &lockedBuf{}, &lockedBuf{})
	}()
	// net.Pipe blocks the Run write until the server reads, so the request
	// is mid-write here.
	deadline := time.Now().Add(2 * time.Second)
	for mc.writing.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("run never started writing")
		}
		time.Sleep(time.Millisecond)
	}
	if mc.active.Load() != 0 {
		t.Fatal("active set before the Run frame was written")
	}
	canceled := make(chan struct{})
	go func() {
		mc.Cancel()
		close(canceled)
	}()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	typ, payload, err := ReadMonitorFrame(server)
	if err != nil || typ != MonitorFrameRun {
		t.Fatalf("first frame type=%d err=%v", typ, err)
	}
	req, err := DecodeMonitorRun(payload)
	if err != nil {
		t.Fatal(err)
	}
	typ, payload, err = ReadMonitorFrame(server)
	if err != nil || typ != MonitorFrameCancel {
		t.Fatalf("second frame type=%d err=%v", typ, err)
	}
	c, err := DecodeMonitorCancel(payload)
	if err != nil || c.ID != req.ID {
		t.Fatalf("cancel id=%d want %d err=%v", c.ID, req.ID, err)
	}
	<-canceled
}

func TestSessionPrincipalsAccessorsNoRace(t *testing.T) {
	s := &Session{ID: "p-race", User: "bob", Principals: []string{"dev"}}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = s.PrincipalList()
				_ = s.Info()
			}
		}()
	}
	for i := 0; i < 500; i++ {
		if !s.AddPrincipal("ops") {
			t.Fatal("add reported present")
		}
		if s.AddPrincipal("ops") {
			t.Fatal("second add reported absent")
		}
		if !s.RemovePrincipal("ops") {
			t.Fatal("remove reported absent")
		}
	}
	close(stop)
	wg.Wait()
	if got := s.PrincipalList(); len(got) != 1 || got[0] != "dev" {
		t.Fatalf("principals = %v", got)
	}
	got := s.PrincipalList()
	got[0] = "mutated"
	if s.PrincipalList()[0] != "dev" {
		t.Fatal("PrincipalList returned the backing slice")
	}
}

func TestUnregisterSessionRunsHooks(t *testing.T) {
	var got []string
	var mu sync.Mutex
	remove := OnSessionUnregister(func(id string) {
		mu.Lock()
		got = append(got, id)
		mu.Unlock()
	})
	defer remove()
	if err := RegisterSession(&Session{ID: "hook-sess", User: "bob"}); err != nil {
		t.Fatal(err)
	}
	UnregisterSession("hook-sess")
	UnregisterSession("hook-sess") // already gone: no second call
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "hook-sess" {
		t.Fatalf("hook calls = %v", got)
	}
}
