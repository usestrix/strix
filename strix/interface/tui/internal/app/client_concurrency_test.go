package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestClientResolvesResponseWhileAnotherWriteIsBlocked(t *testing.T) {
	server, connection := net.Pipe()
	defer server.Close()
	client := newClient(connection)
	defer client.Close()
	firstSent := make(chan error, 1)
	go func() {
		_, err := client.Send("collection.resync", map[string]string{"collection": "events"})
		firstSent <- err
	}()
	first, err := readEnvelopeFrame(server)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-firstSent; err != nil {
		t.Fatal(err)
	}

	secondSent := make(chan error, 1)
	go func() {
		_, err := client.Send("agent.send_message", map[string]string{"agent_id": "root", "message": "continue"})
		secondSent <- err
	}()
	// Leave the request body unread, so the second Write cannot finish.
	var header [4]byte
	if _, err := io.ReadFull(server, header[:]); err != nil {
		t.Fatal(err)
	}
	resolved := make(chan bool, 1)
	go func() {
		command, pending := client.ExpectedCommand(first.RequestID)
		resolved <- pending && command == first.Type && client.Resolve(first.RequestID, command)
	}()

	blocked := false
	select {
	case ok := <-resolved:
		if !ok {
			t.Error("could not correlate the previous command's response")
		}
	case <-time.After(time.Second):
		blocked = true
	}
	// Close must unblock the writer without needing the pending-state mutex.
	client.Close()
	if err := <-secondSent; err == nil {
		t.Error("blocked write unexpectedly succeeded after closing its connection")
	}
	if _, pending := client.ExpectedCommand("go-2"); pending {
		t.Error("failed write left its request pending")
	}
	if blocked {
		<-resolved
		t.Fatal("response processing waited for an unrelated socket write")
	}
}

type shortWriteConn struct {
	bytes.Buffer
	mu sync.Mutex
}

func (c *shortWriteConn) Write(p []byte) (int, error) {
	runtime.Gosched()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Buffer.Write(p[:min(3, len(p))])
}

func (c *shortWriteConn) Close() error { return nil }

func TestClientConcurrentShortWritesPreserveFrames(t *testing.T) {
	connection := &shortWriteConn{}
	client := newClient(connection)
	collections := []string{"agents", "events", "vulnerabilities"}
	errors := make(chan error, len(collections))
	var writers sync.WaitGroup
	for _, collection := range collections {
		writers.Add(1)
		go func() {
			defer writers.Done()
			_, err := client.Send("collection.resync", map[string]string{"collection": collection})
			errors <- err
		}()
	}
	writers.Wait()
	for range collections {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for connection.Len() > 0 {
		var header [4]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			t.Fatal(err)
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > maxCommandBytes {
			t.Fatalf("invalid frame size after concurrent writes: %d", size)
		}
		var frame protocol.Envelope
		if err := json.Unmarshal(connection.Next(int(size)), &frame); err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Collection string `json:"collection"`
		}
		if err := json.Unmarshal(frame.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if frame.Version != protocol.Version || frame.Type != "collection.resync" || seen[payload.Collection] {
			t.Fatalf("unexpected frame: %#v", frame)
		}
		seen[payload.Collection] = true
		if !client.Resolve(frame.RequestID, frame.Type) {
			t.Fatal("frame could not be correlated with its pending request")
		}
	}
	for _, collection := range collections {
		if !seen[collection] {
			t.Fatalf("missing collection request: %s", collection)
		}
	}
}

type failingWriteConn struct {
	started chan struct{}
	release chan struct{}
	writes  atomic.Int32
	once    sync.Once
}

func (c *failingWriteConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *failingWriteConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) == 1 {
		close(c.started)
		<-c.release
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (c *failingWriteConn) Close() error {
	c.once.Do(func() { close(c.release) })
	return nil
}

func TestClientFailedWriteKeepsNewerPendingReservation(t *testing.T) {
	connection := &failingWriteConn{started: make(chan struct{}), release: make(chan struct{})}
	defer connection.Close()
	client := newClient(connection)
	firstSent := make(chan error, 1)
	go func() {
		_, err := client.Send("agent.send_message", map[string]string{"message": "first"})
		firstSent <- err
	}()
	<-connection.started
	// A response can arrive before the sender observes its write error.
	resolved := make(chan bool, 1)
	go func() { resolved <- client.Resolve("go-1", "agent.send_message") }()
	select {
	case ok := <-resolved:
		if !ok {
			t.Fatal("first request was not registered before writing")
		}
	case <-time.After(time.Second):
		connection.Close()
		<-firstSent
		<-resolved
		t.Fatal("response waited for the failing write")
	}

	secondSent := make(chan error, 1)
	go func() {
		_, err := client.Send("agent.send_message", map[string]string{"message": "second"})
		secondSent <- err
	}()
	deadline := time.Now().Add(time.Second)
	reserved := false
	for time.Now().Before(deadline) {
		if _, reserved = client.ExpectedCommand("go-2"); reserved {
			break
		}
		runtime.Gosched()
	}
	connection.Close()
	if err := <-firstSent; !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("first send error = %v, want closed pipe", err)
	}
	if err := <-secondSent; err != nil {
		t.Fatal(err)
	}
	if !reserved {
		t.Fatal("second request was not reserved while awaiting the write lock")
	}
	if _, err := client.Send("agent.send_message", map[string]string{"message": "third"}); !errors.Is(err, ErrCommandPending) {
		t.Fatalf("old write failure released the newer pending key: %v", err)
	}
	if !client.Resolve("go-2", "agent.send_message") {
		t.Fatal("second pending request was lost")
	}
	if _, err := client.Send("agent.send_message", map[string]string{"message": "after resolution"}); err != nil {
		t.Fatalf("resolved pending key remained blocked: %v", err)
	}
}
