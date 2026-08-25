package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/usestrix/strix/tui/internal/protocol"
)

func writeEnvelopeFrame(writer io.Writer, envelope protocol.Envelope) error {
	raw, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	return writeAll(writer, append(header[:], raw...))
}

func readEnvelopeFrame(reader io.Reader) (protocol.Envelope, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return protocol.Envelope{}, err
	}
	raw := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(reader, raw); err != nil {
		return protocol.Envelope{}, err
	}
	var envelope protocol.Envelope
	return envelope, json.Unmarshal(raw, &envelope)
}

func TestHandshakeValidatesHelloAndSendsReady(t *testing.T) {
	server, connection := net.Pipe()
	client := newClient(connection)
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		payload, _ := json.Marshal(protocol.Hello{Capabilities: protocol.Capabilities})
		if err := writeEnvelopeFrame(server, protocol.Envelope{Version: protocol.Version, Type: "hello", Payload: payload}); err != nil {
			serverErr <- err
			return
		}
		var header [4]byte
		if _, err := io.ReadFull(server, header[:]); err != nil {
			serverErr <- err
			return
		}
		raw := make([]byte, binary.BigEndian.Uint32(header[:]))
		if _, err := io.ReadFull(server, raw); err != nil {
			serverErr <- err
			return
		}
		var ready protocol.Envelope
		if err := json.Unmarshal(raw, &ready); err != nil {
			serverErr <- err
			return
		}
		var readyPayload protocol.Hello
		if err := json.Unmarshal(ready.Payload, &readyPayload); err != nil {
			serverErr <- err
			return
		}
		if ready.Type != "ready" || ready.Version != protocol.Version || !reflect.DeepEqual(readyPayload.Capabilities, protocol.Capabilities) {
			serverErr <- fmt.Errorf("unexpected ready: %#v %#v", ready, readyPayload)
			return
		}
		serverErr <- nil
	}()

	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRejectsMismatchBeforeReady(t *testing.T) {
	server, connection := net.Pipe()
	client := newClient(connection)
	go func() {
		defer server.Close()
		payload, _ := json.Marshal(protocol.Hello{Capabilities: []string{"state-revisions"}})
		_ = writeEnvelopeFrame(server, protocol.Envelope{Version: 2, Type: "hello", Payload: payload})
	}()

	err := client.Handshake()
	if err == nil || !strings.Contains(err.Error(), "protocol mismatch") {
		t.Fatalf("handshake error = %v, want protocol mismatch", err)
	}
}

func TestReadRejectsOversizedCollectionLengthBeforePayload(t *testing.T) {
	server, connection := net.Pipe()
	client := newClient(connection)
	written := make(chan error, 1)
	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], maxCollectionBytes+1)
		_, err := server.Write(header[:])
		written <- err
	}()

	_, err := client.Read()
	if err == nil || !strings.Contains(err.Error(), "invalid TUI IPC message size") {
		t.Fatalf("read error = %v", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	server.Close()
}

func TestClientPreventsDuplicateCommandsAndRequiresExactCorrelation(t *testing.T) {
	connection := &recordingConn{}
	client := newClient(connection)
	requestID, err := client.Send("setup.select_model", map[string]string{"model": "openai/gpt-5"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send("setup.select_model", map[string]string{"model": "openai/gpt-5.1"}); !errors.Is(err, ErrCommandPending) {
		t.Fatalf("duplicate error = %v, want ErrCommandPending", err)
	}
	if client.Resolve("unknown", "setup.select_model") || client.Resolve(requestID, "models.list") {
		t.Fatal("unknown or mismatched result resolved pending request")
	}
	if !client.Resolve(requestID, "setup.select_model") {
		t.Fatal("exact result did not resolve pending request")
	}
	if _, err := client.Send("setup.select_model", map[string]string{"model": "openai/gpt-5.1"}); err != nil {
		t.Fatalf("command remained blocked after success: %v", err)
	}
}

func TestClientRejectsOversizedCommandBeforeWrite(t *testing.T) {
	connection := &recordingConn{}
	client := newClient(connection)
	_, err := client.Send("setup.set_instruction", map[string]string{"instruction": strings.Repeat("x", maxCommandBytes)})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized send error = %v", err)
	}
	if connection.Len() != 0 || len(client.pending) != 0 {
		t.Fatal("oversized command was written or left pending")
	}
}

func TestClientReadsCollectionFrameLargerThanOneMegabyte(t *testing.T) {
	server, connection := net.Pipe()
	client := &Client{conn: connection}
	payload, err := json.Marshal(map[string]string{"content": string(bytes.Repeat([]byte("x"), 2<<20))})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(protocol.Envelope{
		Version: protocol.Version,
		Type:    "collection_bootstrap",
		Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}

	writeErr := make(chan error, 1)
	go func() {
		defer server.Close()
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
		if _, err := server.Write(header[:]); err != nil {
			writeErr <- err
			return
		}
		_, err := server.Write(raw)
		writeErr <- err
	}()

	message, err := client.Read()
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != "collection_bootstrap" {
		t.Fatalf("message type = %q, want collection_bootstrap", message.Type)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func TestClientReadsStateFrameLargerThanControlLimit(t *testing.T) {
	server, connection := net.Pipe()
	client := &Client{conn: connection}
	payload, err := json.Marshal(map[string]string{"content": strings.Repeat("x", maxCommandBytes+1024)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(protocol.Envelope{
		Version: protocol.Version,
		Type:    "state",
		Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}

	writeErr := make(chan error, 1)
	go func() {
		defer server.Close()
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
		if _, err := server.Write(header[:]); err != nil {
			writeErr <- err
			return
		}
		_, err := server.Write(raw)
		writeErr <- err
	}()

	envelope, err := client.Read()
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Type != "state" {
		t.Fatalf("envelope type = %q", envelope.Type)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func TestConnectFromEnvironmentAuthenticatesTCPTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	t.Setenv("STRIX_TUI_ADDR", listener.Addr().String())
	t.Setenv("STRIX_TUI_TOKEN", "one-use-token")
	t.Setenv("STRIX_TUI_FD", "")

	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		token := make([]byte, len("one-use-token"))
		if _, readErr := io.ReadFull(connection, token); readErr != nil {
			serverErr <- readErr
			return
		}
		if string(token) != "one-use-token" {
			serverErr <- os.ErrPermission
			return
		}
		raw, marshalErr := json.Marshal(protocol.Envelope{
			Version: protocol.Version,
			Type:    "hello",
			Payload: json.RawMessage(`{}`),
		})
		if marshalErr != nil {
			serverErr <- marshalErr
			return
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
		if writeErr := writeAll(connection, append(header[:], raw...)); writeErr != nil {
			serverErr <- writeErr
			return
		}
		serverErr <- nil
	}()

	client, err := ConnectFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	message, err := client.Read()
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != "hello" {
		t.Fatalf("message type = %q, want hello", message.Type)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if os.Getenv("STRIX_TUI_ADDR") != "" || os.Getenv("STRIX_TUI_TOKEN") != "" {
		t.Fatal("TCP transport credentials were not removed from the environment")
	}
}

func TestConnectFromEnvironmentRequiresCompleteTransport(t *testing.T) {
	t.Setenv("STRIX_TUI_FD", "")
	t.Setenv("STRIX_TUI_ADDR", "127.0.0.1:1")
	t.Setenv("STRIX_TUI_TOKEN", "")

	_, err := ConnectFromEnvironment()
	if err == nil || !strings.Contains(err.Error(), "STRIX_TUI_ADDR and STRIX_TUI_TOKEN") {
		t.Fatalf("error = %v, want missing transport error", err)
	}
}

func TestConnectFromEnvironmentPrefersInheritedDescriptor(t *testing.T) {
	t.Setenv("STRIX_TUI_FD", "not-a-number")
	t.Setenv("STRIX_TUI_ADDR", "127.0.0.1:1")
	t.Setenv("STRIX_TUI_TOKEN", "token")

	_, err := ConnectFromEnvironment()
	if err == nil || !strings.Contains(err.Error(), "invalid STRIX_TUI_FD") {
		t.Fatalf("error = %v, want inherited descriptor parse error", err)
	}
}
