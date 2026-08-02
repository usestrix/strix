package app

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usestrix/strix/tui/internal/protocol"
)

const (
	maxCommandBytes    = 64 << 10
	maxCollectionBytes = 4 << 20
)

var ErrCommandPending = errors.New("command is already pending")

type Client struct {
	conn           io.ReadWriteCloser
	mu             sync.Mutex
	seq            atomic.Uint64
	pending        map[string]string
	pendingByKey   map[string]string
	requestKeyByID map[string]string
}

// ConnectInherited opens the connected socket descriptor passed by the Python
// parent. No listener, network address, or authentication secret is involved.
func ConnectInherited(fdValue string) (*Client, error) {
	fd, err := strconv.ParseUint(fdValue, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid STRIX_TUI_FD: %w", err)
	}
	file := os.NewFile(uintptr(fd), "strix-tui-ipc")
	if file == nil {
		return nil, fmt.Errorf("invalid STRIX_TUI_FD %d", fd)
	}
	connection, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("open inherited TUI connection: %w", err)
	}
	return newClient(connection), nil
}

func newClient(connection io.ReadWriteCloser) *Client {
	return &Client{
		conn:           connection,
		pending:        map[string]string{},
		pendingByKey:   map[string]string{},
		requestKeyByID: map[string]string{},
	}
}

// ConnectFromEnvironment selects the private transport prepared by the Python
// parent. POSIX uses an inherited descriptor; Windows uses an authenticated
// one-use loopback connection because pass_fds is unavailable there.
func ConnectFromEnvironment() (*Client, error) {
	if fd := os.Getenv("STRIX_TUI_FD"); fd != "" {
		_ = os.Unsetenv("STRIX_TUI_FD")
		return ConnectInherited(fd)
	}

	address := os.Getenv("STRIX_TUI_ADDR")
	token := os.Getenv("STRIX_TUI_TOKEN")
	_ = os.Unsetenv("STRIX_TUI_ADDR")
	_ = os.Unsetenv("STRIX_TUI_TOKEN")
	if address == "" || token == "" {
		return nil, fmt.Errorf("STRIX_TUI_FD or STRIX_TUI_ADDR and STRIX_TUI_TOKEN are required")
	}

	connection, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to TUI backend: %w", err)
	}
	if err := writeAll(connection, []byte(token)); err != nil {
		connection.Close()
		return nil, fmt.Errorf("authenticate to TUI backend: %w", err)
	}
	return newClient(connection), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (c *Client) readEnvelope(maximum uint32) (protocol.Envelope, int, error) {
	var header [4]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return protocol.Envelope{}, 0, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maximum {
		return protocol.Envelope{}, 0, fmt.Errorf("invalid TUI IPC message size: %d", size)
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(c.conn, raw); err != nil {
		return protocol.Envelope{}, 0, err
	}
	var envelope protocol.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return protocol.Envelope{}, 0, err
	}
	return envelope, int(size), nil
}

func (c *Client) Read() (protocol.Envelope, error) {
	envelope, size, err := c.readEnvelope(maxCollectionBytes)
	if err != nil {
		return protocol.Envelope{}, err
	}
	if envelope.Type != "collection_bootstrap" && envelope.Type != "collection_delta" && size > maxCommandBytes {
		return protocol.Envelope{}, fmt.Errorf("TUI control message exceeds %d bytes", maxCommandBytes)
	}
	return envelope, nil
}

// Handshake validates the exact v3 hello and acknowledges readiness. main calls
// this before constructing Bubble Tea, so mismatch errors never enter alt screen.
func (c *Client) Handshake() error {
	if connection, ok := c.conn.(interface{ SetDeadline(time.Time) error }); ok {
		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		defer connection.SetDeadline(time.Time{}) //nolint:errcheck
	}
	envelope, _, err := c.readEnvelope(maxCommandBytes)
	if err != nil {
		return fmt.Errorf("read protocol hello: %w", err)
	}
	if envelope.Version != protocol.Version {
		return fmt.Errorf("protocol mismatch: backend=%d client=%d", envelope.Version, protocol.Version)
	}
	if envelope.Type != "hello" {
		return fmt.Errorf("protocol handshake expected hello, received %q", envelope.Type)
	}
	var hello protocol.Hello
	if err := json.Unmarshal(envelope.Payload, &hello); err != nil {
		return fmt.Errorf("decode protocol hello: %w", err)
	}
	if !reflect.DeepEqual(hello.Capabilities, protocol.Capabilities) {
		return fmt.Errorf("protocol capability mismatch")
	}
	payload, err := json.Marshal(protocol.Hello{Capabilities: protocol.Capabilities})
	if err != nil {
		return err
	}
	return c.sendEnvelope(protocol.Envelope{
		Version: protocol.Version,
		Type:    "ready",
		Payload: payload,
	}, maxCommandBytes)
}

// ProtocolSmoke exercises command correlation, state propagation, and all
// collection bootstraps without starting Bubble Tea or entering alt screen.
func (c *Client) ProtocolSmoke() error {
	if connection, ok := c.conn.(interface{ SetDeadline(time.Time) error }); ok {
		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		defer connection.SetDeadline(time.Time{}) //nolint:errcheck
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("create protocol smoke nonce: %w", err)
	}
	nonce := "protocol-smoke-" + hex.EncodeToString(nonceBytes)
	requestID, err := c.Send("setup.set_instruction", map[string]string{"instruction": nonce})
	if err != nil {
		return fmt.Errorf("send protocol smoke command: %w", err)
	}

	commandComplete := false
	stateComplete := false
	collections := map[string]bool{"agents": false, "events": false, "vulnerabilities": false}
	cursors := map[string]int{}
	revisions := map[string]int{}
	for !commandComplete || !stateComplete || !collections["agents"] || !collections["events"] || !collections["vulnerabilities"] {
		envelope, err := c.Read()
		if err != nil {
			return fmt.Errorf("read protocol smoke response: %w", err)
		}
		if envelope.Version != protocol.Version {
			return fmt.Errorf("protocol smoke version mismatch: %d", envelope.Version)
		}
		switch envelope.Type {
		case "command_result":
			if envelope.RequestID != requestID {
				continue
			}
			var result protocol.CommandResult
			if err := json.Unmarshal(envelope.Payload, &result); err != nil {
				return fmt.Errorf("decode protocol smoke command result: %w", err)
			}
			if result.Command != "setup.set_instruction" || !c.Resolve(requestID, result.Command) {
				return fmt.Errorf("protocol smoke command correlation failed")
			}
			if !result.OK {
				message := "command failed"
				if result.Error != nil && result.Error.Message != "" {
					message = result.Error.Message
				}
				return fmt.Errorf("protocol smoke command failed: %s", message)
			}
			commandComplete = true
		case "state":
			var update protocol.StateUpdate
			if err := json.Unmarshal(envelope.Payload, &update); err != nil {
				return fmt.Errorf("decode protocol smoke state: %w", err)
			}
			if update.State.Instruction == nonce {
				stateComplete = true
			}
		case "collection_bootstrap":
			var chunk protocol.CollectionBootstrap
			if err := json.Unmarshal(envelope.Payload, &chunk); err != nil {
				return fmt.Errorf("decode protocol smoke collection: %w", err)
			}
			if _, ok := collections[chunk.Collection]; !ok {
				return fmt.Errorf("protocol smoke received unknown collection %q", chunk.Collection)
			}
			if chunk.Cursor == 0 {
				cursors[chunk.Collection] = 0
				revisions[chunk.Collection] = chunk.Revision
			}
			if revisions[chunk.Collection] != chunk.Revision || cursors[chunk.Collection] != chunk.Cursor || chunk.NextCursor != chunk.Cursor+len(chunk.Items) {
				return fmt.Errorf("protocol smoke collection cursor mismatch for %s", chunk.Collection)
			}
			cursors[chunk.Collection] = chunk.NextCursor
			if chunk.Done {
				collections[chunk.Collection] = true
			}
		}
	}
	return nil
}

func (c *Client) sendEnvelope(envelope protocol.Envelope, maximum int) error {
	raw, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(raw) > maximum {
		return fmt.Errorf("TUI IPC message exceeds %d bytes", maximum)
	}
	framed := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(raw)))
	copy(framed[4:], raw)
	return writeAll(c.conn, framed)
}

func pendingKey(command string, payload json.RawMessage) string {
	if command == "collection.resync" {
		return command + ":" + string(payload)
	}
	return command
}

func (c *Client) Send(command string, payload any) (string, error) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	requestID := fmt.Sprintf("go-%d", c.seq.Add(1))
	envelope := protocol.Envelope{
		Version: protocol.Version, Type: command, RequestID: requestID, Payload: rawPayload,
	}
	key := pendingKey(command, rawPayload)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending = map[string]string{}
		c.pendingByKey = map[string]string{}
		c.requestKeyByID = map[string]string{}
	}
	if existing := c.pendingByKey[key]; existing != "" {
		return "", fmt.Errorf("%w: %s (%s)", ErrCommandPending, command, existing)
	}
	c.pending[requestID] = command
	c.pendingByKey[key] = requestID
	c.requestKeyByID[requestID] = key
	if err := c.sendEnvelope(envelope, maxCommandBytes); err != nil {
		delete(c.pending, requestID)
		delete(c.pendingByKey, key)
		delete(c.requestKeyByID, requestID)
		return "", err
	}
	return requestID, nil
}

// Resolve accepts only the exact request/command pair that was submitted.
// Unknown or mismatched results remain inert and do not release pending state.
func (c *Client) Resolve(requestID, command string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if requestID == "" || c.pending[requestID] != command {
		return false
	}
	key := c.requestKeyByID[requestID]
	delete(c.pending, requestID)
	delete(c.pendingByKey, key)
	delete(c.requestKeyByID, requestID)
	return true
}

func (c *Client) ExpectedCommand(requestID string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	command, ok := c.pending[requestID]
	return command, ok
}

func (c *Client) Close() error { return c.conn.Close() }
