// esalat-tunnel — optional WebSocket transport (transport=ws).
//
// The mux does not care what carries it: this file wraps a connection into a
// WebSocket (RFC 6455) and hands the mux a net.Conn. On the wire the session
// therefore looks like a normal wss:// stream — an HTTP Upgrade, then binary
// frames — which is exactly what a CDN or a browser does, so a middlebox has
// nothing unusual to key on.
//
// Client frames are masked, server frames are not, as the RFC requires.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

var errNotWebSocket = errors.New("not a websocket upgrade")

type wsConn struct {
	c      net.Conn
	r      *bufio.Reader
	client bool // client must mask what it sends

	wmu sync.Mutex
	rmu sync.Mutex

	readBuf []byte
}

func (w *wsConn) LocalAddr() net.Addr  { return w.c.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr { return w.c.RemoteAddr() }
func (w *wsConn) Close() error         { return w.c.Close() }

func (w *wsConn) SetDeadline(t time.Time) error {
	_ = w.c.SetReadDeadline(t)
	return w.c.SetWriteDeadline(t)
}
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

// Write sends p as one (or more) binary frames.
func (w *wsConn) Write(p []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 1<<16 {
			n = 1 << 16
		}
		if err := w.writeFrame(opBinary, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (w *wsConn) writeFrame(op byte, payload []byte) error {
	n := len(payload)
	mask := w.client
	var hdr [14]byte
	hdr[0] = 0x80 | op // FIN + opcode
	var hl int
	switch {
	case n < 126:
		hdr[1] = byte(n)
		hl = 2
	case n < 1<<16:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
		hl = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
		hl = 10
	}
	if mask {
		hdr[1] |= 0x80
	}
	if _, err := w.c.Write(hdr[:hl]); err != nil {
		return err
	}
	if !mask {
		_, err := w.c.Write(payload)
		return err
	}
	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	if _, err := w.c.Write(key[:]); err != nil {
		return err
	}
	buf := make([]byte, n)
	for i := range payload {
		buf[i] = payload[i] ^ key[i&3]
	}
	_, err := w.c.Write(buf)
	return err
}

// Read returns payload bytes from data frames; control frames are answered
// inline and never surfaced.
func (w *wsConn) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for {
		if len(w.readBuf) > 0 {
			n := copy(p, w.readBuf)
			w.readBuf = w.readBuf[n:]
			return n, nil
		}
		op, payload, err := w.readFrame()
		if err != nil {
			return 0, err
		}
		switch op {
		case opBinary, opText, opContinuation:
			w.readBuf = payload
		case opPing:
			w.wmu.Lock()
			_ = w.writeFrame(opPong, payload)
			w.wmu.Unlock()
		case opPong:
			// ignore
		case opClose:
			w.wmu.Lock()
			_ = w.writeFrame(opClose, nil)
			w.wmu.Unlock()
			return 0, io.EOF
		default:
			// unknown opcode: ignore payload
		}
	}
}

func (w *wsConn) readFrame() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(w.r, h[:]); err != nil {
		return 0, nil, err
	}
	op := h[0] & 0x0F
	masked := h[1]&0x80 != 0
	n := int(h[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.r, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.r, ext[:]); err != nil {
			return 0, nil, err
		}
		v := binary.BigEndian.Uint64(ext[:])
		if v > 1<<24 {
			return 0, nil, fmt.Errorf("ws: frame too large (%d)", v)
		}
		n = int(v)
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(w.r, key[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(w.r, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= key[i&3]
			}
		}
	}
	return op, payload, nil
}

// wsServerUpgrade reads an HTTP Upgrade request from r and answers it.
// wsServerUpgrade tries the RFC 6455 handshake. On failure it also returns the
// bytes it already consumed, so the caller can replay them to the decoy backend
// instead of silently eating a real request.
func wsServerUpgrade(c net.Conn, r *bufio.Reader, path string) (*wsConn, []byte, error) {
	req, consumed, err := readUpgradeRequest(c, r)
	if err != nil {
		return nil, consumed, err
	}
	if !strings.EqualFold(req["upgrade"], "websocket") ||
		!strings.Contains(strings.ToLower(req["connection"]), "upgrade") {
		return nil, consumed, errNotWebSocket
	}
	key := req["sec-websocket-key"]
	if key == "" {
		return nil, consumed, errNotWebSocket
	}
	if path != "" && req["_path"] != path {
		return nil, consumed, fmt.Errorf("ws: unexpected path %q", req["_path"])
	}
	sum := sha1.Sum([]byte(key + wsMagic))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := c.Write([]byte(resp)); err != nil {
		return nil, consumed, err
	}
	return &wsConn{c: c, r: r, client: false}, nil, nil
}

// wsClientDial performs the client half of the upgrade on an established
// connection (already TLS wrapped when transport is ws).
func wsClientDial(c net.Conn, host, path string) (*wsConn, error) {
	if path == "" {
		path = "/"
	}
	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36\r\n" +
		"Accept: */*\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Cache-Control: no-cache\r\n" +
		"Pragma: no-cache\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(c, 64*1024)
	status, headers, err := readUpgradeResponse(br)
	if err != nil {
		return nil, err
	}
	if status != 101 {
		return nil, fmt.Errorf("ws: upgrade refused (HTTP %d)", status)
	}
	want := base64.StdEncoding.EncodeToString(func() []byte { s := sha1.Sum([]byte(key + wsMagic)); return s[:] }())
	if !strings.EqualFold(headers["sec-websocket-accept"], want) {
		return nil, errors.New("ws: bad Sec-WebSocket-Accept")
	}
	return &wsConn{c: c, r: br, client: true}, nil
}

// readUpgradeRequest parses the request line and headers manually: net/http
// would consume bytes we must keep for the tunnel.
func readUpgradeRequest(c net.Conn, r *bufio.Reader) (map[string]string, []byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var consumed []byte
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, consumed, err
	}
	consumed = append(consumed, line...)
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 3 {
		return nil, consumed, errNotWebSocket
	}
	h := map[string]string{"_method": parts[0], "_path": parts[1]}
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return nil, consumed, err
		}
		consumed = append(consumed, l...)
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		if i := strings.Index(l, ":"); i > 0 {
			h[strings.ToLower(strings.TrimSpace(l[:i]))] = strings.TrimSpace(l[i+1:])
		}
	}
	return h, consumed, nil
}

func readUpgradeResponse(r *bufio.Reader) (int, map[string]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, nil, err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return 0, nil, errors.New("ws: malformed status line")
	}
	var code int
	if _, err := fmt.Sscanf(parts[1], "%d", &code); err != nil {
		return 0, nil, err
	}
	h := map[string]string{"_status": parts[1]}
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return 0, nil, err
		}
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		if i := strings.Index(l, ":"); i > 0 {
			h[strings.ToLower(strings.TrimSpace(l[:i]))] = strings.TrimSpace(l[i+1:])
		}
	}
	return code, h, nil
}
