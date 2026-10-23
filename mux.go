// esalat-tunnel mux: a tiny multiplexer over one TLS connection.
//
// Layout of a session (everything after the TLS handshake):
//
//	AUTH frame  (client -> server, once)
//	OPEN/DATA/FIN frames in both directions, multiplexed by stream id
//	CREDIT frames carry flow-control window back to the sender
//	PING/PONG keep the session alive and measure rtt
//
// Frame header, 10 bytes, little endian:
//
//	0: type   1: flags   2..5: stream id   6..9: payload length
//
// Flow control: each direction of a stream starts with `window` bytes of
// credit. A sender may only emit as much as it has credit for; the receiver
// grants more credit after the bytes have been written to the local socket.
// A stream therefore can never outrun its peer, and one slow stream cannot
// block the shared connection.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	fOpen   = 1
	fData   = 2
	fFin    = 3
	fCredit = 4
	fPing   = 5
	fPong   = 6
	fAuth   = 9

	hdrLen    = 10
	chunkSize = 16 * 1024
	window    = 1 << 20 // 1 MiB initial credit per direction
	queueCap  = 256     // chunks buffered per stream (> window/chunk, so DATA never blocks the read loop)
	writeQCap = 512
	pingEvery = 10 * time.Second
	pingWait  = 5 * time.Second
)

var errSessionClosed = errors.New("session closed")

type frame struct {
	typ  byte
	id   uint32
	data []byte
	buf  *[]byte // optional pooled buffer, returned to bufPool after the write
}

// ---------------------------------------------------------------- session

type Session struct {
	conn   net.Conn
	rw     *bufio.ReadWriter
	wmu    sync.Mutex
	writeQ chan frame
	closed atomic.Bool
	done   chan struct{}

	smu     sync.Mutex
	streams map[uint32]*Stream
	nextID  atomic.Uint32

	bytesUp   atomic.Int64
	bytesDown atomic.Int64
	lastPong  atomic.Int64 // unix nanos of the most recent pong
	createdAt time.Time
	rtt       atomic.Int64 // microseconds
	err       atomic.Value

	acceptCh chan *Stream
	pool     chan struct{} // limits concurrent session-wide work
}

func newSession(conn net.Conn) *Session {
	return &Session{
		createdAt: time.Now(),
		conn:      conn,
		rw:        bufio.NewReadWriter(bufio.NewReaderSize(conn, 64*1024), bufio.NewWriterSize(conn, 64*1024)),
		writeQ:    make(chan frame, writeQCap),
		done:      make(chan struct{}),
		streams:   map[uint32]*Stream{},
		acceptCh:  make(chan *Stream, 64),
		pool:      make(chan struct{}, 4096),
	}
}

func (s *Session) Close() {
	if s.closed.Swap(true) {
		return
	}
	close(s.done)
	_ = s.conn.Close()
	s.smu.Lock()
	for _, st := range s.streams {
		st.kill()
	}
	s.streams = map[uint32]*Stream{}
	s.smu.Unlock()
}

// write queues a frame; returns false when the session is gone.
func (s *Session) write(f frame) bool {
	if s.closed.Load() {
		return false
	}
	select {
	case s.writeQ <- f:
		return true
	case <-s.done:
		return false
	}
}

// writer drains the queue and batches as many frames as are already waiting
// into a single flush: one syscall per batch instead of one per 16 KiB frame.
func (s *Session) writer() {
	const batch = 64
	for {
		var f frame
		select {
		case f = <-s.writeQ:
		case <-s.done:
			return
		}
		sent := 0
		for {
			if err := s.writeFrame(f, false); err != nil {
				if f.buf != nil {
					putBuf(f.buf)
				}
				s.Close()
				return
			}
			if f.buf != nil {
				putBuf(f.buf)
			}
			sent++
			if sent >= batch {
				break
			}
			select {
			case f = <-s.writeQ:
			case <-s.done:
				break
			default:
				sent = batch
			}
			if sent >= batch {
				break
			}
		}
		s.wmu.Lock()
		err := s.rw.Flush()
		s.wmu.Unlock()
		if err != nil {
			s.Close()
			return
		}
	}
}

func (s *Session) writeFrame(f frame, flush bool) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	var h [hdrLen]byte
	h[0] = f.typ
	binary.LittleEndian.PutUint32(h[2:], f.id)
	binary.LittleEndian.PutUint32(h[6:], uint32(len(f.data)))
	if _, err := s.rw.Write(h[:]); err != nil {
		return err
	}
	if len(f.data) > 0 {
		if _, err := s.rw.Write(f.data); err != nil {
			return err
		}
	}
	s.bytesUp.Add(int64(len(f.data)))
	if flush {
		return s.rw.Flush()
	}
	return nil
}

func (s *Session) register(st *Stream) {
	s.smu.Lock()
	s.streams[st.id] = st
	s.smu.Unlock()
}

func (s *Session) unregister(id uint32) {
	s.smu.Lock()
	if st, ok := s.streams[id]; ok {
		delete(s.streams, id)
		st.kill()
	}
	s.smu.Unlock()
}

func (s *Session) stream(id uint32) *Stream {
	s.smu.Lock()
	st := s.streams[id]
	s.smu.Unlock()
	return st
}

func (s *Session) Open(target string) (*Stream, error) {
	id := s.nextID.Add(2) - 1 // client-initiated streams are odd
	st := newStream(s, id)
	s.register(st)
	if !s.write(frame{typ: fOpen, id: id, data: []byte(target)}) {
		s.unregister(id)
		return nil, errSessionClosed
	}
	return st, nil
}

// reader is the single consumer of the connection.
func (s *Session) reader() {
	buf := make([]byte, 0, chunkSize)
	for {
		var h [hdrLen]byte
		if _, err := io.ReadFull(s.rw, h[:]); err != nil {
			s.fail(err)
			return
		}
		typ := h[0]
		id := binary.LittleEndian.Uint32(h[2:])
		n := int(binary.LittleEndian.Uint32(h[6:]))
		if n < 0 || n > 1<<20 {
			s.fail(fmt.Errorf("bad frame length %d", n))
			return
		}
		if cap(buf) < n {
			buf = make([]byte, n)
		}
		payload := buf[:n]
		if n > 0 {
			if _, err := io.ReadFull(s.rw, payload); err != nil {
				s.fail(err)
				return
			}
		}
		s.bytesDown.Add(int64(n))

		switch typ {
		case fPing:
			cp := append([]byte(nil), payload...)
			s.write(frame{typ: fPong, id: 0, data: cp})
		case fPong:
			if len(payload) == 8 {
				sent := int64(binary.LittleEndian.Uint64(payload))
				now := time.Now().UnixNano()
				s.lastPong.Store(now)
				if lat := now - sent; lat > 0 {
					s.rtt.Store(lat / 1000)
				}
			}
		case fOpen:
			st := newStream(s, id)
			st.openData = append([]byte(nil), payload...)
			s.register(st)
			select {
			case s.acceptCh <- st:
			case <-s.done:
				return
			}
		case fData:
			if st := s.stream(id); st != nil {
				cp := append([]byte(nil), payload...)
				select {
				case st.rq <- cp:
				case <-st.done:
				default:
					// queue full: defensive, only reachable if the peer
					// ignored our window. Drop the stream, not the session.
					s.unregister(id)
				}
			}
		case fCredit:
			if st := s.stream(id); st != nil && len(payload) == 4 {
				st.grant(int(binary.LittleEndian.Uint32(payload)))
			}
		case fFin:
			if st := s.stream(id); st != nil {
				st.remoteClose()
			}
		}
	}
}

func (s *Session) fail(err error) {
	s.err.Store(err.Error())
	s.Close()
}

// keepalive sends a ping every pingEvery and drops the session when a pong
// does not come back within pingWait.
func (s *Session) keepalive() {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			var b [8]byte
			binary.LittleEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
			if !s.write(frame{typ: fPing, id: 0, data: b[:]}) {
				return
			}
			t0 := time.Now()
			deadline := t0.Add(pingWait)
			for {
				if s.lastPong.Load() > t0.UnixNano() {
					break
				}
				if time.Now().After(deadline) {
					s.fail(errors.New("keepalive timeout"))
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		case <-s.done:
			return
		}
	}
}

// Serve starts the reader/writer/keepalive loops and blocks until the session dies.
func (s *Session) Serve() {
	go s.writer()
	go s.keepalive()
	s.reader()
	s.Close()
}

// ---------------------------------------------------------------- stream

type Stream struct {
	id   uint32
	sess *Session
	rq   chan []byte
	done chan struct{}
	once sync.Once

	openData []byte
	credit   atomic.Int64
	waker    chan struct{}
	halfFin  atomic.Bool
	closed   atomic.Bool
	finOnce  sync.Once
}

func newStream(s *Session, id uint32) *Stream {
	st := &Stream{
		id:    id,
		sess:  s,
		rq:    make(chan []byte, queueCap),
		done:  make(chan struct{}),
		waker: make(chan struct{}, 1),
	}
	st.credit.Store(window)
	return st
}

func (st *Stream) grant(n int) {
	if n <= 0 || st.closed.Load() {
		return
	}
	st.credit.Add(int64(n))
	select {
	case st.waker <- struct{}{}:
	default:
	}
}

// takeCredit blocks until at least one byte of credit is available.
func (st *Stream) takeCredit(max int) (int, error) {
	for {
		if st.closed.Load() {
			return 0, io.EOF
		}
		if c := st.credit.Load(); c > 0 {
			n := int64(max)
			if c < n {
				n = c
			}
			st.credit.Add(-n)
			return int(n), nil
		}
		select {
		case <-st.waker:
		case <-st.done:
			return 0, io.EOF
		}
	}
}

// bufPool holds 16 KiB payload buffers. Every DATA frame must own its bytes:
// the session writer runs asynchronously, while the caller (a socket read
// loop) reuses its own buffer immediately.
var bufPool = sync.Pool{New: func() any { b := make([]byte, chunkSize); return &b }}

func putBuf(p *[]byte) {
	if p == nil || cap(*p) < chunkSize {
		return
	}
	*p = (*p)[:chunkSize]
	bufPool.Put(p)
}

// Write sends payload to the peer, respecting the flow-control window.
func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := st.takeCredit(min(len(p), chunkSize))
		if err != nil {
			return total, err
		}
		chunk := p[:n]
		bp := bufPool.Get().(*[]byte)
		cp := append((*bp)[:0], chunk...)
		if !st.sess.write(frame{typ: fData, id: st.id, data: cp, buf: bp}) {
			putBuf(bp)
			return total, errSessionClosed
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Read returns data queued by the peer; it returns io.EOF once the peer closed.
func (st *Stream) Read(p []byte) (int, error) {
	select {
	case b := <-st.rq:
		n := copy(p, b)
		if n < len(b) {
			// shouldn't happen with 16 KiB reads, keep the rest
			st.rq <- b[n:] //nolint:staticcheck // re-queue remainder
		}
		st.sess.write(frame{typ: fCredit, id: st.id, data: le32(uint32(n))})
		return n, nil
	case <-st.done:
		// drain what is left, then EOF
		select {
		case b := <-st.rq:
			n := copy(p, b)
			return n, nil
		default:
			return 0, io.EOF
		}
	}
}

func le32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

// CloseLocal finishes our side: send FIN and stop.
func (st *Stream) CloseLocal() {
	st.finOnce.Do(func() {
		st.halfFin.Store(true)
		st.sess.write(frame{typ: fFin, id: st.id})
	})
}

func (st *Stream) remoteClose() {
	st.kill()
}

func (st *Stream) kill() {
	if st.closed.Swap(true) {
		return
	}
	close(st.done)
	select {
	case st.waker <- struct{}{}:
	default:
	}
}

// Pipe copies between a net.Conn and the stream until either side ends.
func Pipe(c net.Conn, st *Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // local -> stream
		defer wg.Done()
		buf := make([]byte, chunkSize)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				if _, werr := st.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		st.CloseLocal()
		c.Close()
	}()
	go func() { // stream -> local
		defer wg.Done()
		for {
			b, err := st.ReadChunk()
			if err != nil {
				break
			}
			if _, werr := c.Write(b); werr != nil {
				break
			}
		}
		st.CloseLocal()
		c.Close()
	}()
	wg.Wait()
	st.sess.unregister(st.id)
}

// ReadChunk is Read without the caller-supplied buffer, used by Pipe.
func (st *Stream) ReadChunk() ([]byte, error) {
	select {
	case b := <-st.rq:
		st.sess.write(frame{typ: fCredit, id: st.id, data: le32(uint32(len(b)))})
		return b, nil
	case <-st.done:
		select {
		case b := <-st.rq:
			return b, nil
		default:
			return nil, io.EOF
		}
	}
}

// ---------------------------------------------------------------- client pool

type Client struct {
	addr      string
	tlsCfg    *tls.Config
	token     []byte
	sessions  int
	sni       string
	transport string
	wsPath    string
	wsHost    string

	mu      sync.Mutex
	dialing int
	all     []*Session
	up      atomic.Int64
	down    atomic.Int64
	lastLog atomic.Int64
}

func NewClient(addr string, tlsCfg *tls.Config, token string, sessions int) *Client {
	return &Client{addr: addr, tlsCfg: tlsCfg, token: []byte(token), sessions: sessions}
}

// EnsureSessions keeps `sessions` healthy connections to the server. Missing
// sessions are dialled in parallel (one slow dial must not delay the others)
// and the retry backoff is capped low so a server that comes back is picked up
// in a second or two, not after a long exponential wait.
func (c *Client) EnsureSessions(ctx context.Context) {
	const maxBackoff = 1 * time.Second
	backoff := 250 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		live, dialing := 0, 0
		for _, s := range c.all {
			if !s.stale() {
				live++
			}
		}
		dialing = c.dialing
		c.mu.Unlock()

		missing := c.sessions - live - dialing
		if missing > 0 {
			c.mu.Lock()
			c.dialing++
			c.mu.Unlock()
			go func() {
				defer func() { c.mu.Lock(); c.dialing--; c.mu.Unlock() }()
				s, err := c.dial(ctx)
				if err != nil {
					c.logErr("dial " + c.addr + ": " + err.Error())
					return
				}
				c.logErr("") // reset the rate limiter on success
				go s.Serve()
			}()
			time.Sleep(backoff)
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		backoff = 250 * time.Millisecond
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func (c *Client) dial(ctx context.Context) (*Session, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	tuneConn(raw)

	var conn net.Conn = raw
	if c.transport != "tcp" {
		tconn := tls.Client(raw, c.tlsCfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		conn = tconn
	}
	if c.transport == "ws" {
		host := c.wsHost
		if host == "" {
			host = c.sni
		}
		if host == "" {
			host = c.addr
		}
		wc, err := wsClientDial(conn, host, c.wsPath)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = wc
	}
	s := newSession(conn)
	// AUTH = magic + token + random padding (blurs the on-wire size)
	pad := make([]byte, rand.Intn(64))
	rand.Read(pad)
	body := append([]byte("ET1"), c.token...)
	body = append(body, pad...)
	if !s.write(frame{typ: fAuth, id: 0, data: body}) {
		s.Close()
		return nil, errSessionClosed
	}
	c.mu.Lock()
	c.all = append(c.all, s)
	c.mu.Unlock()
	return s, nil
}

// logErr prints connection problems at most once every 10 seconds; an empty
// message just resets the limiter.
func (c *Client) logErr(msg string) {
	now := time.Now().UnixNano()
	if msg == "" {
		c.lastLog.Store(0)
		return
	}
	if last := c.lastLog.Load(); last != 0 && now-last < int64(10*time.Second) {
		return
	}
	c.lastLog.Store(now)
	log.Printf("client: %s", msg)
}

// stale reports whether a session has stopped answering: either it is closed,
// or its last keepalive exchange is too old to trust. Without this a session
// whose peer vanished (host down, firewall drop) keeps looking alive until the
// kernel notices, and every new user connection is handed to a black hole.
func (s *Session) stale() bool {
	if s.closed.Load() {
		return true
	}
	now := time.Now()
	if lp := s.lastPong.Load(); lp > 0 {
		return now.Sub(time.Unix(0, lp)) > 3*pingEvery
	}
	return now.Sub(s.createdAt) > 3*pingEvery
}

// Pick returns the live session with the fewest streams.
func (c *Client) Pick() (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best *Session
	bestN := 1 << 30
	for _, s := range c.all {
		if s.stale() {
			continue
		}
		s.smu.Lock()
		n := len(s.streams)
		s.smu.Unlock()
		if n < bestN {
			best, bestN = s, n
		}
	}
	if best == nil {
		return nil, errors.New("no live session")
	}
	// drop dead sessions occasionally
	if len(c.all) > 16 {
		live := c.all[:0]
		for _, s := range c.all {
			if !s.closed.Load() {
				live = append(live, s)
			}
		}
		c.all = live
	}
	return best, nil
}

func (c *Client) Stats() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	up, down, streams := int64(0), int64(0), 0
	live := 0
	rtt := int64(0)
	for _, s := range c.all {
		up += s.bytesUp.Load()
		down += s.bytesDown.Load()
		s.smu.Lock()
		streams += len(s.streams)
		s.smu.Unlock()
		if !s.closed.Load() {
			live++
			if r := s.rtt.Load(); r > 0 {
				rtt = r
			}
		}
	}
	c.up.Store(up)
	c.down.Store(down)
	return map[string]any{
		"sessions_live": live, "sessions_total": len(c.all), "sessions_want": c.sessions, "dialing": c.dialing,
		"streams_open": streams, "bytes_up": up, "bytes_down": down,
		"rtt_us": rtt,
	}
}

func (c *Client) JSON() []byte {
	b, _ := json.Marshal(c.Stats())
	return b
}

// ---------------------------------------------------------------- server side

// Server accepts tunnel sessions on a listener. Non-tunnel traffic (probes,
// port scanners, a browser hitting the port) is handed to the decoy backend so
// the port answers like a normal HTTPS site.
type Server struct {
	transport     string // tls (default) | ws | tcp
	wsPath        string
	token         []byte
	tlsCfg        *tls.Config
	allow         []string
	decoy         string
	decoyTLS      string
	listener      net.Listener
	streamHandler func(*Stream, string)

	conns   atomic.Int64
	streams atomic.Int64
	errors  atomic.Int64

	smu      sync.Mutex
	sessions map[*Session]struct{}
}

func (s *Server) Serve(ln net.Listener) error {
	s.listener = ln
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		tuneConn(c)
		go s.handle(c)
	}
}

func (s *Server) handle(raw net.Conn) {
	defer raw.Close()
	s.conns.Add(1)
	defer s.conns.Add(-1)

	br := bufio.NewReaderSize(raw, 4096)
	var conn net.Conn = raw

	switch s.transport {
	case "tcp":
		// no TLS, no decoy: only for local testing
		conn = raw
	default:
		raw.SetReadDeadline(time.Now().Add(8 * time.Second))
		first, err := br.Peek(1)
		if err != nil {
			return
		}
		raw.SetReadDeadline(time.Time{})
		if first[0] != 0x16 { // not a TLS handshake: a probe or a browser
			s.decoyPipe(raw, br, false)
			return
		}
		tconn := tls.Server(&bufferedConn{Conn: raw, r: br}, s.tlsCfg)
		if err := tconn.Handshake(); err != nil {
			s.errors.Add(1)
			return
		}
		conn = tconn
	}

	if s.transport == "ws" {
		wbr := bufio.NewReaderSize(conn, 64*1024)
		wc, consumed, err := wsServerUpgrade(conn, wbr, s.wsPath)
		if err != nil {
			// a real browser (or a scanner) asked for something else:
			// replay what we already read so the decoy sees a valid request
			s.decoyPipePrefixed(conn, wbr, consumed)
			return
		}
		conn = wc
	}
	sess := newSession(conn)
	s.trackSession(sess)
	defer s.untrackSession(sess)

	// first frame must be AUTH
	var h [hdrLen]byte
	if _, err := io.ReadFull(sess.rw, h[:]); err != nil {
		return
	}
	if h[0] != fAuth {
		s.errors.Add(1)
		return
	}
	n := int(binary.LittleEndian.Uint32(h[6:]))
	if n < 3+len(s.token) || n > 4096 {
		s.errors.Add(1)
		return
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(sess.rw, body); err != nil {
		return
	}
	if string(body[:3]) != "ET1" || !constTimeEq(body[3:3+len(s.token)], s.token) {
		s.errors.Add(1)
		return
	}
	go sess.Serve()
	for {
		select {
		case st := <-sess.acceptCh:
			s.streams.Add(1)
			go func(st *Stream) {
				defer s.streams.Add(-1)
				defer sess.unregister(st.id)
				s.serveStream(st)
			}(st)
		case <-sess.done:
			return
		}
	}
}

// serveStream reads the target the client asked for, then proxies to it.
func (s *Server) serveStream(st *Stream) {
	target := strings.TrimSpace(string(st.openData))
	if target == "" {
		return
	}
	if !s.allowed(target) {
		s.errors.Add(1)
		st.CloseLocal()
		return
	}
	if isUDPTarget(target) {
		serveUDPStream(st, udpTarget(target))
		return
	}
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		s.errors.Add(1)
		st.CloseLocal()
		return
	}
	tuneConn(up)
	Pipe(up, st)
}

func (s *Server) allowed(target string) bool {
	target = udpTarget(target)
	for _, p := range s.allow {
		if strings.HasPrefix(target, p) {
			return true
		}
	}
	return false
}

// decoyPipe forwards a non-tunnel connection to a real site. viaTLS says the
// connection reaching us already had its TLS terminated here, so the decoy side
// must be spoken to over TLS to keep the illusion intact for a TLS client.
func (s *Server) decoyPipe(raw net.Conn, br *bufio.Reader, viaTLS bool) {
	s.decoyPipePrefixed2(raw, br, nil, viaTLS)
}

// decoyPipePrefixed replays already-consumed bytes to the decoy; used when the
// upgrade parser read (and rejected) a real HTTP request.
func (s *Server) decoyPipePrefixed(raw net.Conn, br *bufio.Reader, prefix []byte) {
	s.decoyPipePrefixed2(raw, br, prefix, true)
}

func (s *Server) decoyPipePrefixed2(raw net.Conn, br *bufio.Reader, prefix []byte, viaTLS bool) {
	target := s.decoy
	if viaTLS && s.decoyTLS != "" {
		target = s.decoyTLS
	}
	if target == "" {
		return
	}
	up, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if viaTLS {
		host, _, _ := net.SplitHostPort(s.decoy)
		if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
			host = h
		}
		tc := tls.Client(up, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec
		if err := tc.Handshake(); err != nil {
			return
		}
		up = tc
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if len(prefix) > 0 {
			if _, err := up.Write(prefix); err != nil {
				return
			}
		}
		io.Copy(up, br)
		if tcp, ok := up.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	go func() { defer wg.Done(); io.Copy(raw, up) }()
	wg.Wait()
}

func (s *Server) trackSession(sess *Session) {
	s.smu.Lock()
	if s.sessions == nil {
		s.sessions = map[*Session]struct{}{}
	}
	if sess != nil {
		s.sessions[sess] = struct{}{}
	}
	s.smu.Unlock()
}

func (s *Server) untrackSession(sess *Session) {
	s.smu.Lock()
	delete(s.sessions, sess)
	s.smu.Unlock()
}

func (s *Server) Stats() map[string]any {
	s.smu.Lock()
	up, down, streams, live := int64(0), int64(0), 0, 0
	rtt := int64(0)
	for sess := range s.sessions {
		up += sess.bytesUp.Load()
		down += sess.bytesDown.Load()
		sess.smu.Lock()
		streams += len(sess.streams)
		sess.smu.Unlock()
		if !sess.closed.Load() {
			live++
			if r := sess.rtt.Load(); r > 0 {
				rtt = r
			}
		}
	}
	s.smu.Unlock()
	return map[string]any{
		"conns_now": s.conns.Load(), "sessions_live": live,
		"streams_open": streams, "bytes_up": up, "bytes_down": down,
		"rtt_us": rtt, "errors": s.errors.Load(),
	}
}

// bufferedConn lets tls.Server reuse the bytes we already peeked.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func constTimeEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
