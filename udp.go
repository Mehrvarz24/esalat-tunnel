package main

import (
	"net"
	"strings"
	"sync"
	"time"
)

const (
	udpMagic  = "u:"
	udpIdle   = 60 * time.Second
	udpMaxPkt = 65507
)

func isUDPTarget(t string) bool { return strings.HasPrefix(t, udpMagic) }

func udpTarget(t string) string { return strings.TrimPrefix(t, udpMagic) }

// serveUDPStream pairs one multiplexed stream with one UDP socket: every stream
// chunk is one datagram, in both directions, so packet boundaries survive.
func serveUDPStream(st *Stream, target string) {
	uc, err := net.Dial("udp", target)
	if err != nil {
		st.CloseLocal()
		return
	}
	defer uc.Close()
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	go func() {
		defer stop()
		for {
			select {
			case <-done:
				return
			default:
			}
			b, err := st.ReadChunk()
			if err != nil {
				return
			}
			if _, err := uc.Write(b); err != nil {
				return
			}
		}
	}()

	last := time.Now()
	go func() {
		for {
			if time.Since(last) > udpIdle {
				stop()
				return
			}
			time.Sleep(5 * time.Second)
		}
	}()

	buf := make([]byte, udpMaxPkt)
	for {
		_ = uc.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := uc.Read(buf)
		if n > 0 {
			last = time.Now()
			if _, werr := st.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	stop()
	st.CloseLocal()
}

// udpAssoc relays datagrams between one client-side UDP source address and one
// stream. Each source address gets its own stream, mirroring how NAT keeps one
// outbound port per flow.
type udpAssoc struct {
	conn   *net.UDPConn
	stream *Stream
	peer   *net.UDPAddr
	last   time.Time
}

type udpForwarder struct {
	client   *Client
	target   string
	timeout  time.Duration
	mu       sync.Mutex
	assocs   map[string]*udpAssoc
	bytesIn  int64
	bytesOut int64
}

func newUDPForwarder(c *Client, target string) *udpForwarder {
	f := &udpForwarder{client: c, target: udpMagic + target, timeout: udpIdle, assocs: map[string]*udpAssoc{}}
	go f.reaper()
	return f
}

func (f *udpForwarder) reaper() {
	for {
		time.Sleep(10 * time.Second)
		f.mu.Lock()
		for k, a := range f.assocs {
			if time.Since(a.last) > f.timeout {
				a.stream.CloseLocal()
				delete(f.assocs, k)
			}
		}
		f.mu.Unlock()
	}
}

// Run reads datagrams from conn and fans them out to per-source streams.
func (f *udpForwarder) Run(conn *net.UDPConn) {
	buf := make([]byte, udpMaxPkt)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		key := peer.String()
		f.mu.Lock()
		a := f.assocs[key]
		if a == nil {
			st, err := f.open()
			if err != nil {
				f.mu.Unlock()
				continue
			}
			a = &udpAssoc{conn: conn, stream: st, peer: peer, last: time.Now()}
			f.assocs[key] = a
			go f.pump(a, key)
		}
		a.last = time.Now()
		f.mu.Unlock()
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if _, err := a.stream.Write(pkt); err != nil {
			f.drop(key)
		}
	}
}

func (f *udpForwarder) open() (*Stream, error) {
	for attempt := 0; attempt < 40; attempt++ {
		s, err := f.client.Pick()
		if err == nil {
			if st, oerr := s.Open(f.target); oerr == nil {
				return st, nil
			}
		}
		time.Sleep(120 * time.Millisecond)
	}
	return nil, errSessionClosed
}

func (f *udpForwarder) pump(a *udpAssoc, key string) {
	for {
		b, err := a.stream.ReadChunk()
		if err != nil {
			f.drop(key)
			return
		}
		a.last = time.Now()
		if _, err := a.conn.WriteToUDP(b, a.peer); err != nil {
			f.drop(key)
			return
		}
	}
}

func (f *udpForwarder) drop(key string) {
	f.mu.Lock()
	if a, ok := f.assocs[key]; ok {
		a.stream.CloseLocal()
		delete(f.assocs, key)
	}
	f.mu.Unlock()
}

func (f *udpForwarder) Stats() map[string]any {
	f.mu.Lock()
	n := len(f.assocs)
	f.mu.Unlock()
	return map[string]any{"udp_assocs": n}
}
