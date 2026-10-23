// esalat-tunnel — one tiny binary, two roles.
//
//	abroad:  easalt server -listen :440 -token <secret> -allow 127.0.0.1 -decoy www.microsoft.com:443
//	iran:    easalt client -server <abroad-ip> -link-port 440 -token <secret> \
//	                        -listen :440 -target 127.0.0.1:8443 -stats 127.0.0.1:9100
//
// The client listens for users on the Iran box and pipes every accepted
// connection through one or more TLS sessions to the abroad box, where the
// server dials the target (an xray/VLESS inbound bound to 127.0.0.1, say).
// Nothing is exposed on the abroad box, and the abroad IP never appears in a
// client config.
//
// Non-TLS traffic arriving at the server port is proxied to a decoy host, so a
// probe or a port scanner sees a normal HTTPS site instead of a dead port.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type commonCfg struct {
	token     string
	tlsCert   string
	tlsKey    string
	sni       string
	pin       string // sha256/base64 of the server SPKI
	transport string
	wsPath    string
	wsHost    string
	certDir   string
	insecure  bool
	statsAddr string
	listen    string
}

func genSelfSigned(names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0], Organization: []string{"esalat"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// loadOrMakeCert keeps the server certificate stable across restarts, so the
// client's -pin stays valid: an ephemeral certificate would change the pin on
// every start and silently break pinning.
func loadOrMakeCert(dir, sni string) (tls.Certificate, error) {
	crtPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if _, err := os.Stat(crtPath); err == nil {
		if cert, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
			return cert, nil
		}
	}
	names := []string{"localhost"}
	if sni != "" {
		names = strings.Split(sni, ",")
	}
	cert, err := genSelfSigned(names)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err == nil {
		crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
		keyDER, _ := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		_ = os.WriteFile(crtPath, crtPEM, 0o644)
		_ = os.WriteFile(keyPath, keyPEM, 0o600)
	}
	return cert, nil
}

func serverTLS(c commonCfg) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if c.tlsCert != "" && c.tlsKey != "" {
		cert, err = tls.LoadX509KeyPair(c.tlsCert, c.tlsKey)
		if err != nil {
			return nil, err
		}
	} else if c.certDir != "" {
		cert, err = loadOrMakeCert(c.certDir, c.sni)
		if err != nil {
			return nil, err
		}
	} else {
		names := []string{"localhost"}
		if c.sni != "" {
			names = strings.Split(c.sni, ",")
		}
		cert, err = genSelfSigned(names)
		if err != nil {
			return nil, err
		}
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return cfg, nil
}

func clientTLS(c commonCfg) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // we verify by SPKI pin or trust-on-first-use
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.sni,
	}
	if c.pin != "" {
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			got := base64.StdEncoding.EncodeToString(sha256Sum(cert.RawSubjectPublicKeyInfo))
			if got != strings.TrimSpace(c.pin) {
				return fmt.Errorf("certificate pin mismatch: got %s", got)
			}
			return nil
		}
	}
	return cfg
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// tuneConn applies the socket options that matter for a long-haul tunnel.
func tuneConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(true)
	tc.SetReadBuffer(4 << 20)
	tc.SetWriteBuffer(4 << 20)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(30 * time.Second)
}

func printPin(cert tls.Certificate) {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	log.Printf("server pin (paste into the client as -pin): %s", spkiPin(leaf))
}

func serveStats(addr string, fn func() any) {
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fn())
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	})
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("stats server: %v", err)
		}
	}()
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	common := commonCfg{}
	fs.StringVar(&common.listen, "listen", ":440", "address to accept tunnel sessions on")
	fs.StringVar(&common.token, "token", "", "shared secret (required)")
	fs.StringVar(&common.tlsCert, "cert", "", "TLS certificate file (optional)")
	fs.StringVar(&common.tlsKey, "key", "", "TLS key file (optional)")
	fs.StringVar(&common.sni, "sni", "", "SNI name(s) for the self-signed certificate")
	fs.StringVar(&common.certDir, "cert-dir", "/var/lib/esalat", "where to keep the generated certificate (stable pin across restarts)")
	fs.StringVar(&common.transport, "transport", "tls", "tls | ws (websocket upgrade, looks like normal wss) | tcp (no TLS, testing only)")
	fs.StringVar(&common.wsPath, "ws-path", "/ws", "websocket upgrade path (transport=ws)")
	fs.StringVar(&common.wsHost, "ws-host", "", "Host header for the ws upgrade (default: -sni)")
	fs.StringVar(&common.statsAddr, "stats", "127.0.0.1:9101", "stats listener (empty to disable)")
	allow := fs.String("allow", "127.0.0.1", "comma separated target prefixes the client may reach")
	decoy := fs.String("decoy", "www.cloudflare.com:80", "plain-HTTP decoy for non-tunnel traffic (empty: do nothing)")
	decoyTLS := fs.String("decoy-tls", "www.cloudflare.com:443", "decoy used when the probe already spoke TLS")
	_ = fs.Parse(args)

	if common.token == "" {
		log.Fatal("server: -token is required")
	}
	tlsCfg, err := serverTLS(common)
	if err != nil {
		log.Fatalf("server: tls: %v", err)
	}
	printPin(tlsCfg.Certificates[0])

	ln, err := net.Listen("tcp", common.listen)
	if err != nil {
		log.Fatalf("server: listen: %v", err)
	}
	srv := &Server{
		transport: common.transport,
		wsPath:    common.wsPath,
		token:     []byte(common.token),
		tlsCfg:    tlsCfg,
		allow:     strings.Split(*allow, ","),
		decoy:     *decoy,
		decoyTLS:  *decoyTLS,
	}
	for i := range srv.allow {
		srv.allow[i] = strings.TrimSpace(srv.allow[i])
	}
	log.Printf("server listening on %s (allow=%s decoy=%s)", common.listen, *allow, *decoy)
	serveStats(common.statsAddr, func() any { return srv.Stats() })

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()
	if err := srv.Serve(ln); err != nil {
		log.Printf("server stopped: %v", err)
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	common := commonCfg{}
	server := fs.String("server", "", "tunnel server host or ip (required)")
	linkPort := fs.Int("link-port", 440, "tunnel server port")
	fs.StringVar(&common.listen, "listen", ":440", "local address that accepts user traffic")
	target := fs.String("target", "127.0.0.1:8443", "target on the server side to forward to")
	fs.StringVar(&common.token, "token", "", "shared secret (required)")
	sessions := fs.Int("sessions", 4, "parallel TLS sessions to keep open")
	udp := fs.Bool("udp", false, "also forward UDP on the same listen port (for QUIC, DNS, WireGuard and friends)")
	udpTargetFlag := fs.String("udp-target", "", "where UDP goes on the server side (default: -target)")
	fs.StringVar(&common.sni, "sni", "www.microsoft.com", "SNI to send")
	fs.StringVar(&common.pin, "pin", "", "expected server SPKI pin (recommended)")
	fs.StringVar(&common.statsAddr, "stats", "127.0.0.1:9100", "stats listener (empty to disable)")
	fs.StringVar(&common.wsHost, "ws-host", "", "Host header for the ws upgrade (default: -sni)")
	fs.StringVar(&common.transport, "transport", "tls", "tls | ws (websocket upgrade, looks like normal wss) | tcp (no TLS, testing only)")
	fs.StringVar(&common.wsPath, "ws-path", "/ws", "websocket upgrade path (transport=ws)")
	_ = fs.Parse(args)

	if *server == "" || common.token == "" {
		log.Fatal("client: -server and -token are required")
	}
	addr := fmt.Sprintf("%s:%d", *server, *linkPort)
	c := NewClient(addr, clientTLS(common), common.token, *sessions)
	c.transport = common.transport
	c.wsPath = common.wsPath
	c.sni = common.sni
	c.wsHost = common.wsHost

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go c.EnsureSessions(ctx)

	udpTarget := *udpTargetFlag
	if udpTarget == "" {
		udpTarget = *target
	}
	if *udp {
		host, port, err := net.SplitHostPort(common.listen)
		if err != nil {
			log.Fatalf("client: -listen must be host:port for -udp: %v", err)
		}
		_ = host
		uaddr, err := net.ResolveUDPAddr("udp", ":"+port)
		if err != nil {
			log.Fatalf("client: udp listen: %v", err)
		}
		uconn, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			log.Fatalf("client: udp listen: %v", err)
		}
		fwd := newUDPForwarder(c, udpTarget)
		go fwd.Run(uconn)
		log.Printf("udp  %s/udp -> %s (through the same sessions)", common.listen, udpTarget)
	}

	ln, err := net.Listen("tcp", common.listen)
	if err != nil {
		log.Fatalf("client: listen: %v", err)
	}
	log.Printf("client %s -> %s :%d  (%s => %s), sessions=%d",
		common.listen, *server, *linkPort, common.listen, *target, *sessions)
	serveStats(common.statsAddr, func() any { return c.Stats() })

	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tuneConn(conn)
		go func() {
			var st *Stream
			var err error
			for attempt := 0; attempt < 20; attempt++ {
				s, perr := c.Pick()
				if perr == nil {
					if st, err = s.Open(*target); err == nil {
						break
					}
				}
				if ctx.Err() != nil {
					conn.Close()
					return
				}
				time.Sleep(120 * time.Millisecond)
			}
			if st == nil {
				log.Printf("no session available for %s: %v", conn.RemoteAddr(), err)
				conn.Close()
				return
			}
			Pipe(conn, st)
		}()
	}
}

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `esalat-tunnel

  easalt server -listen :440 -token <secret> [-allow 127.0.0.1] [-decoy host:port]
  easalt client -server <ip> -link-port 440 -token <secret> [-listen :440] [-target 127.0.0.1:8443]

  easalt version

`)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Printf("esalat-tunnel %s\n", version)
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "pin":
		// print the pin of the persisted certificate (creates it if missing)
		dir := "/var/lib/esalat"
		if len(os.Args) > 3 && (os.Args[2] == "-cert-dir" || os.Args[2] == "--cert-dir") {
			dir = os.Args[3]
		}
		cert, err := loadOrMakeCert(dir, "esalat")
		if err != nil {
			log.Fatal(err)
		}
		printPin(cert)
	default:
		usage()
		os.Exit(2)
	}
}
