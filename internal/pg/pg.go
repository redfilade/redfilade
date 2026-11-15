// Package pg is a small, dependency-free PostgreSQL client for the hosted
// Test Bench (ADR-0022): the v3 wire protocol, SCRAM-SHA-256 authentication,
// optional TLS, and the extended query protocol so every value travels as a
// separate parameter and SQL is never built from input.
//
// It deliberately supports little: text-format parameters and results, no
// COPY, no LISTEN. Weak authentication (cleartext, MD5) is refused, and the
// server's SCRAM signature is verified, so a fake server cannot pretend to
// accept the password.
package pg

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxMessage bounds one protocol message from the server.
const MaxMessage = 64 << 20

// Error is an error reported by the server.
type Error struct {
	Severity, Code, Message, Detail string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("pg %s %s: %s (%s)", e.Severity, e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("pg %s %s: %s", e.Severity, e.Code, e.Message)
}

// Conn is one connection. It is not safe for concurrent use; see Pool.
type Conn struct {
	nc  net.Conn
	r   *bufio.Reader
	w   *bufio.Writer
	bad atomic.Bool
}

// Config is a parsed connection URL.
type Config struct {
	Host, Port, User, Password, Database, SSLMode string
}

// ParseURL reads postgres://user:password@host:port/db?sslmode=... .
// sslmode is disable, require or verify-full; it defaults to verify-full,
// or to disable for loopback hosts.
func ParseURL(s string) (Config, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return Config{}, errors.New("pg: URL must start with postgres://")
	}
	c := Config{Host: u.Hostname(), Port: u.Port(), User: u.User.Username(), Database: strings.TrimPrefix(u.Path, "/"), SSLMode: u.Query().Get("sslmode")}
	c.Password, _ = u.User.Password()
	if c.Port == "" {
		c.Port = "5432"
	}
	if c.Database == "" {
		c.Database = c.User
	}
	if c.SSLMode == "" {
		c.SSLMode = "verify-full"
		if ip := net.ParseIP(c.Host); c.Host == "localhost" || (ip != nil && ip.IsLoopback()) {
			c.SSLMode = "disable"
		}
	}
	switch c.SSLMode {
	case "disable", "require", "verify-full":
	default:
		return Config{}, fmt.Errorf("pg: unsupported sslmode %q", c.SSLMode)
	}
	if c.Host == "" || c.User == "" {
		return Config{}, errors.New("pg: URL needs a host and a user")
	}
	return c, nil
}

// Connect opens and authenticates a connection.
func Connect(ctx context.Context, rawURL string) (*Conn, error) {
	cfg, err := ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, cfg.Port))
	if err != nil {
		return nil, err
	}
	c := &Conn{nc: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc)}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	} else {
		_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	}
	if err := c.startup(cfg); err != nil {
		nc.Close()
		return nil, err
	}
	_ = c.nc.SetDeadline(time.Time{})
	return c, nil
}

// Close ends the connection.
func (c *Conn) Close() error {
	_ = c.send('X', nil)
	_ = c.w.Flush()
	return c.nc.Close()
}

func (c *Conn) startup(cfg Config) error {
	if cfg.SSLMode != "disable" {
		var b [8]byte
		binary.BigEndian.PutUint32(b[0:], 8)
		binary.BigEndian.PutUint32(b[4:], 80877103)
		if _, err := c.nc.Write(b[:]); err != nil {
			return err
		}
		var resp [1]byte
		if _, err := io.ReadFull(c.nc, resp[:]); err != nil {
			return err
		}
		if resp[0] != 'S' {
			return errors.New("pg: server refused TLS")
		}
		tc := tls.Client(c.nc, &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.SSLMode == "require", MinVersion: tls.VersionTLS12}) //nolint:gosec // sslmode=require is explicit
		if err := tc.Handshake(); err != nil {
			return err
		}
		c.nc, c.r, c.w = tc, bufio.NewReader(tc), bufio.NewWriter(tc)
	}
	var p []byte
	p = binary.BigEndian.AppendUint32(p, 196608)
	for _, kv := range [][2]string{{"user", cfg.User}, {"database", cfg.Database}, {"application_name", "redfilade"}, {"client_encoding", "UTF8"}} {
		p = append(append(append(append(p, kv[0]...), 0), kv[1]...), 0)
	}
	p = append(p, 0)
	msg := binary.BigEndian.AppendUint32(nil, uint32(len(p)+4))
	if _, err := c.w.Write(append(msg, p...)); err != nil {
		return err
	}
	if err := c.w.Flush(); err != nil {
		return err
	}
	var scram *scramState
	for {
		t, body, err := c.recv()
		if err != nil {
			return err
		}
		switch t {
		case 'R':
			if len(body) < 4 {
				return errors.New("pg: short auth message")
			}
			code, rest := binary.BigEndian.Uint32(body), body[4:]
			switch code {
			case 0: // AuthenticationOk
				if scram != nil && !scram.verified {
					return errors.New("pg: server skipped SCRAM verification")
				}
			case 10: // SASL: list of mechanisms
				if !strings.Contains(string(rest), "SCRAM-SHA-256\x00") {
					return errors.New("pg: server does not offer SCRAM-SHA-256")
				}
				scram = newScram(cfg.Password)
				first := scram.clientFirst()
				var m []byte
				m = append(append(m, "SCRAM-SHA-256"...), 0)
				m = binary.BigEndian.AppendUint32(m, uint32(len(first)))
				m = append(m, first...)
				if err := c.send('p', m); err != nil {
					return err
				}
			case 11: // SASLContinue
				if scram == nil {
					return errors.New("pg: unexpected SASL continue")
				}
				final, err := scram.clientFinal(string(rest))
				if err != nil {
					return err
				}
				if err := c.send('p', []byte(final)); err != nil {
					return err
				}
			case 12: // SASLFinal
				if scram == nil || !scram.verify(string(rest)) {
					return errors.New("pg: server SCRAM signature is wrong")
				}
			default:
				return fmt.Errorf("pg: authentication method %d refused (only SCRAM-SHA-256 is allowed)", code)
			}
			if err := c.w.Flush(); err != nil {
				return err
			}
		case 'E':
			return parseError(body)
		case 'Z':
			if scram == nil || !scram.verified {
				// trust authentication: allowed only without a password.
				if cfg.Password != "" {
					return errors.New("pg: server did not authenticate with SCRAM")
				}
			}
			return nil
		}
	}
}

func (c *Conn) send(t byte, body []byte) error {
	var h [5]byte
	h[0] = t
	binary.BigEndian.PutUint32(h[1:], uint32(len(body)+4))
	if _, err := c.w.Write(h[:]); err != nil {
		return err
	}
	_, err := c.w.Write(body)
	return err
}

func (c *Conn) recv() (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		c.bad.Store(true)
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n < 4 || n-4 > MaxMessage {
		c.bad.Store(true)
		return 0, nil, errors.New("pg: message too large")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(c.r, body); err != nil {
		c.bad.Store(true)
		return 0, nil, err
	}
	return h[0], body, nil
}

func parseError(b []byte) *Error {
	e := &Error{}
	for len(b) > 1 {
		f := b[0]
		i := strings.IndexByte(string(b[1:]), 0)
		if i < 0 {
			break
		}
		v := string(b[1 : 1+i])
		switch f {
		case 'S':
			e.Severity = v
		case 'C':
			e.Code = v
		case 'M':
			e.Message = v
		case 'D':
			e.Detail = v
		}
		b = b[2+i:]
	}
	return e
}

// Rows is a fully read result in text format.
type Rows struct {
	Columns []string
	Data    [][]*string // nil means SQL NULL
	Tag     string      // e.g. "INSERT 0 1"
}

// Affected returns the row count in the command tag.
func (r *Rows) Affected() int64 {
	f := strings.Fields(r.Tag)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(f[len(f)-1], 10, 64)
	return n
}

// Exec runs one statement with parameters ($1, $2, ...) and returns its result.
// With no arguments and several statements, use Script.
func (c *Conn) Exec(ctx context.Context, sql string, args ...any) (*Rows, error) {
	if c.bad.Load() {
		return nil, errors.New("pg: connection is broken")
	}
	params, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	stop := c.watch(ctx)
	defer stop()
	var b []byte
	b = append(append(append(b, 0), sql...), 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	if err := c.send('P', b); err != nil {
		return nil, err
	}
	b = []byte{0, 0}
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(params)))
	for _, p := range params {
		if p == nil {
			b = binary.BigEndian.AppendUint32(b, 0xFFFFFFFF)
			continue
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(*p)))
		b = append(b, *p...)
	}
	b = binary.BigEndian.AppendUint16(b, 0)
	for _, m := range []struct {
		t byte
		b []byte
	}{{'B', b}, {'D', []byte{'P', 0}}, {'E', []byte{0, 0, 0, 0, 0}}, {'S', nil}} {
		if err := c.send(m.t, m.b); err != nil {
			return nil, err
		}
	}
	if err := c.w.Flush(); err != nil {
		c.bad.Store(true)
		return nil, err
	}
	return c.collect()
}

// Script runs SQL text with no parameters, possibly several statements (the
// simple query protocol). Use it only for trusted SQL such as migrations.
func (c *Conn) Script(ctx context.Context, sql string) error {
	if c.bad.Load() {
		return errors.New("pg: connection is broken")
	}
	stop := c.watch(ctx)
	defer stop()
	if err := c.send('Q', append([]byte(sql), 0)); err != nil {
		return err
	}
	if err := c.w.Flush(); err != nil {
		c.bad.Store(true)
		return err
	}
	_, err := c.collect()
	return err
}

// watch closes the connection if ctx ends while a call is in flight. The
// returned stop function waits for the watcher to finish, so a connection is
// never broken after it has gone back to the pool; if the watcher fired, the
// connection is marked bad and the pool discards it.
func (c *Conn) watch(ctx context.Context) func() {
	if ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			c.bad.Store(true)
			_ = c.nc.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

func (c *Conn) collect() (*Rows, error) {
	rows := &Rows{}
	var perr *Error
	for {
		t, body, err := c.recv()
		if err != nil {
			return nil, err
		}
		switch t {
		case 'T':
			rows.Columns = nil
			if len(body) < 2 {
				continue
			}
			n := int(binary.BigEndian.Uint16(body))
			b := body[2:]
			for i := 0; i < n; i++ {
				j := strings.IndexByte(string(b), 0)
				if j < 0 || len(b) < j+19 {
					break
				}
				rows.Columns = append(rows.Columns, string(b[:j]))
				b = b[j+19:]
			}
		case 'D':
			if len(body) < 2 {
				continue
			}
			n := int(binary.BigEndian.Uint16(body))
			b := body[2:]
			row := make([]*string, n)
			for i := 0; i < n && len(b) >= 4; i++ {
				l := int32(binary.BigEndian.Uint32(b))
				b = b[4:]
				if l < 0 {
					continue
				}
				if int(l) > len(b) {
					return nil, errors.New("pg: malformed data row")
				}
				s := string(b[:l])
				row[i] = &s
				b = b[l:]
			}
			rows.Data = append(rows.Data, row)
		case 'C':
			rows.Tag = strings.TrimRight(string(body), "\x00")
		case 'E':
			if perr == nil {
				perr = parseError(body)
			}
		case 'Z':
			if perr != nil {
				return nil, perr
			}
			return rows, nil
		}
	}
}

// encodeArgs turns Go values into text-format parameters.
func encodeArgs(args []any) ([]*string, error) {
	out := make([]*string, len(args))
	for i, a := range args {
		var s string
		switch v := a.(type) {
		case nil:
			continue
		case string:
			s = v
		case []byte:
			s = `\x` + hex.EncodeToString(v)
		case int:
			s = strconv.Itoa(v)
		case int64:
			s = strconv.FormatInt(v, 10)
		case bool:
			s = strconv.FormatBool(v)
		case time.Time:
			s = v.UTC().Format(time.RFC3339Nano)
		case json.RawMessage:
			if v == nil {
				continue
			}
			s = string(v)
		default:
			return nil, fmt.Errorf("pg: unsupported parameter type %T", a)
		}
		if strings.IndexByte(s, 0) >= 0 {
			return nil, errors.New("pg: parameters cannot contain NUL bytes")
		}
		out[i] = &s
	}
	return out, nil
}

// --- SCRAM-SHA-256 (RFC 5802, RFC 7677) --------------------------------------

type scramState struct {
	password, nonce, clientFirstBare, authMessage string
	saltedPassword                                []byte
	verified                                      bool
}

func newScram(password string) *scramState {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return &scramState{password: password, nonce: base64.RawStdEncoding.EncodeToString(b)}
}

func (s *scramState) clientFirst() string {
	s.clientFirstBare = "n=,r=" + s.nonce
	return "n,," + s.clientFirstBare
}

func (s *scramState) clientFinal(serverFirst string) (string, error) {
	var nonce, salt string
	iter := 0
	for _, kv := range strings.Split(serverFirst, ",") {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "r":
			nonce = v
		case "s":
			salt = v
		case "i":
			iter, _ = strconv.Atoi(v)
		}
	}
	if !strings.HasPrefix(nonce, s.nonce) || len(nonce) == len(s.nonce) {
		return "", errors.New("pg: SCRAM server nonce does not extend ours")
	}
	if iter < 4096 || iter > 1<<20 {
		return "", fmt.Errorf("pg: SCRAM iteration count %d out of range", iter)
	}
	saltB, err := base64.StdEncoding.DecodeString(salt)
	if err != nil || len(saltB) == 0 {
		return "", errors.New("pg: bad SCRAM salt")
	}
	s.saltedPassword, err = pbkdf2.Key(sha256.New, s.password, saltB, iter, 32)
	if err != nil {
		return "", err
	}
	withoutProof := "c=biws,r=" + nonce
	s.authMessage = s.clientFirstBare + "," + serverFirst + "," + withoutProof
	clientKey := hmacSHA256(s.saltedPassword, "Client Key")
	stored := sha256.Sum256(clientKey)
	sig := hmacSHA256(stored[:], s.authMessage)
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ sig[i]
	}
	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

func (s *scramState) verify(serverFinal string) bool {
	v, ok := strings.CutPrefix(strings.TrimSpace(serverFinal), "v=")
	if !ok {
		return false
	}
	got, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return false
	}
	want := hmacSHA256(hmacSHA256(s.saltedPassword, "Server Key"), s.authMessage)
	s.verified = hmac.Equal(got, want)
	return s.verified
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// --- pool ---------------------------------------------------------------------

// Pool keeps a few connections for concurrent use.
type Pool struct {
	url  string
	mu   sync.Mutex
	idle []*Conn
	sem  chan struct{}
}

// NewPool returns a pool of at most size connections.
func NewPool(url string, size int) *Pool {
	return &Pool{url: url, sem: make(chan struct{}, size)}
}

// With runs f on a pooled connection.
func (p *Pool) With(ctx context.Context, f func(*Conn) error) error {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-p.sem }()
	p.mu.Lock()
	var c *Conn
	if n := len(p.idle); n > 0 {
		c, p.idle = p.idle[n-1], p.idle[:n-1]
	}
	p.mu.Unlock()
	if c == nil {
		var err error
		if c, err = Connect(ctx, p.url); err != nil {
			return err
		}
	}
	err := f(c)
	if c.bad.Load() {
		c.nc.Close()
		return err
	}
	p.mu.Lock()
	p.idle = append(p.idle, c)
	p.mu.Unlock()
	return err
}

// Tx runs f inside a transaction, rolling back on error.
func (p *Pool) Tx(ctx context.Context, f func(*Conn) error) error {
	return p.With(ctx, func(c *Conn) error {
		if err := c.Script(ctx, "BEGIN"); err != nil {
			return err
		}
		if err := f(c); err != nil {
			_ = c.Script(context.Background(), "ROLLBACK")
			return err
		}
		return c.Script(ctx, "COMMIT")
	})
}

// Close closes idle connections.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.idle {
		c.Close()
	}
	p.idle = nil
}
