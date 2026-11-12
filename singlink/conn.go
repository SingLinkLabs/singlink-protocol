// Copyright 2026 SingLinkLabs (https://github.com/SingLinkLabs)
// SPDX-License-Identifier: Apache-2.0

package singlink

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Stats counts payload bytes and live connections.
type Stats struct {
	Up    atomic.Int64
	Down  atomic.Int64
	Conns atomic.Int64
}

// earlyWait is how long a client conn waits for the application's first write
// (to send it as 0-RTT early data) before sending an empty request because
// the application is reading first.
const earlyWait = 100 * time.Millisecond

// Conn is an SingLink stream. On the client side the request is sent lazily with
// the first Write so that the first chunk travels in the same flight.
type Conn struct {
	raw net.Conn

	// client handshake
	client    *Client
	req       request
	sendOnce  sync.Mutex
	sent      bool
	sentCh    chan struct{}
	hsDone    chan struct{}
	hsErr     error
	closeOnce sync.Once

	fw *frameWriter
	fr *frameReader

	rmu     sync.Mutex
	pending []byte
	readErr error
	stats   *Stats
}

func newServerConn(raw net.Conn, c2s, s2c *cipherState, padFrames, padMax int) *Conn {
	c := &Conn{
		raw:    raw,
		fw:     &frameWriter{w: raw, cs: s2c, padFrames: padFrames, padMax: padMax},
		fr:     &frameReader{r: raw, cs: c2s},
		hsDone: make(chan struct{}),
		sentCh: make(chan struct{}),
		sent:   true,
	}
	c.closeOnce.Do(func() { close(c.hsDone) })
	close(c.sentCh)
	return c
}

// sendRequest sends the first flight with up to MaxEarlyData bytes of p.
// It returns how many bytes of p were consumed.
func (c *Conn) sendRequest(p []byte) (int, error) {
	c.sendOnce.Lock()
	defer c.sendOnce.Unlock()
	if c.sent {
		return 0, nil
	}
	c.sent = true
	defer close(c.sentCh)
	n := min(len(p), MaxEarlyData)
	req := c.req
	req.early = p[:n]
	req.ts = time.Now()
	flight, hs, err := buildFirstFlight(c.client.p.ServerKey, c.client.p.Device, &req, c.client.HeaderPadMax)
	if err != nil {
		c.fail(err)
		return 0, err
	}
	if _, err := c.raw.Write(flight); err != nil {
		c.fail(err)
		return 0, err
	}
	go c.finishHandshake(hs)
	return n, nil
}

func (c *Conn) fail(err error) {
	c.closeOnce.Do(func() {
		c.hsErr = err
		close(c.hsDone)
		if err != nil && err != net.ErrClosed && c.client != nil {
			c.client.lastErr.Store(err.Error())
		}
	})
}

// finishHandshake reads F and the status frame from the server.
func (c *Conn) finishHandshake(hs *clientHandshake) {
	F := make([]byte, x25519Len)
	if _, err := io.ReadFull(c.raw, F); err != nil {
		c.fail(ErrRejected)
		return
	}
	if bytes.HasPrefix(F, []byte("HTTP/")) {
		// The node handed us to its fallback website.
		c.fail(ErrRejected)
		return
	}
	c2s, s2c, err := hs.finish(F)
	if err != nil {
		c.fail(err)
		return
	}
	c.fw = &frameWriter{w: c.raw, cs: c2s, padFrames: c.client.PadFrames, padMax: c.client.PadMax}
	c.fr = &frameReader{r: c.raw, cs: s2c}
	t, data, err := c.fr.readFrame()
	if err != nil {
		c.fail(err)
		return
	}
	if t != frameStatus || len(data) < 1 {
		c.fail(errBadFrame)
		return
	}
	if Status(data[0]) != StatusOK {
		c.fail(&StatusError{Code: Status(data[0]), Msg: string(data[1:])})
		return
	}
	c.fail(nil)
}

// Handshake forces the request out (with no early data) and waits for the
// server's answer.
func (c *Conn) Handshake() error {
	if _, err := c.sendRequest(nil); err != nil {
		return err
	}
	<-c.hsDone
	return c.hsErr
}

func (c *Conn) Write(p []byte) (int, error) {
	total := len(p)
	n, err := c.sendRequest(p)
	if err != nil {
		return 0, err
	}
	if c.stats != nil {
		c.stats.Up.Add(int64(n))
	}
	p = p[n:]
	if len(p) == 0 {
		return total, nil
	}
	<-c.hsDone
	if c.hsErr != nil {
		return n, c.hsErr
	}
	if err := c.fw.writeData(frameData, p); err != nil {
		return n, err
	}
	if c.stats != nil {
		c.stats.Up.Add(int64(len(p)))
	}
	return total, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	select {
	case <-c.sentCh:
	case <-time.After(earlyWait):
		if _, err := c.sendRequest(nil); err != nil {
			return 0, err
		}
	}
	<-c.hsDone
	if c.hsErr != nil {
		return 0, c.hsErr
	}
	for {
		t, data, err := c.fr.readFrame()
		if err != nil {
			c.readErr = err
			return 0, err
		}
		switch t {
		case frameData:
			if len(data) == 0 {
				continue
			}
			n := copy(p, data)
			if n < len(data) {
				c.pending = append(c.pending[:0], data[n:]...)
			}
			if c.stats != nil {
				c.stats.Down.Add(int64(len(data)))
			}
			return n, nil
		case framePadding:
			continue
		case frameEOF:
			c.readErr = io.EOF
			return 0, io.EOF
		default:
			c.readErr = errBadFrame
			return 0, errBadFrame
		}
	}
}

// CloseWrite tells the peer no more data will be sent (half close).
func (c *Conn) CloseWrite() error {
	if _, err := c.sendRequest(nil); err != nil {
		return err
	}
	<-c.hsDone
	if c.hsErr != nil {
		return c.hsErr
	}
	return c.fw.writeFrame(frameEOF, nil)
}

func (c *Conn) Close() error {
	c.fail(net.ErrClosed)
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// PacketConn carries UDP datagrams over an SingLink stream. Each datagram is one
// frame holding the remote address and the payload.
type PacketConn struct {
	c *Conn
}

// WriteTo sends one datagram to dst.
func (pc *PacketConn) WriteTo(p []byte, dst Addr) error {
	if len(p) > maxFrameData-260 {
		return errors.New("singlink: datagram too large")
	}
	b := dst.appendTo(make([]byte, 0, 260+len(p)))
	b = append(b, p...)
	if err := pc.c.fw.writeFrame(frameUDP, b); err != nil {
		return err
	}
	if pc.c.stats != nil {
		pc.c.stats.Up.Add(int64(len(p)))
	}
	return nil
}

// ReadFrom receives one datagram. The returned slice is a copy.
func (pc *PacketConn) ReadFrom() ([]byte, Addr, error) {
	for {
		t, data, err := pc.c.fr.readFrame()
		if err != nil {
			return nil, Addr{}, err
		}
		if t == framePadding {
			continue
		}
		if t != frameUDP {
			return nil, Addr{}, errBadFrame
		}
		a, payload, err := decodeAddr(data)
		if err != nil {
			return nil, Addr{}, err
		}
		if pc.c.stats != nil {
			pc.c.stats.Down.Add(int64(len(payload)))
		}
		return append([]byte{}, payload...), a, nil
	}
}

func (pc *PacketConn) Close() error { return pc.c.Close() }
