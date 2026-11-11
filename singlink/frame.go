package singlink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"sync"
)

// cipherState is one direction of AES-256-GCM with a 64-bit message counter
// as the nonce. Keys are never reused across directions.
type cipherState struct {
	aead  cipher.AEAD
	n     uint64
	nonce [12]byte
}

func newCipherState(key []byte) (*cipherState, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &cipherState{aead: aead}, nil
}

func (c *cipherState) next() ([]byte, error) {
	// Stop well before the counter could wrap.
	if c.n >= 1<<62 {
		return nil, errNonceLimit
	}
	binary.LittleEndian.PutUint64(c.nonce[:8], c.n)
	c.n++
	return c.nonce[:], nil
}

func (c *cipherState) seal(dst, plaintext []byte) ([]byte, error) {
	nonce, err := c.next()
	if err != nil {
		return nil, err
	}
	return c.aead.Seal(dst, nonce, plaintext, nil), nil
}

func (c *cipherState) open(dst, ciphertext []byte) ([]byte, error) {
	nonce, err := c.next()
	if err != nil {
		return nil, err
	}
	return c.aead.Open(dst, nonce, ciphertext, nil)
}

// randInt returns a uniform integer in [0, n).
func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// frameWriter seals frames:
//
//	seal(uint16 bodyLen) || seal(type || uint16 dataLen || data || padding)
type frameWriter struct {
	mu        sync.Mutex
	w         io.Writer
	cs        *cipherState
	padFrames int // remaining frames that get random padding
	padMax    int
	buf       []byte
}

func (fw *frameWriter) writeFrame(t frameType, data []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	pad := 0
	if fw.padFrames > 0 {
		fw.padFrames--
		pad = randInt(fw.padMax + 1)
	}
	bodyLen := 3 + len(data) + pad
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(bodyLen))
	out, err := fw.cs.seal(fw.buf[:0], hdr[:])
	if err != nil {
		return err
	}
	body := make([]byte, 0, bodyLen)
	body = append(body, byte(t))
	body = binary.BigEndian.AppendUint16(body, uint16(len(data)))
	body = append(body, data...)
	body = append(body, make([]byte, pad)...)
	out, err = fw.cs.seal(out, body)
	if err != nil {
		return err
	}
	fw.buf = out
	_, err = fw.w.Write(out)
	return err
}

// writeData splits p into frames of at most maxFrameData bytes.
func (fw *frameWriter) writeData(t frameType, p []byte) error {
	for len(p) > 0 {
		n := min(len(p), maxFrameData)
		if err := fw.writeFrame(t, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

type frameReader struct {
	r   io.Reader
	cs  *cipherState
	hdr [lenBlock]byte
	buf []byte
}

// readFrame returns the next frame. data aliases an internal buffer that is
// only valid until the next call.
func (fr *frameReader) readFrame() (frameType, []byte, error) {
	if _, err := io.ReadFull(fr.r, fr.hdr[:]); err != nil {
		return 0, nil, err
	}
	var lenPT [2]byte
	if _, err := fr.cs.open(lenPT[:0], fr.hdr[:]); err != nil {
		return 0, nil, errBadFrame
	}
	bodyLen := int(binary.BigEndian.Uint16(lenPT[:]))
	if bodyLen < 3 || bodyLen > maxBodyLen {
		return 0, nil, errBadFrame
	}
	if cap(fr.buf) < bodyLen+tagLen {
		fr.buf = make([]byte, maxBodyLen+tagLen)
	}
	ct := fr.buf[:bodyLen+tagLen]
	if _, err := io.ReadFull(fr.r, ct); err != nil {
		return 0, nil, err
	}
	body, err := fr.cs.open(ct[:0], ct)
	if err != nil {
		return 0, nil, errBadFrame
	}
	dataLen := int(binary.BigEndian.Uint16(body[1:3]))
	if 3+dataLen > len(body) {
		return 0, nil, errBadFrame
	}
	return frameType(body[0]), body[3 : 3+dataLen], nil
}
