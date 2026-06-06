// Package ccm implements the CCM (Counter with CBC-MAC) AEAD mode
// specified by RFC 3610 and NIST SP 800-38C, suitable for use with
// AES (or any 128-bit block cipher).
//
// CCM is not provided by the Go standard library — stdlib's
// crypto/cipher only exposes GCM. This package fills that gap so
// callers (in particular OpenZFS native-encryption parsers) don't
// have to depend on golang.org/x/crypto for AES-CCM.
//
// The implementation is pure Go, uses only crypto/aes + the
// caller-supplied cipher.Block, and exposes the standard
// cipher.AEAD interface so it composes with any code that already
// understands GCM-style sealed/open.
//
// Parameter ranges:
//
//	nonce size  N  ∈ [7, 13]   (RFC 3610 §3 — encoded as L = 15 - N)
//	tag size    M  ∈ {4, 6, 8, 10, 12, 14, 16}
//	plaintext   P  with len(P) ≤ 2^(8L) - 1
//
// Typical OpenZFS usage: N=12, M=16 (L=3, so the encoded-length
// field is 3 bytes — sufficient for any ZFS block since a block
// is at most 2^24 bytes).
package ccm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const blockSize = 16

// CCM is the cipher.AEAD wrapper around a 128-bit block cipher
// configured for CCM mode. Construct one with NewCCM.
type CCM struct {
	b         cipher.Block
	nonceSize int
	tagSize   int
}

// NewCCM returns a cipher.AEAD that uses b in CCM mode with the
// given tag and nonce sizes (in bytes). b must have a 16-byte
// block size; tagSize must be one of {4,6,8,10,12,14,16}; nonceSize
// must be in [7, 13].
func NewCCM(b cipher.Block, tagSize, nonceSize int) (cipher.AEAD, error) {
	if b.BlockSize() != blockSize {
		return nil, errors.New("ccm: cipher block size must be 16 bytes")
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, errors.New("ccm: invalid tag size (want 4, 6, 8, 10, 12, 14, or 16)")
	}
	if nonceSize < 7 || nonceSize > 13 {
		return nil, errors.New("ccm: invalid nonce size (want 7..13)")
	}
	return &CCM{b: b, nonceSize: nonceSize, tagSize: tagSize}, nil
}

// NonceSize returns the configured nonce length.
func (c *CCM) NonceSize() int { return c.nonceSize }

// Overhead returns the number of bytes Seal appends after the
// ciphertext (the authentication tag).
func (c *CCM) Overhead() int { return c.tagSize }

// maxPlaintextLen returns the largest plaintext that can be sealed
// for the configured nonce size. L = 15 - N, max = 2^(8L) - 1.
func (c *CCM) maxPlaintextLen() uint64 {
	L := uint(15 - c.nonceSize)
	if L >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << (8 * L)) - 1
}

// Seal encrypts and authenticates plaintext, authenticates
// additionalData and appends the result to dst, returning the
// updated slice. The nonce must be NonceSize() bytes long and must
// be unique for any particular key.
func (c *CCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.nonceSize {
		panic("ccm: incorrect nonce length")
	}
	if uint64(len(plaintext)) > c.maxPlaintextLen() {
		panic("ccm: plaintext too large for nonce size")
	}

	tag := c.computeMAC(nonce, plaintext, additionalData)

	ret, out := sliceForAppend(dst, len(plaintext)+c.tagSize)

	// CTR-encrypt plaintext starting at counter = 1.
	c.ctrXOR(out[:len(plaintext)], nonce, 1, plaintext)

	// Encrypt the tag with the counter=0 keystream block.
	var s0 [blockSize]byte
	c.formatCounter(s0[:], nonce, 0)
	c.b.Encrypt(s0[:], s0[:])
	for i := 0; i < c.tagSize; i++ {
		out[len(plaintext)+i] = tag[i] ^ s0[i]
	}
	return ret
}

// Open verifies and decrypts ciphertext, authenticates
// additionalData, and if successful appends the resulting
// plaintext to dst, returning the updated slice. The nonce must be
// NonceSize() bytes long. If the authentication tag does not
// verify Open returns an error and dst is unchanged.
func (c *CCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		return nil, errors.New("ccm: incorrect nonce length")
	}
	if len(ciphertext) < c.tagSize {
		return nil, errors.New("ccm: ciphertext too short")
	}
	ctLen := len(ciphertext) - c.tagSize
	if uint64(ctLen) > c.maxPlaintextLen() {
		return nil, errors.New("ccm: ciphertext too large for nonce size")
	}

	// CTR-decrypt the body (counter ≥ 1) into a scratch buffer first;
	// only commit to dst on successful tag verification.
	pt := make([]byte, ctLen)
	c.ctrXOR(pt, nonce, 1, ciphertext[:ctLen])

	// Recover the tag the sender computed.
	var s0 [blockSize]byte
	c.formatCounter(s0[:], nonce, 0)
	c.b.Encrypt(s0[:], s0[:])
	wantTag := make([]byte, c.tagSize)
	for i := 0; i < c.tagSize; i++ {
		wantTag[i] = ciphertext[ctLen+i] ^ s0[i]
	}

	// Recompute the tag locally and compare in constant time.
	gotTag := c.computeMAC(nonce, pt, additionalData)
	if subtle.ConstantTimeCompare(wantTag, gotTag[:c.tagSize]) != 1 {
		// Wipe the scratch plaintext on failure.
		for i := range pt {
			pt[i] = 0
		}
		return nil, errors.New("ccm: authentication failed")
	}

	ret, out := sliceForAppend(dst, ctLen)
	copy(out, pt)
	return ret, nil
}

// computeMAC computes the CBC-MAC over [B_0 || AAD-blocks ||
// PT-blocks] as specified in RFC 3610 §2.2 and §2.4. Returns the
// full 16-byte CBC-MAC; callers truncate to tagSize.
func (c *CCM) computeMAC(nonce, plaintext, ad []byte) [blockSize]byte {
	L := 15 - c.nonceSize

	// B_0: flags | nonce | length(plaintext)
	var b0 [blockSize]byte
	flags := byte(0)
	if len(ad) > 0 {
		flags |= 1 << 6
	}
	flags |= byte(((c.tagSize - 2) / 2) << 3)
	flags |= byte(L - 1)
	b0[0] = flags
	copy(b0[1:1+c.nonceSize], nonce)
	encodeLengthBE(b0[1+c.nonceSize:], uint64(len(plaintext)), L)

	// Initial CBC-MAC X = AES(K, B_0)
	var x [blockSize]byte
	c.b.Encrypt(x[:], b0[:])

	// AAD-length prefix block(s), if any.
	if len(ad) > 0 {
		var hdr [10]byte
		var hdrLen int
		switch {
		case len(ad) < (1<<16 - 1<<8):
			binary.BigEndian.PutUint16(hdr[:2], uint16(len(ad)))
			hdrLen = 2
		case uint64(len(ad)) < (uint64(1) << 32):
			hdr[0] = 0xff
			hdr[1] = 0xfe
			binary.BigEndian.PutUint32(hdr[2:6], uint32(len(ad)))
			hdrLen = 6
		default:
			hdr[0] = 0xff
			hdr[1] = 0xff
			binary.BigEndian.PutUint64(hdr[2:10], uint64(len(ad)))
			hdrLen = 10
		}
		c.macAppend(&x, hdr[:hdrLen], ad)
	}

	// Plaintext blocks.
	c.macAppend(&x, plaintext)
	return x
}

// macAppend folds one or more byte slices (concatenated, then
// zero-padded to the next 16-byte boundary) into the running
// CBC-MAC state x.
func (c *CCM) macAppend(x *[blockSize]byte, parts ...[]byte) {
	var buf [blockSize]byte
	var n int
	for _, p := range parts {
		i := 0
		for i < len(p) {
			take := copy(buf[n:], p[i:])
			n += take
			i += take
			if n == blockSize {
				for j := 0; j < blockSize; j++ {
					x[j] ^= buf[j]
				}
				c.b.Encrypt(x[:], x[:])
				n = 0
			}
		}
	}
	if n > 0 {
		// Zero-pad and flush the final partial block.
		for j := n; j < blockSize; j++ {
			buf[j] = 0
		}
		for j := 0; j < blockSize; j++ {
			x[j] ^= buf[j]
		}
		c.b.Encrypt(x[:], x[:])
	}
}

// ctrXOR XORs successive keystream blocks A_i = AES(K, formatCounter(i))
// starting at counter `start` over src into dst.
func (c *CCM) ctrXOR(dst, nonce []byte, start uint64, src []byte) {
	var counter, keystream [blockSize]byte
	i := start
	for off := 0; off < len(src); off += blockSize {
		c.formatCounter(counter[:], nonce, i)
		c.b.Encrypt(keystream[:], counter[:])
		end := off + blockSize
		if end > len(src) {
			end = len(src)
		}
		for j := off; j < end; j++ {
			dst[j] = src[j] ^ keystream[j-off]
		}
		i++
	}
}

// formatCounter builds the 16-byte CTR input A_i = (L-1) | nonce |
// counter_BE_L_bytes for counter value i.
func (c *CCM) formatCounter(out []byte, nonce []byte, i uint64) {
	L := 15 - c.nonceSize
	out[0] = byte(L - 1)
	copy(out[1:1+c.nonceSize], nonce)
	encodeLengthBE(out[1+c.nonceSize:], i, L)
}

// encodeLengthBE writes v as a big-endian L-byte field at the
// start of dst (which must be ≥ L bytes). Mirrors RFC 3610's
// l(m) and i encoding.
func encodeLengthBE(dst []byte, v uint64, L int) {
	for j := L - 1; j >= 0; j-- {
		dst[j] = byte(v)
		v >>= 8
	}
}

// sliceForAppend grows in (in place if capacity permits) by n
// bytes and returns the combined slice plus a sub-slice pointing
// at the newly added n-byte region. Mirrors the helper used by
// the stdlib AEAD implementations.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
