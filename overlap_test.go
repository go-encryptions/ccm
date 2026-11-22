package ccm

import (
	"bytes"
	"crypto/aes"
	"testing"
)

// cipher.AEAD forbids dst and plaintext overlapping inexactly; crypto/cipher
// panics on it. Seal used to compute the MAC over the intact plaintext and then
// write the keystream forward over bytes it had not read: no panic, a wrong
// ciphertext, and Open answered "authentication failed".
func TestSealInexactOverlapPanics(t *testing.T) {
	b, _ := aes.NewCipher(make([]byte, 16))
	a, err := NewCCM(b, 16, 12)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	pt := bytes.Repeat([]byte("0123456789abcdef"), 4)
	ref := a.Seal(nil, nonce, pt, nil)

	seal := func(buf, dst, src []byte) (panicked bool) {
		defer func() { panicked = recover() != nil }()
		a.Seal(dst, nonce, src, nil)
		return false
	}

	// Exact overlap, the documented in-place form: allowed and correct.
	buf := make([]byte, 200)
	copy(buf, pt)
	var ct []byte
	if seal(buf, buf[:0], buf[:len(pt)]) {
		t.Error("exact overlap panicked")
	}
	copy(buf, pt)
	func() {
		defer func() { _ = recover() }()
		ct = a.Seal(buf[:0], nonce, buf[:len(pt)], nil)
	}()
	if !bytes.Equal(ct, ref) {
		t.Error("exact overlap gives a wrong ciphertext")
	}

	// No overlap at all, adjacent buffers: allowed.
	buf = make([]byte, 300)
	copy(buf, pt)
	if seal(buf, buf[len(pt):len(pt)], buf[:len(pt)]) {
		t.Error("adjacent, non-overlapping buffers panicked")
	}

	// dst starting after the plaintext start, and before it: both panic.
	buf = make([]byte, 200)
	copy(buf, pt)
	if !seal(buf, buf[8:8], buf[:len(pt)]) {
		t.Error("dst offset forward of plaintext did not panic")
	}
	buf = make([]byte, 200)
	copy(buf[8:], pt)
	if !seal(buf, buf[:0], buf[8:8+len(pt)]) {
		t.Error("dst offset behind plaintext did not panic")
	}

	// Open with an offset overlap stays correct (it decrypts to a scratch
	// buffer first).
	buf = make([]byte, 200)
	copy(buf, ref)
	got, err := a.Open(buf[8:8], nonce, buf[:len(ref)], nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Errorf("Open with inexact overlap: err=%v equal=%v", err, bytes.Equal(got, pt))
	}

	// Empty plaintext never overlaps.
	if seal(nil, make([]byte, 0, 32), nil) {
		t.Error("empty plaintext panicked")
	}
}
