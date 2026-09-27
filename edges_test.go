package ccm

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"encoding/binary"
	"strings"
	"testing"
)

// The RFC 3610 vectors in ccm_test.go prove the algorithm. What they do not
// reach is every refusal and every length-encoding case, and those were 13.2%
// of the statements — the difference between 86.8% and the 100% floor this
// organisation's other three modules gate on.

func aead(t *testing.T, tagSize, nonceSize int) *CCM {
	t.Helper()
	b, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewCCM(b, tagSize, nonceSize)
	if err != nil {
		t.Fatal(err)
	}
	return a.(*CCM)
}

// TestNewCCMRefusesABlockThatIsNotSixteenBytes. CCM is defined over a 128-bit
// block and nothing else; DES gives a real 8-byte one, so the check is
// exercised by a cipher somebody could actually pass rather than by a stub.
func TestNewCCMRefusesABlockThatIsNotSixteenBytes(t *testing.T) {
	b, err := des.NewCipher(make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewCCM(b, 16, 13)
	if err == nil {
		t.Fatal("a 8-byte block cipher was accepted")
	}
	if a != nil {
		t.Error("a refusal returned a non-nil AEAD")
	}
	if !strings.Contains(err.Error(), "block size") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// TestNewCCMRefusesEveryTagSizeTheFormatDoesNot — RFC 3610 allows the even
// values 4..16 and no others.
func TestNewCCMRefusesEveryTagSizeTheFormatDoesNot(t *testing.T) {
	b, _ := aes.NewCipher(make([]byte, 16))
	for _, tagSize := range []int{-2, 0, 2, 3, 5, 15, 17, 18} {
		if _, err := NewCCM(b, tagSize, 13); err == nil {
			t.Errorf("tag size %d was accepted", tagSize)
		}
	}
	// The other direction, or the rule above would pass for a constructor
	// that refuses everything.
	for _, tagSize := range []int{4, 6, 8, 10, 12, 14, 16} {
		if _, err := NewCCM(b, tagSize, 13); err != nil {
			t.Errorf("tag size %d was refused: %v", tagSize, err)
		}
	}
}

// TestMaxPlaintextForTheShortestNonce. L = 15 - N, so a 7-byte nonce gives
// L = 8 and a length field that cannot overflow — the branch returning the
// whole uint64 range, which every RFC vector (N = 13) misses.
func TestMaxPlaintextForTheShortestNonce(t *testing.T) {
	if got := aead(t, 8, 7).maxPlaintextLen(); got != ^uint64(0) {
		t.Errorf("L=8 max = %d, want %d", got, uint64(1<<64-1))
	}
	// And the ordinary case below it, so the test says which is which.
	if got := aead(t, 8, 13).maxPlaintextLen(); got != 1<<16-1 {
		t.Errorf("L=2 max = %d, want 65535", got)
	}
}

// TestSealPanicsRatherThanForgingAShortNonce. Seal has no error return — the
// cipher.AEAD contract says a wrong nonce length is a programming mistake —
// so the only honest answer is a panic, and it has to be tested as one.
func TestSealPanicsRatherThanForgingAShortNonce(t *testing.T) {
	c := aead(t, 16, 13)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("a 4-byte nonce was accepted for a 13-byte AEAD")
		}
		if !strings.Contains(r.(string), "nonce") {
			t.Errorf("the panic does not say what is wrong: %v", r)
		}
	}()
	c.Seal(nil, make([]byte, 4), []byte("hello"), nil)
}

// TestSealPanicsOnAPlaintextTheLengthFieldCannotHold. N = 13 leaves two bytes
// for the length, so 65536 is one byte too many — and sealing it would write a
// truncated length into B_0, which is a forgery nobody would notice.
func TestSealPanicsOnAPlaintextTheLengthFieldCannotHold(t *testing.T) {
	c := aead(t, 16, 13)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("a plaintext of 65536 bytes was sealed under a 2-byte length field")
		} else if !strings.Contains(r.(string), "too large") {
			t.Errorf("the panic does not say what is wrong: %v", r)
		}
	}()
	c.Seal(nil, make([]byte, 13), make([]byte, 1<<16), nil)
}

// TestOpenReturnsErrorsWhereSealPanics. Open takes untrusted input, so the
// same three conditions are errors rather than panics — that asymmetry is the
// design, and a test that treated them alike would hide it.
func TestOpenReturnsErrorsWhereSealPanics(t *testing.T) {
	c := aead(t, 16, 13)
	for name, in := range map[string]struct{ nonce, ct []byte }{
		"nonce too short":  {make([]byte, 4), make([]byte, 32)},
		"shorter than tag": {make([]byte, 13), make([]byte, 15)},
		"longer than L":    {make([]byte, 13), make([]byte, 1<<16+16)},
	} {
		out, err := c.Open(nil, in.nonce, in.ct, nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if out != nil {
			t.Errorf("%s: returned plaintext with an error", name)
		}
	}
}

// TestEncodeADLenCoversAllThreeCases, including the one that would need four
// gigabytes of additional data to reach through Seal. That is why it is a
// function of its own: the case is required by RFC 3610 §2.2 and no test is
// going to allocate its input.
func TestEncodeADLenCoversAllThreeCases(t *testing.T) {
	for _, c := range []struct {
		n       uint64
		wantLen int
		wantHdr []byte
	}{
		{1, 2, []byte{0x00, 0x01}},
		{0xfeff, 2, []byte{0xfe, 0xff}},                           // the last two-byte length
		{0xff00, 6, []byte{0xff, 0xfe, 0x00, 0x00, 0xff, 0x00}},   // the first six-byte one
		{1 << 31, 6, []byte{0xff, 0xfe, 0x80, 0x00, 0x00, 0x00}},  //
		{1 << 32, 10, []byte{0xff, 0xff, 0, 0, 0, 1, 0, 0, 0, 0}}, // the first ten-byte one
		{^uint64(0), 10, []byte{0xff, 0xff, 255, 255, 255, 255, 255, 255, 255, 255}},
	} {
		hdr, n := encodeADLen(c.n)
		if n != c.wantLen {
			t.Errorf("encodeADLen(%d) length = %d, want %d", c.n, n, c.wantLen)
		}
		if !bytes.Equal(hdr[:n], c.wantHdr) {
			t.Errorf("encodeADLen(%d) = % x, want % x", c.n, hdr[:n], c.wantHdr)
		}
	}
}

// TestTheSixByteHeaderIsReachedThroughSeal, so the boundary in encodeADLen is
// the one Seal actually crosses and not a number two tests agree on. 0xff00
// bytes of additional data is 65 280 — large, and allocatable.
func TestTheSixByteHeaderIsReachedThroughSeal(t *testing.T) {
	c := aead(t, 16, 13)
	nonce := make([]byte, 13)
	big := make([]byte, 0xff00)
	sealed := c.Seal(nil, nonce, []byte("body"), big)
	got, err := c.Open(nil, nonce, sealed, big)
	if err != nil {
		t.Fatalf("a message with 65 280 bytes of AAD did not open: %v", err)
	}
	if string(got) != "body" {
		t.Errorf("round trip gave %q", got)
	}
	// And it must NOT open against additional data one byte shorter, or the
	// length prefix is not authenticating what it claims to.
	if _, err := c.Open(nil, nonce, sealed, big[:len(big)-1]); err == nil {
		t.Error("it opened against different additional data")
	}
}

// TestSealAppendsIntoSpareCapacity. sliceForAppend has a path for a dst that
// already has room, which every RFC vector misses by passing nil.
func TestSealAppendsIntoSpareCapacity(t *testing.T) {
	c := aead(t, 16, 13)
	nonce := make([]byte, 13)
	prefix := []byte("keep-me")

	roomy := make([]byte, len(prefix), len(prefix)+512)
	copy(roomy, prefix)
	withRoom := c.Seal(roomy, nonce, []byte("body"), nil)

	exact := c.Seal(append([]byte{}, prefix...), nonce, []byte("body"), nil)

	if !bytes.Equal(withRoom, exact) {
		t.Errorf("appending into spare capacity gave a different result:\n % x\n % x", withRoom, exact)
	}
	if !bytes.HasPrefix(withRoom, prefix) {
		t.Errorf("the caller's bytes were overwritten: % x", withRoom)
	}
	got, err := c.Open(nil, nonce, withRoom[len(prefix):], nil)
	if err != nil || string(got) != "body" {
		t.Errorf("Open on the appended part: %q %v", got, err)
	}
}

// A guard on the constant this file leans on: if blockSize ever stopped being
// 16 the DES test above would be testing nothing.
func TestBlockSizeIsTheOneCCMIsDefinedOver(t *testing.T) {
	if blockSize != 16 {
		t.Fatalf("blockSize = %d; CCM is defined over 128-bit blocks", blockSize)
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], 1)
	if b[0] != 0 || b[1] != 1 {
		t.Error("the length prefixes are big-endian and this platform disagrees")
	}
}
