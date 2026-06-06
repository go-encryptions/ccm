package ccm

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// rfc3610Packet is one of the 8 test packets enumerated in
// RFC 3610 §8 (Test Vectors). Each packet documents:
//   - K (16-byte key)
//   - N (13-byte nonce)
//   - hdr (associated data)
//   - body (plaintext)
//   - mLen (tag length M, in bytes)
//   - want (expected ciphertext || tag)
type rfc3610Packet struct {
	name        string
	key         string
	nonce       string
	ad          string
	pt          string
	tagLen      int
	wantPayload string // ciphertext (post-AD) appended with tag
}

// All 8 RFC 3610 packets share the same 16-byte key. Across packets
// 1-4 the tag length is 8; packets 5-8 use a 10-byte tag. AD ranges
// from 8 to 12 bytes in the published vectors.
const rfcKey = "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"

var rfc3610Vectors = []rfc3610Packet{
	{
		name:        "packet#1 M=8",
		key:         rfcKey,
		nonce:       "00000003020100A0A1A2A3A4A5",
		ad:          "0001020304050607",
		pt:          "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
		tagLen:      8,
		wantPayload: "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0",
	},
	{
		name:        "packet#2 M=8",
		key:         rfcKey,
		nonce:       "00000004030201A0A1A2A3A4A5",
		ad:          "0001020304050607",
		pt:          "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		tagLen:      8,
		wantPayload: "72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916",
	},
	{
		name:        "packet#3 M=8",
		key:         rfcKey,
		nonce:       "00000005040302A0A1A2A3A4A5",
		ad:          "0001020304050607",
		pt:          "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
		tagLen:      8,
		wantPayload: "51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA8596574ADAA76FBD9FB0C5",
	},
	{
		name:        "packet#4 M=8 AD=12",
		key:         rfcKey,
		nonce:       "00000006050403A0A1A2A3A4A5",
		ad:          "000102030405060708090A0B",
		pt:          "0C0D0E0F101112131415161718191A1B1C1D1E",
		tagLen:      8,
		wantPayload: "A28C6865939A9A79FAAA5C4C2A9D4A91CDAC8C96C861B9C9E61EF1",
	},
	{
		name:        "packet#5 M=8 AD=12",
		key:         rfcKey,
		nonce:       "00000007060504A0A1A2A3A4A5",
		ad:          "000102030405060708090A0B",
		pt:          "0C0D0E0F101112131415161718191A1B1C1D1E1F",
		tagLen:      8,
		wantPayload: "DCF1FB7B5D9E23FB9D4E131253658AD86EBDCA3E51E83F077D9C2D93",
	},
	{
		name:        "packet#6 M=8 AD=12",
		key:         rfcKey,
		nonce:       "00000008070605A0A1A2A3A4A5",
		ad:          "000102030405060708090A0B",
		pt:          "0C0D0E0F101112131415161718191A1B1C1D1E1F20",
		tagLen:      8,
		wantPayload: "6FC1B011F006568B5171A42D953D469B2570A4BD87405A0443AC91CB94",
	},
	{
		name:        "packet#7 M=10",
		key:         rfcKey,
		nonce:       "00000009080706A0A1A2A3A4A5",
		ad:          "0001020304050607",
		pt:          "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
		tagLen:      10,
		wantPayload: "0135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C048C56602C97ACBB7490",
	},
	{
		name:        "packet#8 M=10",
		key:         rfcKey,
		nonce:       "0000000A090807A0A1A2A3A4A5",
		ad:          "0001020304050607",
		pt:          "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		tagLen:      10,
		wantPayload: "7B75399AC0831DD2F0BBD75879A2FD8F6CAE6B6CD9B7DB24C17B4433F434963F34B4",
	},
}

func TestSealRFC3610(t *testing.T) {
	for _, tc := range rfc3610Vectors {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHex(t, tc.key)
			nonce := mustHex(t, tc.nonce)
			ad := mustHex(t, tc.ad)
			pt := mustHex(t, tc.pt)
			want := mustHex(t, tc.wantPayload)

			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatalf("aes.NewCipher: %v", err)
			}
			aead, err := NewCCM(block, tc.tagLen, len(nonce))
			if err != nil {
				t.Fatalf("NewCCM: %v", err)
			}
			got := aead.Seal(nil, nonce, pt, ad)
			if !bytes.Equal(got, want) {
				t.Errorf("Seal mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

func TestOpenRFC3610(t *testing.T) {
	for _, tc := range rfc3610Vectors {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHex(t, tc.key)
			nonce := mustHex(t, tc.nonce)
			ad := mustHex(t, tc.ad)
			pt := mustHex(t, tc.pt)
			ct := mustHex(t, tc.wantPayload)

			block, _ := aes.NewCipher(key)
			aead, _ := NewCCM(block, tc.tagLen, len(nonce))
			got, err := aead.Open(nil, nonce, ct, ad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("plaintext mismatch\n got %x\nwant %x", got, pt)
			}
		})
	}
}

// TestOpenAuthFailure flips the final byte of every RFC 3610 packet
// and confirms Open rejects it.
func TestOpenAuthFailure(t *testing.T) {
	for _, tc := range rfc3610Vectors {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHex(t, tc.key)
			nonce := mustHex(t, tc.nonce)
			ad := mustHex(t, tc.ad)
			ct := mustHex(t, tc.wantPayload)

			ct[len(ct)-1] ^= 0x01

			block, _ := aes.NewCipher(key)
			aead, _ := NewCCM(block, tc.tagLen, len(nonce))
			if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
				t.Fatalf("Open accepted a corrupted ciphertext")
			}
		})
	}
}

// TestNonceSizeOutOfRange covers the parameter-validation guards.
func TestNonceSizeOutOfRange(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))

	if _, err := NewCCM(block, 16, 6); err == nil {
		t.Errorf("expected nonceSize=6 to be rejected")
	}
	if _, err := NewCCM(block, 16, 14); err == nil {
		t.Errorf("expected nonceSize=14 to be rejected")
	}
	if _, err := NewCCM(block, 3, 12); err == nil {
		t.Errorf("expected tagSize=3 to be rejected")
	}
	if _, err := NewCCM(block, 5, 12); err == nil {
		t.Errorf("expected tagSize=5 (odd) to be rejected")
	}
}

// TestZFSDefaults exercises the parameter set OpenZFS uses
// (N=12, M=16) — round-trip a chunk of random-ish data through
// Seal+Open and confirm we get the input back.
func TestZFSDefaults(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(0xa0 ^ i)
	}
	pt := make([]byte, 4096)
	for i := range pt {
		pt[i] = byte(i)
	}
	ad := []byte("zfs-block-aad-example")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes-256: %v", err)
	}
	aead, err := NewCCM(block, 16, 12)
	if err != nil {
		t.Fatalf("NewCCM zfs defaults: %v", err)
	}
	if aead.NonceSize() != 12 {
		t.Errorf("NonceSize = %d, want 12", aead.NonceSize())
	}
	if aead.Overhead() != 16 {
		t.Errorf("Overhead = %d, want 16", aead.Overhead())
	}

	ct := aead.Seal(nil, nonce, pt, ad)
	if len(ct) != len(pt)+16 {
		t.Fatalf("Seal output len = %d, want %d", len(ct), len(pt)+16)
	}
	round, err := aead.Open(nil, nonce, ct, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(round, pt) {
		t.Errorf("round-trip mismatch")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}
