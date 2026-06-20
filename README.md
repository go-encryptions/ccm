<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/ccm" width="720"></p>

# go-encryptions/ccm

[![ci](https://github.com/go-encryptions/ccm/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/ccm/actions/workflows/ci.yml)

Pure-Go **AES-CCM** (Counter with CBC-MAC) AEAD, per [RFC 3610](https://www.rfc-editor.org/rfc/rfc3610) and [NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final). CCM is not in the Go standard library — `crypto/cipher` only exposes GCM — so this package fills the gap **without** pulling in `golang.org/x/crypto`.

It wraps any 128-bit `cipher.Block` (typically `crypto/aes`) and implements the standard `cipher.AEAD` interface, so it drops into anything that already speaks Seal/Open. Built for the [`go-encryptions`](https://github.com/go-encryptions) family; the primary consumer is [`go-encryptions/zfscrypt`](https://github.com/go-encryptions/zfscrypt) (OpenZFS native encryption).

## Install

```sh
go get github.com/go-encryptions/ccm
```

## Usage

```go
block, _ := aes.NewCipher(key)          // 16/24/32-byte AES key
aead, err := ccm.NewCCM(block, 16, 12)  // tagSize=16, nonceSize=12 (the OpenZFS default)
if err != nil { /* ... */ }

ct := aead.Seal(nil, nonce, plaintext, additionalData)
pt, err := aead.Open(nil, nonce, ct, additionalData) // err != nil ⇒ authentication failed
```

## Parameter ranges

| parameter | symbol | allowed | notes |
| --- | --- | --- | --- |
| nonce size | N | `[7, 13]` bytes | encoded as `L = 15 − N` |
| tag size | M | `{4, 6, 8, 10, 12, 14, 16}` | even, 4…16 |
| plaintext | P | `len(P) ≤ 2^(8L) − 1` | with N=12 ⇒ up to 2^24 bytes (one ZFS block) |

`NewCCM` validates all three and returns an error on out-of-range values; `Seal` panics on a wrong-length nonce or oversized plaintext, matching the `cipher.AEAD` contract.

## Security notes

- Tag verification is constant-time (`crypto/subtle`); `Open` commits to `dst` only after the tag checks out and wipes its scratch buffer on failure.
- Correct CBC-MAC + CTR construction with proper AAD length encoding (RFC 3610 §2.2).
- No weak primitives, no `unsafe`, no cgo. Pure Go.

## License

BSD-3-Clause © the go-encryptions/ccm authors.
