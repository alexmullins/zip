// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Counter (CTR) mode.

// CTR converts a block cipher into a stream cipher by
// repeatedly encrypting an incrementing counter and
// xoring the resulting stream of data with the input.

// This is a reimplementation of Go's CTR mode to allow
// for little-endian, left-aligned uint32 counter. Go's
// cipher.NewCTR follows the NIST Standard SP 800-38A, pp 13-15
// which has a big-endian, right-aligned counter. WinZip
// AES requires the CTR mode to have a little-endian,
// left-aligned counter.

type ctr struct {
	b       cipher.Block
	ctr     []byte
	out     []byte
	outUsed int
}

const streamBufferSize = 512

// NewWinZipCTR returns a Stream which encrypts/decrypts using the given Block in
// counter mode. The counter is initially set to 1.
func newWinZipCTR(block cipher.Block) cipher.Stream {
	bufSize := streamBufferSize
	if bufSize < block.BlockSize() {
		bufSize = block.BlockSize()
	}
	// Set the IV (counter) to 1
	iv := make([]byte, block.BlockSize())
	iv[0] = 1
	return &ctr{
		b:       block,
		ctr:     iv,
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}
}

func (x *ctr) refill() {
	remain := len(x.out) - x.outUsed
	if remain > x.outUsed {
		return
	}
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)]
	bs := x.b.BlockSize()
	for remain < len(x.out)-bs {
		x.b.Encrypt(x.out[remain:], x.ctr)
		remain += bs

		// Increment counter
		// for i := len(x.ctr) - 1; i >= 0; i-- {
		// 	x.ctr[i]++
		// 	if x.ctr[i] != 0 {
		// 		break
		// 	}
		// }

		// Change to allow for little-endian,
		// left-aligned counter
		for i := 0; i < len(x.ctr); i++ {
			x.ctr[i]++
			if x.ctr[i] != 0 {
				break
			}
		}
	}
	x.out = x.out[:remain]
	x.outUsed = 0
}

func (x *ctr) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		if x.outUsed >= len(x.out)-x.b.BlockSize() {
			x.refill()
		}
		n := xorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}

func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

func checkAuthentication(message, authcode, key []byte) bool {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	expectedAuthCode := mac.Sum(nil)
	// Truncate at the first 10 bytes
	expectedAuthCode = expectedAuthCode[:10]
	// Change to use crypto/subtle for constant time comparison
	return bytes.Equal(expectedAuthCode, authcode)
}

func generateKeys(password, salt []byte, keySize int) (encKey, authKey, pwv []byte) {
	totalSize := (keySize * 2) + 2 // enc + auth + pv sizes
	key := pbkdf2.Key(password, salt, 1000, totalSize, sha1.New)
	encKey = key[:keySize]
	authKey = key[keySize : keySize*2]
	pwv = key[keySize*2:]
	return
}

func newDecryptionReader(r io.Reader, f *File) (io.Reader, error) {
	keyLen := aesKeyLen(f.aesStrength)
	saltLen := keyLen / 2 // salt is half of key len
	if saltLen == 0 {
		return nil, ErrDecryption
	}
	// Change to a streaming implementation
	// Maybe not such a good idea after all.
	// See:
	// https://www.imperialviolet.org/2014/06/27/streamingencryption.html
	// https://www.imperialviolet.org/2015/05/16/aeads.html
	content := make([]byte, f.CompressedSize64)
	if _, err := io.ReadFull(r, content); err != nil {
		return nil, ErrDecryption
	}
	// grab the salt, pwvv, data, and authcode
	salt := content[:saltLen]
	pwvv := content[saltLen : saltLen+2]
	content = content[saltLen+2:]
	size := f.CompressedSize64 - uint64(saltLen) - 2 - 10
	data := content[:size]
	authcode := content[size:]
	// generate keys
	decKey, authKey, pwv := generateKeys(f.password, salt, keyLen)
	// check password verifier (pwv)
	// Change to use crypto/subtle for constant time comparison
	if !bytes.Equal(pwv, pwvv) {
		return nil, ErrDecryption
	}
	// check authentication
	if !checkAuthentication(data, authcode, authKey) {
		return nil, ErrDecryption
	}
	return decryptStream(data, decKey), nil
}

func decryptStream(ciphertext, key []byte) io.Reader {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	stream := newWinZipCTR(block)
	reader := cipher.StreamReader{S: stream, R: bytes.NewReader(ciphertext)}
	return reader
}

func aesKeyLen(strength byte) int {
	switch strength {
	case 1:
		return aes128
	case 2:
		return aes192
	case 3:
		return aes256
	default:
		return 0
	}
}
