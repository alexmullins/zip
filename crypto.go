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
	"crypto/subtle"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/pbkdf2"
)

// Decryption Errors
var (
	ErrDecryption = errors.New("zip: decryption error")
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

type authReader struct {
	data  io.Reader     // data to be authenticated
	adata io.Reader     // the authentication code to read
	akey  []byte        // authentication key
	buf   *bytes.Buffer // buffer to store data to authenticate
	err   error
	auth  bool
}

func newAuthReader(akey []byte, data, adata io.Reader) io.Reader {
	return &authReader{
		data:  data,
		adata: adata,
		akey:  akey,
		buf:   new(bytes.Buffer),
		err:   nil,
		auth:  false,
	}
}

// Read will fully buffer the file data payload to authenticate first.
// If authentication fails, returns ErrDecryption immediately.
// Else, sends data along for decryption.
func (a *authReader) Read(b []byte) (int, error) {
	// check for sticky error
	if a.err != nil {
		return 0, a.err
	}
	// make sure we have auth'ed before we send any data
	if !a.auth {
		nn, err := io.Copy(a.buf, a.data)
		if err != nil {
			a.err = ErrDecryption
			return 0, a.err
		}
		ab := new(bytes.Buffer)
		nn, err = io.Copy(ab, a.adata)
		if err != nil || nn != 10 {
			a.err = ErrDecryption
			return 0, a.err
		}
		a.auth = checkAuthentication(a.buf.Bytes(), ab.Bytes(), a.akey)
		if !a.auth {
			a.err = ErrDecryption
			return 0, a.err
		}
	}
	// so we've authenticated the data, now just pass it on.
	n, err := a.buf.Read(b)
	if err != nil {
		a.err = err
	}
	return n, a.err
}

func checkAuthentication(message, authcode, key []byte) bool {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	expectedAuthCode := mac.Sum(nil)
	// Truncate at the first 10 bytes
	expectedAuthCode = expectedAuthCode[:10]
	// Change to use crypto/subtle for constant time comparison
	b := subtle.ConstantTimeCompare(expectedAuthCode, authcode) > 0
	return b
}

func checkPasswordVerification(pwvv, pwv []byte) bool {
	b := subtle.ConstantTimeCompare(pwvv, pwv) > 0
	return b
}

func generateKeys(password, salt []byte, keySize int) (encKey, authKey, pwv []byte) {
	totalSize := (keySize * 2) + 2 // enc + auth + pv sizes
	key := pbkdf2.Key(password, salt, 1000, totalSize, sha1.New)
	encKey = key[:keySize]
	authKey = key[keySize : keySize*2]
	pwv = key[keySize*2:]
	return
}

func newDecryptionReader(r *io.SectionReader, f *File) (io.ReadCloser, error) {
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
	// grab the salt, pwvv, data, and authcode
	saltpwvv := make([]byte, saltLen+2)
	if _, err := r.Read(saltpwvv); err != nil {
		return nil, ErrDecryption
	}
	salt := saltpwvv[:saltLen]
	pwvv := saltpwvv[saltLen : saltLen+2]
	dataOff := int64(saltLen + 2)
	dataLen := int64(f.CompressedSize64 - uint64(saltLen) - 2 - 10)
	data := io.NewSectionReader(r, dataOff, dataLen)
	authOff := dataOff + dataLen
	authcode := io.NewSectionReader(r, authOff, 10)
	// generate keys
	decKey, authKey, pwv := generateKeys(f.password, salt, keyLen)
	// check password verifier (pwv)
	// Change to use crypto/subtle for constant time comparison
	if !checkPasswordVerification(pwv, pwvv) {
		return nil, ErrDecryption
	}
	// setup auth reader
	ar := newAuthReader(authKey, data, authcode)
	// return decryption reader
	dr := decryptStream(decKey, ar)
	return ioutil.NopCloser(dr), nil
}

func decryptStream(key []byte, ciphertext io.Reader) io.Reader {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	stream := newWinZipCTR(block)
	reader := &cipher.StreamReader{S: stream, R: ciphertext}
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
