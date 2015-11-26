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
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// AES key lengths
	aes128 = 16
	aes192 = 24
	aes256 = 32
)

// Encryption/Decryption Errors
var (
	ErrDecryption     = errors.New("zip: decryption error")
	ErrPassword       = errors.New("zip: invalid password")
	ErrAuthentication = errors.New("zip: authentication failed")
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
	data  io.Reader // data to be authenticated
	adata io.Reader // the authentication code to read
	mac   hash.Hash // hmac hash
	err   error
	auth  bool
}

// Streaming authentication
func (a *authReader) Read(p []byte) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	end := false
	// read underlying data
	n, err := a.data.Read(p)
	if err != nil && err != io.EOF {
		a.err = err
		return n, a.err
	} else if err == io.EOF {
		// if we are at the end, calculate the mac
		end = true
		a.err = err
	}
	// write any data to mac
	nn, err := a.mac.Write(p[:n])
	if nn != n || err != nil {
		a.err = io.ErrUnexpectedEOF
		return n, a.err
	}
	if end {
		ab := new(bytes.Buffer)
		_, err = io.Copy(ab, a.adata)
		if err != nil || ab.Len() != 10 {
			a.err = io.ErrUnexpectedEOF
			return n, a.err
		}
		if !a.checkAuthentication(ab.Bytes()) {
			a.err = ErrAuthentication
			return n, a.err
		}
	}
	return n, a.err
}

// newAuthReader returns either a buffered or streaming authentication reader.
// Buffered authentication is recommended. Streaming authentication is only
// recommended if: 1. you buffer the data yourself and wait for authentication
// before streaming to another source such as the network, or 2. you just don't
// care about authenticating unknown ciphertext before use :).
func newAuthReader(akey []byte, data, adata io.Reader, streaming bool) io.Reader {
	ar := authReader{
		data:  data,
		adata: adata,
		mac:   hmac.New(sha1.New, akey),
		err:   nil,
		auth:  false,
	}
	if streaming {
		return &ar
	}
	return &bufferedAuthReader{
		ar,
		new(bytes.Buffer),
	}
}

type bufferedAuthReader struct {
	authReader
	buf *bytes.Buffer // buffer to store data to authenticate
}

// buffered authentication
func (a *bufferedAuthReader) Read(b []byte) (int, error) {
	// check for sticky error
	if a.err != nil {
		return 0, a.err
	}
	// make sure we have auth'ed before we send any data
	if !a.auth {
		_, err := io.Copy(a.buf, a.data)
		if err != nil {
			a.err = io.ErrUnexpectedEOF
			return 0, a.err
		}
		ab := new(bytes.Buffer)
		nn, err := io.Copy(ab, a.adata)
		if err != nil || nn != 10 {
			a.err = io.ErrUnexpectedEOF
			return 0, a.err
		}
		mn, err := a.mac.Write(a.buf.Bytes())
		if mn != a.buf.Len() || err != nil {
			a.err = io.ErrUnexpectedEOF
			return 0, a.err
		}
		if !a.checkAuthentication(ab.Bytes()) {
			a.err = ErrAuthentication
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

func (a *authReader) checkAuthentication(authcode []byte) bool {
	expectedAuthCode := a.mac.Sum(nil)
	// Truncate at the first 10 bytes
	expectedAuthCode = expectedAuthCode[:10]
	// Change to use crypto/subtle for constant time comparison
	a.auth = subtle.ConstantTimeCompare(expectedAuthCode, authcode) > 0
	return a.auth
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

// newDecryptionReader returns an authenticated, decryption reader
func newDecryptionReader(r *io.SectionReader, f *File) (io.Reader, error) {
	keyLen := aesKeyLen(f.aesStrength)
	saltLen := keyLen / 2 // salt is half of key len
	if saltLen == 0 {
		return nil, ErrDecryption
	}
	// Change to a streaming implementation
	// Maybe not such a good idea after all. See:
	// https://www.imperialviolet.org/2014/06/27/streamingencryption.html
	// https://www.imperialviolet.org/2015/05/16/aeads.html
	// grab the salt, pwvv, data, and authcode
	saltpwvv := make([]byte, saltLen+2)
	if _, err := r.Read(saltpwvv); err != nil {
		return nil, err
	}
	salt := saltpwvv[:saltLen]
	pwvv := saltpwvv[saltLen : saltLen+2]
	// generate keys
	decKey, authKey, pwv := generateKeys(f.password, salt, keyLen)
	// check password verifier (pwv)
	// Change to use crypto/subtle for constant time comparison
	if !checkPasswordVerification(pwv, pwvv) {
		return nil, ErrPassword
	}
	dataOff := int64(saltLen + 2)
	dataLen := int64(f.CompressedSize64 - uint64(saltLen) - 2 - 10)
	data := io.NewSectionReader(r, dataOff, dataLen)
	authOff := dataOff + dataLen
	authcode := io.NewSectionReader(r, authOff, 10)
	// setup auth reader, (buffered)/streaming
	ar := newAuthReader(authKey, data, authcode, false)
	// return decryption reader
	dr := decryptStream(decKey, ar)
	if dr == nil {
		return nil, ErrDecryption
	}
	return dr, nil
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
