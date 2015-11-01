// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Counter (CTR) mode.

// CTR converts a block cipher into a stream cipher by
// repeatedly encrypting an incrementing counter and
// xoring the resulting stream of data with the input.

// This is a reimplementation of Go's CTR mode to allow
// for little-endian, left-aligned uint32 counter. Go's
// NewCTR follows the NIST Standard SP 800-38A, pp 13-15
// which has a big-endian, right-aligned counter. WinZip
// AES requires the CTR mode to have a little-endian,
// left-aligned counter.

package zip

import "crypto/cipher"

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
