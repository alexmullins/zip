package zip

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"
)

var pwFn = func() []byte {
	return []byte("golang")
}

// Test simple password reading.
func TestPasswordSimple(t *testing.T) {
	file := "hello-aes.zip"
	var buf bytes.Buffer
	r, err := OpenReader(filepath.Join("testdata", file))
	if err != nil {
		t.Errorf("Expected %s to open: %v.", file, err)
	}
	defer r.Close()
	if len(r.File) != 1 {
		t.Errorf("Expected %s to contain one file.", file)
	}
	f := r.File[0]
	if f.FileInfo().Name() != "hello.txt" {
		t.Errorf("Expected %s to have a file named hello.txt", file)
	}
	if f.Method != 0 {
		t.Errorf("Expected %s to have its Method set to 0.", file)
	}
	f.Password = pwFn
	rc, err := f.Open()
	if err != nil {
		t.Errorf("Expected to open the readcloser: %v.", err)
	}
	_, err = io.Copy(&buf, rc)
	if err != nil {
		t.Errorf("Expected to copy bytes: %v.", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Hello World\r\n")) {
		t.Errorf("Expected contents were not found.")
	}
}

// Test for multi-file password protected zip.
func TestPasswordHelloWorldAes(t *testing.T) {
	file := "world-aes.zip"
	expecting := "helloworld"
	r, err := OpenReader(filepath.Join("testdata", file))
	if err != nil {
		t.Errorf("Expected %s to open: %v", file, err)
	}
	defer r.Close()
	if len(r.File) != 2 {
		t.Errorf("Expected %s to contain two files.", file)
	}
	var b bytes.Buffer
	for _, f := range r.File {
		if !f.IsEncrypted() {
			t.Errorf("Expected %s to be encrypted.", f.FileInfo().Name)
		}
		f.Password = pwFn
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Expected to open readcloser: %v", err)
		}
		defer rc.Close()
		if _, err := io.Copy(&b, rc); err != nil {
			t.Errorf("Expected to copy bytes to buffer: %v", err)
		}
	}
	if !bytes.Equal([]byte(expecting), b.Bytes()) {
		t.Errorf("Expected ending content to be %s instead of %s", expecting, b.Bytes())
	}
}

// Test for password protected file that is larger than a single
// AES block size to check CTR implementation.
func TestPasswordMacbethAct1(t *testing.T) {
	file := "macbeth-act1.zip"
	expecting := "Exeunt"
	var b bytes.Buffer
	r, err := OpenReader(filepath.Join("testdata", file))
	if err != nil {
		t.Errorf("Expected %s to open: %v", file, err)
	}
	defer r.Close()
	for _, f := range r.File {
		if !f.IsEncrypted() {
			t.Errorf("Expected %s to be encrypted.", f.Name)
		}
		f.Password = pwFn
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Expected to open readcloser: %v", err)
		}
		defer rc.Close()
		if _, err := io.Copy(&b, rc); err != nil {
			t.Errorf("Expected to copy bytes to buffer: %v", err)
		}
	}
	if !bytes.Contains(b.Bytes(), []byte(expecting)) {
		t.Errorf("Expected to find %s in the buffer %v", expecting, b.Bytes())
	}
}

// Change to AE-1 and change CRC value to fail check.
// Must be != 0 due to zip package already skipping if == 0.
func returnAE1BadCRC() (io.ReaderAt, int64) {
	return messWith("hello-aes.zip", func(b []byte) {
		// Change version to AE-1(1)
		b[0x2B] = 1 // file
		b[0xBA] = 1 // TOC
		// Change CRC to bad value
		b[0x11]++ // file
		b[0x6B]++ // TOC
	})
}

// Test for AE-1 Corrupt CRC
func TestPasswordAE1BadCRC(t *testing.T) {
	buf := new(bytes.Buffer)
	file, s := returnAE1BadCRC()
	r, err := NewReader(file, s)
	if err != nil {
		t.Errorf("Expected hello-aes.zip to open: %v", err)
	}
	for _, f := range r.File {
		if !f.IsEncrypted() {
			t.Errorf("Expected zip to be encrypted")
		}
		f.Password = pwFn
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Expected the readcloser to open.")
		}
		defer rc.Close()
		if _, err := io.Copy(buf, rc); err != ErrChecksum {
			t.Errorf("Expected the checksum to fail")
		}
	}
}

// Corrupt the last byte of ciphertext to fail authentication
func returnTamperedData() (io.ReaderAt, int64) {
	return messWith("hello-aes.zip", func(b []byte) {
		b[0x50]++
	})
}

// Test for tampered file data payload.
func TestPasswordTamperedData(t *testing.T) {
	buf := new(bytes.Buffer)
	file, s := returnTamperedData()
	r, err := NewReader(file, s)
	if err != nil {
		t.Errorf("Expected hello-aes.zip to open: %v", err)
	}
	for _, f := range r.File {
		if !f.IsEncrypted() {
			t.Errorf("Expected zip to be encrypted")
		}
		f.Password = pwFn
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Expected the readcloser to open.")
		}
		defer rc.Close()
		if _, err := io.Copy(buf, rc); err != ErrAuthentication {
			t.Errorf("Expected the checksum to fail")
		}
	}
}
