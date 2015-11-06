package zip

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"
)

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
	f.SetPassword([]byte("golang"))
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
		f.SetPassword([]byte("golang"))
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
		f.SetPassword([]byte("golang"))
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

// Test for AE-1 vs AE-2
// Test for tampered data payload, use messWith
// Test streaming vs buffered reading
