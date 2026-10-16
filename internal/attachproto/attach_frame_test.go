package attachproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestAttachFrameRoundTrip(t *testing.T) {
	cases := []struct {
		typ     byte
		payload []byte
	}{
		{AttachFrameOut, []byte("hello\r\n")},
		{AttachFrameIn, []byte("ls\r")},
		{AttachFrameResize, []byte(`{"cols":120,"rows":40}`)},
		{AttachFrameClose, []byte(`{"reason":"detach"}`)},
		{AttachFrameOut, nil},
		{AttachFrameOut, bytes.Repeat([]byte{'x'}, AttachMaxFrame)},
	}
	var buf bytes.Buffer
	for _, c := range cases {
		if err := WriteAttachFrame(&buf, c.typ, c.payload); err != nil {
			t.Fatalf("write 0x%02x: %v", c.typ, err)
		}
	}
	for _, c := range cases {
		typ, payload, err := ReadAttachFrame(&buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if typ != c.typ || !bytes.Equal(payload, c.payload) {
			t.Fatalf("got 0x%02x %d bytes, want 0x%02x %d bytes", typ, len(payload), c.typ, len(c.payload))
		}
	}
	if _, _, err := ReadAttachFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read past end: %v, want io.EOF", err)
	}
	if AttachProtocol != "adssh-attach/1" {
		t.Fatalf("AttachProtocol = %q", AttachProtocol)
	}
}

func TestAttachFrameRejectsOversized(t *testing.T) {
	if err := WriteAttachFrame(io.Discard, AttachFrameOut, make([]byte, AttachMaxFrame+1)); err == nil {
		t.Fatal("write of an oversized frame succeeded")
	}
	// Only the header is supplied: the length must be refused before the
	// body is allocated or read.
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], AttachMaxFrame+1)
	hdr[4] = AttachFrameOut
	if _, _, err := ReadAttachFrame(bytes.NewReader(hdr[:])); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("oversized read: %v, want a frame-too-large error", err)
	}
	binary.BigEndian.PutUint32(hdr[:4], 0xffffffff)
	if _, _, err := ReadAttachFrame(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("4 GiB length accepted")
	}
}

func TestAttachFrameRejectsUnknownType(t *testing.T) {
	for _, typ := range []byte{0x00, 0x01, 0x0f, 0x14, 0xff} {
		var buf bytes.Buffer
		var hdr [5]byte
		binary.BigEndian.PutUint32(hdr[:4], 2)
		hdr[4] = typ
		buf.Write(hdr[:])
		buf.WriteString("hi")
		if _, _, err := ReadAttachFrame(&buf); err == nil {
			t.Fatalf("type 0x%02x accepted", typ)
		}
		if err := WriteAttachFrame(io.Discard, typ, nil); err == nil {
			t.Fatalf("write of type 0x%02x accepted", typ)
		}
	}
}

func TestAttachFrameTruncatedBody(t *testing.T) {
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], 10)
	hdr[4] = AttachFrameIn
	r := io.MultiReader(bytes.NewReader(hdr[:]), bytes.NewReader([]byte("abc")))
	if _, _, err := ReadAttachFrame(r); err == nil {
		t.Fatal("truncated body accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestAttachFrameShortWriteFails(t *testing.T) {
	if err := WriteAttachFrame(shortWriter{}, AttachFrameOut, []byte("abc")); err == nil {
		t.Fatal("short write reported success")
	}
}
