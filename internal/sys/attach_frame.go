package sys

import (
	"encoding/binary"
	"errors"
	"io"
)

// Threats: an attach stream carries another user's terminal to an admin
// client, and in rw mode the client's keystrokes back to it. Frames are a
// 4-byte big-endian length, one type byte, and the payload, as on the monitor
// socket. A length over AttachMaxFrame is refused before the body is
// allocated, and a type outside Out/In/Resize/Close is refused, so a
// malformed or hostile peer ends the attach instead of desynchronizing it. A
// short write fails closed. This file does not authorize anything: whether
// In and Resize are allowed is the attach handler's decision.

const (
	// AttachProtocol is the Upgrade token of the admin attach endpoint.
	AttachProtocol = "adssh-attach/1"
	// AttachMaxFrame bounds one frame's payload.
	AttachMaxFrame = 1 << 20

	// AttachFrameOut carries raw session output, server to client.
	AttachFrameOut = byte(0x10)
	// AttachFrameIn carries raw input, client to server, rw only.
	AttachFrameIn = byte(0x11)
	// AttachFrameResize carries {"cols":N,"rows":N}, client to server, rw only.
	AttachFrameResize = byte(0x12)
	// AttachFrameClose carries {"reason":"..."} either way and ends the attach.
	AttachFrameClose = byte(0x13)
)

var (
	errAttachFrameTooLarge = errors.New("adssh: attach: frame too large")
	errAttachFrameType     = errors.New("adssh: attach: unknown frame type")
	errAttachShortWrite    = errors.New("adssh: attach: short write")
	errAttachTruncated     = errors.New("adssh: attach: truncated frame")
)

func validAttachFrameType(typ byte) bool {
	return typ >= AttachFrameOut && typ <= AttachFrameClose
}

// ReadAttachFrame reads one frame. A clean end of stream before a frame
// starts is io.EOF; a stream that ends inside a frame, an oversized length,
// or an unknown type is an error that ends the attach.
func ReadAttachFrame(r io.Reader) (typ byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, io.EOF
		}
		return 0, nil, errAttachTruncated
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n > AttachMaxFrame {
		return 0, nil, errAttachFrameTooLarge
	}
	if !validAttachFrameType(hdr[4]) {
		return 0, nil, errAttachFrameType
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, errAttachTruncated
	}
	return hdr[4], payload, nil
}

// WriteAttachFrame writes the length, type, and payload in one Write. A short
// write fails closed.
func WriteAttachFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > AttachMaxFrame {
		return errAttachFrameTooLarge
	}
	if !validAttachFrameType(typ) {
		return errAttachFrameType
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	buf[4] = typ
	copy(buf[5:], payload)
	n, err := w.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return errAttachShortWrite
	}
	return nil
}
