package sys

import (
	"encoding/binary"
	"testing"
)

func TestParseDirectTCPIPPayload(t *testing.T) {
	payloadBytes := appendSSHString(nil, "db.internal")
	payloadBytes = binary.BigEndian.AppendUint32(payloadBytes, 5432)
	payloadBytes = appendSSHString(payloadBytes, "127.0.0.1")
	payloadBytes = binary.BigEndian.AppendUint32(payloadBytes, 60000)

	payload, err := parseDirectTCPIPPayload(payloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	if payload.TargetHost != "db.internal" || payload.TargetPort != 5432 {
		t.Fatalf("target = %s:%d", payload.TargetHost, payload.TargetPort)
	}
	if payload.OriginatorHost != "127.0.0.1" || payload.OriginatorPort != 60000 {
		t.Fatalf("originator = %s:%d", payload.OriginatorHost, payload.OriginatorPort)
	}
}

func TestParseDirectTCPIPPayloadRejectsMalformed(t *testing.T) {
	if _, err := parseDirectTCPIPPayload([]byte{0, 0, 0, 10, 's'}); err == nil {
		t.Fatal("malformed direct-tcpip payload accepted")
	}
}

func appendSSHString(out []byte, value string) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(value)))
	return append(out, value...)
}
