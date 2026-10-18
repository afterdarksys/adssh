//go:build ee

package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Four-eyes helpers for enterprise tests.

func seedPending(t *testing.T, eng *Engine, id, requester, approver string) string {
	t.Helper()
	data, err := json.Marshal(FourEyesPending{Token: "tok-" + id, RequestID: id, Requester: requester, Command: "rm -rf /srv", Rule: FourEyesRule{Approver: approver}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(eng.fourEyesPendingDir(), id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
