package security

import (
	"context"
	"testing"
)

func TestMutationBlockedIsOffWithoutQuarantine(t *testing.T) {
	t.Setenv("ADSSH_QUARANTINE", "")
	t.Setenv("ADSSH_QUARANTINE_FILE", "")
	if mutationBlocked(context.Background()) {
		t.Fatal("mutationBlocked")
	}
}
