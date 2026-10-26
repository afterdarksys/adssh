//go:build ee

package grid

import (
	"testing"
	"time"
)

func TestAgentSponsorEnded(t *testing.T) {
	for _, key := range []string{
		"ADSSH_QUARANTINE",
		"ADSSH_QUARANTINE_FILE",
		"ADSSH_HOST_PROFILE",
		"ADSSH_HOST_PROFILE_PREV",
		"ADSSH_HOST_PROFILE_KEYS",
		"ADSSH_HOST_PROFILE_NARROW",
		"ADSSH_HOST_ID",
	} {
		t.Setenv(key, "")
	}
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	sponsor := elevatedSession(t, "sp", "alice")
	initTestGrid(t, testID(t, "g"))
	res, err := procGrid.placeFlight(placeOpts{
		FlightID:       testID(t, "f"),
		AgentID:        testID(t, "a"),
		WorktreeID:     testID(t, "w"),
		TTL:            time.Hour,
		User:           "alice",
		SponsorSession: sponsor.ID,
		Gate:           eng,
	})
	if err != nil {
		t.Fatal(err)
	}
	sponsor.Terminate()
	equalErr(t, eng.AuthorizeCommand([]string{"why"}, res.SessionID), "admin plane: agent sponsor ended")
}
