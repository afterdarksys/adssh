//go:build ee

// Threats: quarantine fails closed. A set switch, a present file, or any
// Lstat error other than a missing file activates it. Lift removes only the
// named file, and only after a signed v1 action=lift envelope verifies.
// A bad signature or the wrong action leaves the file. The environment
// switch is not cleared by a file lift. This does not start sshd.
// Non-goals: quarantine is not an allow-all emergency path.

package security

import (
	"os"
	"path"
)

func quarantineActive() bool {
	if envTruthy(os.Getenv("ADSSH_QUARANTINE")) {
		return true
	}
	file := os.Getenv("ADSSH_QUARANTINE_FILE")
	if file == "" {
		return false
	}
	_, err := os.Lstat(file)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

func quarantineAllows(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch path.Base(args[0]) {
	case "journal", "net", "disk", "posture", "asof", "why", "evidence":
		return true
	case "host":
		return len(args) == 2 && (args[1] == "drift" || args[1] == "status" || args[1] == "verify")
	case "unit":
		if len(args) == 2 && (args[1] == "check" || args[1] == "timers") {
			return true
		}
		if len(args) == 3 && (args[1] == "status" || args[1] == "logs") && unitNamePattern.MatchString(args[2]) {
			return true
		}
		if len(args) == 3 && args[1] == "restart" {
			agent := os.Getenv("ADSSH_AGENT_UNIT")
			return agent != "" && args[2] == agent && unitNamePattern.MatchString(args[2])
		}
		return false
	default:
		return false
	}
}

// LiftQuarantine verifies a signed {"v":1,"action":"lift"} envelope and
// removes path. The keys file is ADSSH_HOST_PROFILE_KEYS. One distinct
// signer is required. A verify failure leaves the file in place.
func LiftQuarantine(path string, body []byte) error {
	keys, err := loadEd25519Keys(os.Getenv("ADSSH_HOST_PROFILE_KEYS"))
	if err != nil {
		return err
	}
	payload, _, err := verifySignedPayload(body, keys, 1)
	if err != nil {
		return err
	}
	var lift struct {
		V      int    `json:"v"`
		Action string `json:"action"`
	}
	if err := unmarshalStrict(payload, &lift); err != nil || lift.V != 1 || lift.Action != "lift" {
		return errSignedPayload
	}
	return os.Remove(path)
}
