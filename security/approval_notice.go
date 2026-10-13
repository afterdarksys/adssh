package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Threats: an approval notice tells an operator that a command is waiting or
// was denied. It carries a fingerprint, not the approval token and not the
// command arguments. The webhook URL and the link base are operator-supplied
// and are rejected by validateCallbackURL before a dial. A webhook error does
// not authorize the command. The pending approval file remains the authorization.

type approvalNotice struct {
	Event            string `json:"event"`
	Kind             string `json:"kind"`
	Command          string `json:"command"`
	RequiredApprover string `json:"required_approver"`
	Fingerprint      string `json:"fingerprint"`
	ApprovalLink     string `json:"approval_link,omitempty"`
}

var approvalFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func sendApprovalNotice(notice approvalNotice) error {
	webhook := os.Getenv("ADSSH_4EYES_WEBHOOK")
	if webhook == "" {
		return nil
	}
	parsed, err := validateCallbackURL(webhook)
	if err != nil {
		return err
	}
	if base := os.Getenv("ADSSH_APPROVAL_LINK_BASE"); base != "" {
		if link, err := approvalLink(base, notice.Fingerprint); err == nil {
			notice.ApprovalLink = link
		}
	}
	body, err := json.Marshal(notice)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := callbackHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("approval notice status %d", resp.StatusCode)
	}
	return nil
}

func approvalLink(base, fingerprint string) (string, error) {
	if !approvalFingerprintPattern.MatchString(fingerprint) {
		return "", fmt.Errorf("url_rejected")
	}
	parsed, err := validateCallbackURL(base)
	if err != nil {
		return "", err
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/approvals/" + fingerprint
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
