package starlarkext

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"go.starlark.net/starlark"
)

// ExpandNotifyAPI adds the teams key to the existing notify.* dict.
//
// Starlark API:
//
//	notify.teams(webhook_url="", title="Alert", text="Something happened", color="0076D7")
//
// webhook_url falls back to TEAMS_WEBHOOK_URL env var if not provided.
func ExpandNotifyAPI(env starlark.StringDict) {
	notifyVal, ok := env["notify"]
	if !ok {
		return
	}
	notifyDict, ok := notifyVal.(*starlark.Dict)
	if !ok {
		return
	}
	_ = notifyDict.SetKey(starlark.String("teams"), starlark.NewBuiltin("teams", notifyTeams))
}

// ── Microsoft Teams ───────────────────────────────────────────────────────────

func notifyTeams(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var webhookURL, title, text, color string
	color = "0076D7"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"webhook_url?", &webhookURL,
		"title", &title,
		"text", &text,
		"color?", &color,
	); err != nil {
		return nil, err
	}

	if webhookURL == "" {
		webhookURL = os.Getenv("TEAMS_WEBHOOK_URL")
	}
	if webhookURL == "" {
		return nil, fmt.Errorf("notify.teams: no webhook_url provided and TEAMS_WEBHOOK_URL not set")
	}

	card := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": color,
		"summary":    title,
		"sections": []map[string]interface{}{
			{
				"activityTitle": title,
				"activityText":  text,
			},
		},
	}

	body, err := json.Marshal(card)
	if err != nil {
		return nil, fmt.Errorf("notify.teams: marshal: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("notify.teams: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notify.teams: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("notify.teams: HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return starlark.None, nil
}
