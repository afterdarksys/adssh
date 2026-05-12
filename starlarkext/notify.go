package starlarkext

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/slack-go/slack"
	"go.starlark.net/starlark"
)

// SetupNotifyAPI registers the notify.* namespace into the Starlark environment.
//
// Starlark API:
//
//	# Slack — token from SLACK_TOKEN env if not provided
//	notify.slack(channel="#ops", text="Deploy complete")
//	notify.slack(channel="#ops", text="Alert!", token="xoxb-...")
//
//	# Generic webhook (payload is a Starlark dict, serialized to JSON)
//	result = notify.webhook(url="https://...", payload={"key":"val"}, method="POST", headers={})
//	# result is {"status": 200, "body": "..."}
//
//	# PagerDuty Events API v2 (routing_key from PAGERDUTY_ROUTING_KEY env if not provided)
//	dedup_key = notify.pagerduty(summary="DB lag exceeded 30s", severity="error", source="adssh")
//	dedup_key = notify.pagerduty(summary="...", severity="warning", routing_key="...")
func SetupNotifyAPI(env starlark.StringDict) {
	d := starlark.NewDict(3)
	d.SetKey(starlark.String("slack"), starlark.NewBuiltin("slack", notifySlack))
	d.SetKey(starlark.String("webhook"), starlark.NewBuiltin("webhook", notifyWebhook))
	d.SetKey(starlark.String("pagerduty"), starlark.NewBuiltin("pagerduty", notifyPagerDuty))
	env["notify"] = d
}

// ── Slack ─────────────────────────────────────────────────────────────────────

func notifySlack(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var channel, text, token string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "channel", &channel, "text", &text, "token?", &token); err != nil {
		return nil, err
	}
	if token == "" {
		token = os.Getenv("SLACK_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("notify.slack: no token provided and SLACK_TOKEN not set")
	}
	api := slack.New(token)
	_, _, err := api.PostMessageContext(context.Background(), channel, slack.MsgOptionText(text, false))
	if err != nil {
		return nil, fmt.Errorf("notify.slack: %v", err)
	}
	return starlark.None, nil
}

// ── Webhook ───────────────────────────────────────────────────────────────────

func notifyWebhook(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url, method string
	var payload *starlark.Dict
	var headers *starlark.Dict
	method = "POST"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"url", &url, "payload?", &payload, "method?", &method, "headers?", &headers); err != nil {
		return nil, err
	}

	var body []byte
	if payload != nil {
		goPayload := starlarkDictToGo(payload)
		var err error
		body, err = json.Marshal(goPayload)
		if err != nil {
			return nil, fmt.Errorf("notify.webhook: marshal: %v", err)
		}
	}

	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("notify.webhook: %v", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if headers != nil {
		for _, kv := range headers.Items() {
			k, _ := starlark.AsString(kv[0])
			v, _ := starlark.AsString(kv[1])
			req.Header.Set(k, v)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notify.webhook: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return makeDict("status", int64(resp.StatusCode), "body", string(respBody)), nil
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

func notifyPagerDuty(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var routingKey, summary, severity, source, component, group string
	severity = "error"
	source = "adssh"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"summary", &summary,
		"severity?", &severity,
		"routing_key?", &routingKey,
		"source?", &source,
		"component?", &component,
		"group?", &group,
	); err != nil {
		return nil, err
	}
	if routingKey == "" {
		routingKey = os.Getenv("PAGERDUTY_ROUTING_KEY")
	}
	if routingKey == "" {
		return nil, fmt.Errorf("notify.pagerduty: no routing_key provided and PAGERDUTY_ROUTING_KEY not set")
	}

	pdPayload := map[string]interface{}{
		"summary":  summary,
		"severity": severity,
		"source":   source,
	}
	if component != "" {
		pdPayload["component"] = component
	}
	if group != "" {
		pdPayload["group"] = group
	}
	event := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"payload":      pdPayload,
	}
	body, _ := json.Marshal(event)

	req, err := http.NewRequestWithContext(
		context.Background(), "POST",
		"https://events.pagerduty.com/v2/enqueue",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("notify.pagerduty: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notify.pagerduty: %v", err)
	}
	defer resp.Body.Close()
	var result struct {
		Status   string `json:"status"`
		DedupKey string `json:"dedup_key"`
		Message  string `json:"message"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("notify.pagerduty: %s: %s", result.Status, result.Message)
	}
	return starlark.String(result.DedupKey), nil
}
