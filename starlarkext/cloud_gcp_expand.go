package starlarkext

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"cloud.google.com/go/pubsub"
	"go.starlark.net/starlark"
	"google.golang.org/api/container/v1"
)

// ExpandGCPAPI adds gke, pubsub, and run sub-namespaces to the existing gcp.* dict.
//
//	gcp.gke.list_clusters(project="", zone="")
//	gcp.gke.get_cluster(project="", zone="", name="")
//	gcp.pubsub.list_topics(project="")
//	gcp.pubsub.publish(project="", topic="", message="", attrs={})
//	gcp.pubsub.list_subscriptions(project="")
//	gcp.run.list_services(project="", region="")
//	gcp.run.get_service(project="", region="", name="")
func ExpandGCPAPI(env starlark.StringDict) {
	gcpVal, ok := env["gcp"]
	if !ok {
		return
	}
	gcpDict, ok := gcpVal.(*starlark.Dict)
	if !ok {
		return
	}

	gkeDict := starlark.NewDict(2)
	gkeDict.SetKey(starlark.String("list_clusters"), starlark.NewBuiltin("list_clusters", gcpGKEListClusters))
	gkeDict.SetKey(starlark.String("get_cluster"), starlark.NewBuiltin("get_cluster", gcpGKEGetCluster))
	gcpDict.SetKey(starlark.String("gke"), gkeDict)

	pubsubDict := starlark.NewDict(3)
	pubsubDict.SetKey(starlark.String("list_topics"), starlark.NewBuiltin("list_topics", gcpPubSubListTopics))
	pubsubDict.SetKey(starlark.String("publish"), starlark.NewBuiltin("publish", gcpPubSubPublish))
	pubsubDict.SetKey(starlark.String("list_subscriptions"), starlark.NewBuiltin("list_subscriptions", gcpPubSubListSubscriptions))
	gcpDict.SetKey(starlark.String("pubsub"), pubsubDict)

	runDict := starlark.NewDict(2)
	runDict.SetKey(starlark.String("list_services"), starlark.NewBuiltin("list_services", gcpRunListServices))
	runDict.SetKey(starlark.String("get_service"), starlark.NewBuiltin("get_service", gcpRunGetService))
	gcpDict.SetKey(starlark.String("run"), runDict)
}

// ── GKE ───────────────────────────────────────────────────────────────────────

func gcpGKEListClusters(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, zone string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project?", &project, "zone?", &zone); err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := container.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.gke: %v", err)
	}

	parent := fmt.Sprintf("projects/%s/locations/-", project)
	if zone != "" {
		parent = fmt.Sprintf("projects/%s/locations/%s", project, zone)
	}
	out, err := svc.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp.gke.list_clusters: %v", err)
	}

	var results []starlark.Value
	for _, c := range out.Clusters {
		nodeCount := int64(0)
		if c.CurrentNodeCount > 0 {
			nodeCount = c.CurrentNodeCount
		}
		results = append(results, makeDict(
			"name", c.Name,
			"location", c.Location,
			"status", c.Status,
			"nodeCount", nodeCount,
			"k8sVersion", c.CurrentMasterVersion,
		))
	}
	return starlark.NewList(results), nil
}

func gcpGKEGetCluster(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, zone, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project?", &project, "zone?", &zone, "name", &name); err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := container.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.gke: %v", err)
	}

	loc := zone
	if loc == "" {
		loc = "-"
	}
	resourceName := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, loc, name)
	c, err := svc.Projects.Locations.Clusters.Get(resourceName).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp.gke.get_cluster: %v", err)
	}

	nodeCount := int64(0)
	if c.CurrentNodeCount > 0 {
		nodeCount = c.CurrentNodeCount
	}
	return makeDict(
		"name", c.Name,
		"location", c.Location,
		"status", c.Status,
		"nodeCount", nodeCount,
		"k8sVersion", c.CurrentMasterVersion,
	), nil
}

// ── Pub/Sub ───────────────────────────────────────────────────────────────────

func gcpPubSubListTopics(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project?", &project); err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("gcp.pubsub: %v", err)
	}
	defer client.Close()

	var results []starlark.Value
	it := client.Topics(ctx)
	for {
		t, err := it.Next()
		if err != nil {
			// iterator.Done from the pubsub package signals end of iteration
			break
		}
		results = append(results, starlark.String(t.ID()))
	}
	return starlark.NewList(results), nil
}

func gcpPubSubPublish(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, topic, message string
	var attrsDict *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"project?", &project,
		"topic", &topic,
		"message", &message,
		"attrs?", &attrsDict,
	); err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("gcp.pubsub: %v", err)
	}
	defer client.Close()

	attrs := make(map[string]string)
	if attrsDict != nil {
		for _, kv := range attrsDict.Items() {
			k, _ := starlark.AsString(kv[0])
			v, _ := starlark.AsString(kv[1])
			attrs[k] = v
		}
	}

	t := client.Topic(topic)
	result := t.Publish(ctx, &pubsub.Message{
		Data:       []byte(message),
		Attributes: attrs,
	})
	msgID, err := result.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.pubsub.publish: %v", err)
	}
	return starlark.String(msgID), nil
}

func gcpPubSubListSubscriptions(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project?", &project); err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("gcp.pubsub: %v", err)
	}
	defer client.Close()

	var results []starlark.Value
	it := client.Subscriptions(ctx)
	for {
		s, err := it.Next()
		if err != nil {
			break
		}
		results = append(results, starlark.String(s.ID()))
	}
	return starlark.NewList(results), nil
}

// ── Cloud Run ─────────────────────────────────────────────────────────────────

// gcpRunListServices lists Cloud Run services via the REST API.
func gcpRunListServices(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project?", &project, "region?", &region); err != nil {
		return nil, err
	}
	if region == "" {
		region = "-"
	}
	url := fmt.Sprintf("https://run.googleapis.com/v2/projects/%s/locations/%s/services", project, region)
	body, err := gcpRunDoRequest(url)
	if err != nil {
		return nil, fmt.Errorf("gcp.run.list_services: %v", err)
	}

	var resp struct {
		Services []struct {
			Name          string `json:"name"`
			URI           string `json:"uri"`
			TerminalCondition struct {
				State string `json:"state"`
			} `json:"terminalCondition"`
		} `json:"services"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("gcp.run.list_services decode: %v", err)
	}

	var results []starlark.Value
	for _, svc := range resp.Services {
		results = append(results, makeDict(
			"name", svc.Name,
			"url", svc.URI,
			"status", svc.TerminalCondition.State,
		))
	}
	return starlark.NewList(results), nil
}

func gcpRunGetService(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, region, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project?", &project, "region?", &region, "name", &name); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://run.googleapis.com/v2/projects/%s/locations/%s/services/%s", project, region, name)
	body, err := gcpRunDoRequest(url)
	if err != nil {
		return nil, fmt.Errorf("gcp.run.get_service: %v", err)
	}

	var svc struct {
		Name          string `json:"name"`
		URI           string `json:"uri"`
		TerminalCondition struct {
			State string `json:"state"`
		} `json:"terminalCondition"`
	}
	if err := json.Unmarshal(body, &svc); err != nil {
		return nil, fmt.Errorf("gcp.run.get_service decode: %v", err)
	}
	return makeDict(
		"name", svc.Name,
		"url", svc.URI,
		"status", svc.TerminalCondition.State,
	), nil
}

// gcpRunDoRequest performs an authenticated GET to the Cloud Run v2 REST API.
// Uses Application Default Credentials via the metadata server or gcloud token.
func gcpRunDoRequest(url string) ([]byte, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Attempt to get ADC token via metadata server
	token, err := gcpGetADCToken(ctx)
	if err == nil && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// gcpGetADCToken fetches an access token from the GCE metadata server.
// Falls back gracefully if not on GCE (token will be empty).
func gcpGetADCToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		nil,
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

