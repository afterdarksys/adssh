package starlarkext

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"go.starlark.net/starlark"
	"google.golang.org/api/container/v1"
	pubsubv1 "google.golang.org/api/pubsub/v1"
	runv2 "google.golang.org/api/run/v2"
)

// Threats: these builtins reach GKE, Pub/Sub, and Cloud Run with the caller's
// Application Default Credentials. Each one is a governed builtin, so the
// policy gate sees starlark.gcp.<svc>.<fn> with capability "cloud" and its
// arguments before any request is made. Project, location, and resource names
// are checked as single path segments so a crafted name cannot retarget the
// request at a resource the gate did not see. gke.describe never returns
// masterAuth (CA certificate, legacy client credentials). Publish and pull are
// bounded (10 MB payload, 100 attributes, 1000 messages); pull requires the
// ack keyword so the gate always sees whether it consumes. Errors go through
// cloudError so response bodies and headers are not echoed. Every call has a
// 30s deadline. In restricted sessions the gke, pubsub, and run namespaces are
// absent. This does not limit what the credentials themselves may do; that is
// IAM's job.

// ExpandGCPAPI adds gke, pubsub, and run sub-namespaces to the existing gcp.* dict.
// In restricted sessions it adds nothing.
//
//	gcp.gke.list_clusters(project, location="-")
//	gcp.gke.describe(project, location, name)
//	gcp.gke.get_cluster(project, location, name)        # alias of describe
//	gcp.pubsub.list_topics(project)
//	gcp.pubsub.list_subscriptions(project)
//	gcp.pubsub.publish(project, topic, data, attributes={})
//	gcp.pubsub.pull(project, subscription, max=10, ack=)   # ack keyword required
//	gcp.run.list_services(project, region)
//	gcp.run.get_service(project, region, name)
func ExpandGCPAPI(env starlark.StringDict, restricted bool) {
	if restricted {
		return
	}
	gcpDict, ok := env["gcp"].(*starlark.Dict)
	if !ok {
		return
	}

	gkeDict := starlark.NewDict(3)
	_ = gkeDict.SetKey(starlark.String("list_clusters"), starlark.NewBuiltin("list_clusters", gcpGKEListClusters))
	_ = gkeDict.SetKey(starlark.String("describe"), starlark.NewBuiltin("describe", gcpGKEDescribe))
	_ = gkeDict.SetKey(starlark.String("get_cluster"), starlark.NewBuiltin("get_cluster", gcpGKEDescribe))
	_ = gcpDict.SetKey(starlark.String("gke"), gkeDict)

	pubsubDict := starlark.NewDict(4)
	_ = pubsubDict.SetKey(starlark.String("list_topics"), starlark.NewBuiltin("list_topics", gcpPubSubListTopics))
	_ = pubsubDict.SetKey(starlark.String("list_subscriptions"), starlark.NewBuiltin("list_subscriptions", gcpPubSubListSubscriptions))
	_ = pubsubDict.SetKey(starlark.String("publish"), starlark.NewBuiltin("publish", gcpPubSubPublish))
	_ = pubsubDict.SetKey(starlark.String("pull"), starlark.NewBuiltin("pull", gcpPubSubPull))
	_ = gcpDict.SetKey(starlark.String("pubsub"), pubsubDict)

	runDict := starlark.NewDict(2)
	_ = runDict.SetKey(starlark.String("list_services"), starlark.NewBuiltin("list_services", gcpRunListServices))
	_ = runDict.SetKey(starlark.String("get_service"), starlark.NewBuiltin("get_service", gcpRunGetService))
	_ = gcpDict.SetKey(starlark.String("run"), runDict)
}

// ── Clients (swapped for fakes in tests) ─────────────────────────────────────

type gkeAPI interface {
	ListClusters(ctx context.Context, parent string) ([]*container.Cluster, error)
	GetCluster(ctx context.Context, name string) (*container.Cluster, error)
}

type pubsubAPI interface {
	ListTopics(ctx context.Context, project string, limit int) ([]string, error)
	ListSubscriptions(ctx context.Context, project string, limit int) ([]string, error)
	Publish(ctx context.Context, topic string, msg *pubsubv1.PubsubMessage) (string, error)
	Pull(ctx context.Context, subscription string, max int64) ([]*pubsubv1.ReceivedMessage, error)
	Acknowledge(ctx context.Context, subscription string, ackIDs []string) error
}

type runAPI interface {
	ListServices(ctx context.Context, parent string, limit int) ([]*runv2.GoogleCloudRunV2Service, error)
	GetService(ctx context.Context, name string) (*runv2.GoogleCloudRunV2Service, error)
}

var newGKEClient = func(ctx context.Context) (gkeAPI, error) {
	svc, err := container.NewService(ctx)
	if err != nil {
		return nil, err
	}
	return gkeREST{svc}, nil
}

var newPubSubClient = func(ctx context.Context) (pubsubAPI, error) {
	svc, err := pubsubv1.NewService(ctx)
	if err != nil {
		return nil, err
	}
	return pubsubREST{svc}, nil
}

var newRunClient = func(ctx context.Context) (runAPI, error) {
	svc, err := runv2.NewService(ctx)
	if err != nil {
		return nil, err
	}
	return runREST{svc}, nil
}

// gcpListLimit caps the items a list builtin collects across pages.
const gcpListLimit = 5000

var errGCPListLimit = fmt.Errorf("more than %d items", gcpListLimit)

type gkeREST struct{ svc *container.Service }

func (c gkeREST) ListClusters(ctx context.Context, parent string) ([]*container.Cluster, error) {
	out, err := c.svc.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return out.Clusters, nil
}

func (c gkeREST) GetCluster(ctx context.Context, name string) (*container.Cluster, error) {
	return c.svc.Projects.Locations.Clusters.Get(name).Context(ctx).Do()
}

type pubsubREST struct{ svc *pubsubv1.Service }

func (c pubsubREST) ListTopics(ctx context.Context, project string, limit int) ([]string, error) {
	var names []string
	err := c.svc.Projects.Topics.List("projects/"+project).Pages(ctx, func(page *pubsubv1.ListTopicsResponse) error {
		for _, t := range page.Topics {
			if len(names) >= limit {
				return errGCPListLimit
			}
			names = append(names, t.Name)
		}
		return nil
	})
	return names, err
}

func (c pubsubREST) ListSubscriptions(ctx context.Context, project string, limit int) ([]string, error) {
	var names []string
	err := c.svc.Projects.Subscriptions.List("projects/"+project).Pages(ctx, func(page *pubsubv1.ListSubscriptionsResponse) error {
		for _, s := range page.Subscriptions {
			if len(names) >= limit {
				return errGCPListLimit
			}
			names = append(names, s.Name)
		}
		return nil
	})
	return names, err
}

func (c pubsubREST) Publish(ctx context.Context, topic string, msg *pubsubv1.PubsubMessage) (string, error) {
	out, err := c.svc.Projects.Topics.Publish(topic, &pubsubv1.PublishRequest{Messages: []*pubsubv1.PubsubMessage{msg}}).Context(ctx).Do()
	if err != nil {
		return "", err
	}
	if len(out.MessageIds) != 1 {
		return "", fmt.Errorf("publish returned %d message ids, want 1", len(out.MessageIds))
	}
	return out.MessageIds[0], nil
}

func (c pubsubREST) Pull(ctx context.Context, subscription string, max int64) ([]*pubsubv1.ReceivedMessage, error) {
	out, err := c.svc.Projects.Subscriptions.Pull(subscription, &pubsubv1.PullRequest{MaxMessages: max}).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return out.ReceivedMessages, nil
}

func (c pubsubREST) Acknowledge(ctx context.Context, subscription string, ackIDs []string) error {
	_, err := c.svc.Projects.Subscriptions.Acknowledge(subscription, &pubsubv1.AcknowledgeRequest{AckIds: ackIDs}).Context(ctx).Do()
	return err
}

type runREST struct{ svc *runv2.Service }

func (c runREST) ListServices(ctx context.Context, parent string, limit int) ([]*runv2.GoogleCloudRunV2Service, error) {
	var out []*runv2.GoogleCloudRunV2Service
	err := c.svc.Projects.Locations.Services.List(parent).Pages(ctx, func(page *runv2.GoogleCloudRunV2ListServicesResponse) error {
		for _, s := range page.Services {
			if len(out) >= limit {
				return errGCPListLimit
			}
			out = append(out, s)
		}
		return nil
	})
	return out, err
}

func (c runREST) GetService(ctx context.Context, name string) (*runv2.GoogleCloudRunV2Service, error) {
	return c.svc.Projects.Locations.Services.Get(name).Context(ctx).Do()
}

// gcpSegments checks every name with validResourceSegment.
func gcpSegments(op string, pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if !validResourceSegment(pairs[i+1]) {
			return fmt.Errorf("%s: invalid %s %q", op, pairs[i], pairs[i+1])
		}
	}
	return nil
}

// lastSegment returns the part of a resource name after the final '/'.
func lastSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// ── GKE ───────────────────────────────────────────────────────────────────────

func gcpGKEListClusters(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "gcp.gke.list_clusters"
	project, location := "", "-"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "location?", &location); err != nil {
		return nil, err
	}
	if err := gcpSegments(op, "project", project, "location", location); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	client, err := newGKEClient(ctx)
	if err != nil {
		return nil, cloudError("gcp.gke", err)
	}
	clusters, err := client.ListClusters(ctx, fmt.Sprintf("projects/%s/locations/%s", project, location))
	if err != nil {
		return nil, cloudError(op, err)
	}
	results := make([]starlark.Value, 0, len(clusters))
	for _, c := range clusters {
		results = append(results, makeDict(
			"name", c.Name,
			"location", c.Location,
			"status", c.Status,
			"node_count", c.CurrentNodeCount,
			"version", c.CurrentMasterVersion,
		))
	}
	return starlark.NewList(results), nil
}

func gcpGKEDescribe(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	op := "gcp.gke." + b.Name()
	var project, location, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "location", &location, "name", &name); err != nil {
		return nil, err
	}
	if err := gcpSegments(op, "project", project, "location", location, "name", name); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	client, err := newGKEClient(ctx)
	if err != nil {
		return nil, cloudError("gcp.gke", err)
	}
	c, err := client.GetCluster(ctx, fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, location, name))
	if err != nil {
		return nil, cloudError(op, err)
	}
	pools := make([]string, 0, len(c.NodePools))
	for _, p := range c.NodePools {
		pools = append(pools, p.Name)
	}
	channel := ""
	if c.ReleaseChannel != nil {
		channel = c.ReleaseChannel.Channel
	}
	labels := map[string]string{}
	for k, v := range c.ResourceLabels {
		labels[k] = v
	}
	// masterAuth is deliberately left out: it holds the cluster CA and, on
	// legacy clusters, client credentials.
	return makeDict(
		"name", c.Name,
		"location", c.Location,
		"status", c.Status,
		"status_message", c.StatusMessage,
		"node_count", c.CurrentNodeCount,
		"version", c.CurrentMasterVersion,
		"endpoint", c.Endpoint,
		"network", c.Network,
		"subnetwork", c.Subnetwork,
		"create_time", c.CreateTime,
		"release_channel", channel,
		"node_pools", pools,
		"labels", labels,
		"autopilot", c.Autopilot != nil && c.Autopilot.Enabled,
		"private", c.PrivateClusterConfig != nil && c.PrivateClusterConfig.EnablePrivateNodes,
	), nil
}

// ── Pub/Sub ───────────────────────────────────────────────────────────────────

const (
	pubsubMaxData       = 10 << 20 // Pub/Sub request limit
	pubsubMaxAttributes = 100
	pubsubMaxPull       = 1000
)

func gcpPubSubListTopics(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return gcpPubSubList(b, args, kwargs, "gcp.pubsub.list_topics", func(ctx context.Context, c pubsubAPI, project string) ([]string, error) {
		return c.ListTopics(ctx, project, gcpListLimit)
	})
}

func gcpPubSubListSubscriptions(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return gcpPubSubList(b, args, kwargs, "gcp.pubsub.list_subscriptions", func(ctx context.Context, c pubsubAPI, project string) ([]string, error) {
		return c.ListSubscriptions(ctx, project, gcpListLimit)
	})
}

func gcpPubSubList(b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple, op string, list func(context.Context, pubsubAPI, string) ([]string, error)) (starlark.Value, error) {
	var project string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project); err != nil {
		return nil, err
	}
	if err := gcpSegments(op, "project", project); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	client, err := newPubSubClient(ctx)
	if err != nil {
		return nil, cloudError("gcp.pubsub", err)
	}
	names, err := list(ctx, client, project)
	if err != nil {
		return nil, cloudError(op, err)
	}
	results := make([]starlark.Value, 0, len(names))
	for _, n := range names {
		results = append(results, starlark.String(lastSegment(n)))
	}
	return starlark.NewList(results), nil
}

func gcpPubSubPublish(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "gcp.pubsub.publish"
	var project, topic string
	var data starlark.Value
	var attrsDict *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"project", &project, "topic", &topic, "data", &data, "attributes?", &attrsDict); err != nil {
		return nil, err
	}
	if err := gcpSegments(op, "project", project, "topic", topic); err != nil {
		return nil, err
	}
	var payload []byte
	switch d := data.(type) {
	case starlark.String:
		payload = []byte(string(d))
	case starlark.Bytes:
		payload = []byte(string(d))
	default:
		return nil, fmt.Errorf("%s: data must be a string or bytes, got %s", op, data.Type())
	}
	if len(payload) > pubsubMaxData {
		return nil, fmt.Errorf("%s: data is %d bytes, limit is %d", op, len(payload), pubsubMaxData)
	}
	attrs := map[string]string{}
	if attrsDict != nil {
		if attrsDict.Len() > pubsubMaxAttributes {
			return nil, fmt.Errorf("%s: %d attributes, limit is %d", op, attrsDict.Len(), pubsubMaxAttributes)
		}
		for _, kv := range attrsDict.Items() {
			k, kok := starlark.AsString(kv[0])
			v, vok := starlark.AsString(kv[1])
			if !kok || !vok || k == "" {
				return nil, fmt.Errorf("%s: attributes must map non-empty strings to strings", op)
			}
			attrs[k] = v
		}
	}
	if len(payload) == 0 && len(attrs) == 0 {
		return nil, fmt.Errorf("%s: a message needs data or at least one attribute", op)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	client, err := newPubSubClient(ctx)
	if err != nil {
		return nil, cloudError("gcp.pubsub", err)
	}
	msg := &pubsubv1.PubsubMessage{Data: base64.StdEncoding.EncodeToString(payload)}
	if len(attrs) > 0 {
		msg.Attributes = attrs
	}
	id, err := client.Publish(ctx, fmt.Sprintf("projects/%s/topics/%s", project, topic), msg)
	if err != nil {
		return nil, cloudError(op, err)
	}
	return starlark.String(id), nil
}

func gcpPubSubPull(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "gcp.pubsub.pull"
	// ack decides whether the pull consumes messages, so a policy must be
	// able to match it. The gate sees only the arguments as written, so ack
	// is a required keyword: every call reaches the gate with "ack"=True or
	// "ack"=False.
	if len(args) > 3 || !hasKeyword(kwargs, "ack") {
		return nil, fmt.Errorf("%s: pass ack=True or ack=False as a keyword so policy can match on it", op)
	}
	var project, subscription string
	max := 10
	var ack bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"project", &project, "subscription", &subscription, "max?", &max, "ack?", &ack); err != nil {
		return nil, err
	}
	if err := gcpSegments(op, "project", project, "subscription", subscription); err != nil {
		return nil, err
	}
	if max < 1 || max > pubsubMaxPull {
		return nil, fmt.Errorf("%s: max must be between 1 and %d", op, pubsubMaxPull)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	client, err := newPubSubClient(ctx)
	if err != nil {
		return nil, cloudError("gcp.pubsub", err)
	}
	subPath := fmt.Sprintf("projects/%s/subscriptions/%s", project, subscription)
	received, err := client.Pull(ctx, subPath, int64(max))
	if err != nil {
		return nil, cloudError(op, err)
	}
	if len(received) > max {
		received = received[:max]
	}
	results := make([]starlark.Value, 0, len(received))
	ackIDs := make([]string, 0, len(received))
	for _, rm := range received {
		if rm == nil || rm.Message == nil {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(rm.Message.Data)
		if err != nil {
			return nil, fmt.Errorf("%s: message %s has undecodable data", op, rm.Message.MessageId)
		}
		attrs := map[string]string{}
		for k, v := range rm.Message.Attributes {
			attrs[k] = v
		}
		results = append(results, makeDict(
			"id", rm.Message.MessageId,
			"data", string(data),
			"attributes", attrs,
			"publish_time", rm.Message.PublishTime,
			"ack_id", rm.AckId,
		))
		if rm.AckId != "" {
			ackIDs = append(ackIDs, rm.AckId)
		}
	}
	if ack && len(ackIDs) > 0 {
		if err := client.Acknowledge(ctx, subPath, ackIDs); err != nil {
			// Fail closed: the messages were not acked and will be redelivered.
			return nil, cloudError(op+" ack", err)
		}
	}
	return starlark.NewList(results), nil
}

func hasKeyword(kwargs []starlark.Tuple, name string) bool {
	for _, kw := range kwargs {
		if k, ok := starlark.AsString(kw[0]); ok && k == name {
			return true
		}
	}
	return false
}

// ── Cloud Run ─────────────────────────────────────────────────────────────────

func gcpRunServiceDict(s *runv2.GoogleCloudRunV2Service) *starlark.Dict {
	status := ""
	if s.TerminalCondition != nil {
		status = s.TerminalCondition.State
	}
	urls := append([]string(nil), s.Urls...)
	sort.Strings(urls)
	return makeDict(
		"name", lastSegment(s.Name),
		"url", s.Uri,
		"urls", urls,
		"status", status,
		"latest_ready_revision", lastSegment(s.LatestReadyRevision),
		"ingress", s.Ingress,
		"update_time", s.UpdateTime,
	)
}

func gcpRunListServices(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "gcp.run.list_services"
	var project, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "region", &region); err != nil {
		return nil, err
	}
	if err := gcpSegments(op, "project", project, "region", region); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	client, err := newRunClient(ctx)
	if err != nil {
		return nil, cloudError("gcp.run", err)
	}
	services, err := client.ListServices(ctx, fmt.Sprintf("projects/%s/locations/%s", project, region), gcpListLimit)
	if err != nil {
		return nil, cloudError(op, err)
	}
	results := make([]starlark.Value, 0, len(services))
	for _, s := range services {
		results = append(results, gcpRunServiceDict(s))
	}
	return starlark.NewList(results), nil
}

func gcpRunGetService(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "gcp.run.get_service"
	var project, region, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "region", &region, "name", &name); err != nil {
		return nil, err
	}
	if err := gcpSegments(op, "project", project, "region", region, "name", name); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	client, err := newRunClient(ctx)
	if err != nil {
		return nil, cloudError("gcp.run", err)
	}
	s, err := client.GetService(ctx, fmt.Sprintf("projects/%s/locations/%s/services/%s", project, region, name))
	if err != nil {
		return nil, cloudError(op, err)
	}
	return gcpRunServiceDict(s), nil
}
