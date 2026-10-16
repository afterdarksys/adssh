package starlarkext

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/security"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"go.starlark.net/starlark"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	pubsubv1 "google.golang.org/api/pubsub/v1"
	runv2 "google.golang.org/api/run/v2"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

// clientCalls counts every fake factory and method invocation so the gate
// tests can prove no SDK client was built or used.
type clientCalls struct{ n int }

type fakeGKE struct {
	calls    *clientCalls
	clusters []*container.Cluster
	cluster  *container.Cluster
	err      error
	got      string
}

func (f *fakeGKE) ListClusters(_ context.Context, parent string) ([]*container.Cluster, error) {
	f.calls.n++
	f.got = parent
	return f.clusters, f.err
}

func (f *fakeGKE) GetCluster(_ context.Context, name string) (*container.Cluster, error) {
	f.calls.n++
	f.got = name
	return f.cluster, f.err
}

type fakePubSub struct {
	calls     *clientCalls
	topics    []string
	subs      []string
	published *pubsubv1.PubsubMessage
	topic     string
	received  []*pubsubv1.ReceivedMessage
	pullMax   int64
	pullSub   string
	acked     []string
	ackErr    error
	err       error
}

func (f *fakePubSub) ListTopics(_ context.Context, project string, _ int) ([]string, error) {
	f.calls.n++
	return f.topics, f.err
}

func (f *fakePubSub) ListSubscriptions(_ context.Context, project string, _ int) ([]string, error) {
	f.calls.n++
	return f.subs, f.err
}

func (f *fakePubSub) Publish(_ context.Context, topic string, msg *pubsubv1.PubsubMessage) (string, error) {
	f.calls.n++
	f.topic, f.published = topic, msg
	return "msg-1", f.err
}

func (f *fakePubSub) Pull(_ context.Context, sub string, max int64) ([]*pubsubv1.ReceivedMessage, error) {
	f.calls.n++
	f.pullSub, f.pullMax = sub, max
	return f.received, f.err
}

func (f *fakePubSub) Acknowledge(_ context.Context, _ string, ids []string) error {
	f.calls.n++
	f.acked = append(f.acked, ids...)
	return f.ackErr
}

type fakeRun struct {
	calls    *clientCalls
	services []*runv2.GoogleCloudRunV2Service
	got      string
	err      error
}

func (f *fakeRun) ListServices(_ context.Context, parent string, _ int) ([]*runv2.GoogleCloudRunV2Service, error) {
	f.calls.n++
	f.got = parent
	return f.services, f.err
}

func (f *fakeRun) GetService(_ context.Context, name string) (*runv2.GoogleCloudRunV2Service, error) {
	f.calls.n++
	f.got = name
	if len(f.services) == 0 {
		return nil, f.err
	}
	return f.services[0], f.err
}

type fakeCW struct {
	calls   *clientCalls
	getIn   *cloudwatch.GetMetricStatisticsInput
	points  []cwtypes.Datapoint
	pages   []*cloudwatch.ListMetricsOutput
	listIns []*cloudwatch.ListMetricsInput
	err     error
}

func (f *fakeCW) GetMetricStatistics(_ context.Context, in *cloudwatch.GetMetricStatisticsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	f.calls.n++
	f.getIn = in
	if f.err != nil {
		return nil, f.err
	}
	return &cloudwatch.GetMetricStatisticsOutput{Datapoints: f.points}, nil
}

func (f *fakeCW) ListMetrics(_ context.Context, in *cloudwatch.ListMetricsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error) {
	f.calls.n++
	cp := *in
	f.listIns = append(f.listIns, &cp)
	if f.err != nil {
		return nil, f.err
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

type fakeR53 struct {
	calls     *clientCalls
	zonePages []*route53.ListHostedZonesOutput
	recPages  []*route53.ListResourceRecordSetsOutput
	recIns    []*route53.ListResourceRecordSetsInput
	change    *route53.ChangeResourceRecordSetsInput
	err       error
}

func (f *fakeR53) ListHostedZones(_ context.Context, _ *route53.ListHostedZonesInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	f.calls.n++
	if f.err != nil {
		return nil, f.err
	}
	page := f.zonePages[0]
	f.zonePages = f.zonePages[1:]
	return page, nil
}

func (f *fakeR53) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	f.calls.n++
	cp := *in
	f.recIns = append(f.recIns, &cp)
	if f.err != nil {
		return nil, f.err
	}
	page := f.recPages[0]
	f.recPages = f.recPages[1:]
	return page, nil
}

func (f *fakeR53) ChangeResourceRecordSets(_ context.Context, in *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	f.calls.n++
	f.change = in
	if f.err != nil {
		return nil, f.err
	}
	return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: &r53types.ChangeInfo{
		Id: aws.String("/change/C123"), Status: r53types.ChangeStatusPending,
	}}, nil
}

type cloudFakes struct {
	calls  *clientCalls
	gke    *fakeGKE
	pubsub *fakePubSub
	run    *fakeRun
	cw     *fakeCW
	r53    *fakeR53
	region string
}

// installCloudFakes swaps every cloud-gap client factory for a fake and
// restores the real ones when the test ends.
func installCloudFakes(t *testing.T) *cloudFakes {
	t.Helper()
	calls := &clientCalls{}
	f := &cloudFakes{
		calls:  calls,
		gke:    &fakeGKE{calls: calls},
		pubsub: &fakePubSub{calls: calls},
		run:    &fakeRun{calls: calls},
		cw:     &fakeCW{calls: calls},
		r53:    &fakeR53{calls: calls},
	}
	oldGKE, oldPS, oldRun, oldCW, oldR53 := newGKEClient, newPubSubClient, newRunClient, newCloudWatchClient, newRoute53Client
	newGKEClient = func(context.Context) (gkeAPI, error) { calls.n++; return f.gke, nil }
	newPubSubClient = func(context.Context) (pubsubAPI, error) { calls.n++; return f.pubsub, nil }
	newRunClient = func(context.Context) (runAPI, error) { calls.n++; return f.run, nil }
	newCloudWatchClient = func(region string) (cloudWatchAPI, error) { calls.n++; f.region = region; return f.cw, nil }
	newRoute53Client = func() (route53API, error) { calls.n++; return f.r53, nil }
	t.Cleanup(func() {
		newGKEClient, newPubSubClient, newRunClient, newCloudWatchClient, newRoute53Client = oldGKE, oldPS, oldRun, oldCW, oldR53
	})
	return f
}

const allowAllPolicy = `
package adssh.authz
default allow = true
`

// cloudEnv builds a governed session whose engine runs policy.
func cloudEnv(t *testing.T, policy string, restricted bool) starlark.StringDict {
	t.Helper()
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(policy)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	env := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: env, Restricted: restricted, Engine: eng})
	GovernStarlarkGlobalsInPlace(eng, env)
	return env
}

func evalCloud(t *testing.T, env starlark.StringDict, expr string) (starlark.Value, error) {
	t.Helper()
	return starlark.Eval(&starlark.Thread{Name: "cloud-test"}, "<test>", expr, env)
}

func mustEvalCloud(t *testing.T, expr string) starlark.Value {
	t.Helper()
	v, err := evalCloud(t, cloudEnv(t, allowAllPolicy, false), expr)
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	return v
}

func dictGet(t *testing.T, v starlark.Value, key string) starlark.Value {
	t.Helper()
	m, ok := v.(starlark.Mapping)
	if !ok {
		t.Fatalf("%v is %T, want a mapping", v, v)
	}
	got, found, err := m.Get(starlark.String(key))
	if err != nil || !found {
		t.Fatalf("key %q missing from %v", key, v)
	}
	return got
}

func listLen(t *testing.T, v starlark.Value) int {
	t.Helper()
	l, ok := v.(*starlark.List)
	if !ok {
		t.Fatalf("%v is %T, want list", v, v)
	}
	return l.Len()
}

// ── the gate is consulted before any client is built ─────────────────────────

func TestCloudGapsGateDeniesBeforeCall(t *testing.T) {
	cases := []struct{ command, expr string }{
		{"starlark.gcp.gke.list_clusters", `gcp["gke"]["list_clusters"]("p")`},
		{"starlark.gcp.gke.describe", `gcp["gke"]["describe"]("p", "us-central1", "c1")`},
		{"starlark.gcp.pubsub.list_topics", `gcp["pubsub"]["list_topics"]("p")`},
		{"starlark.gcp.pubsub.publish", `gcp["pubsub"]["publish"]("p", "t", "hello")`},
		{"starlark.gcp.pubsub.pull", `gcp["pubsub"]["pull"]("p", "s", ack=True)`},
		{"starlark.gcp.run.list_services", `gcp["run"]["list_services"]("p", "us-central1")`},
		{"starlark.aws.cloudwatch.get_metric", `aws["cloudwatch"]["get_metric"]("AWS/EC2", "CPUUtilization", {})`},
		{"starlark.aws.cloudwatch.list_metrics", `aws["cloudwatch"]["list_metrics"]("AWS/EC2")`},
		{"starlark.aws.route53.list_zones", `aws["route53"]["list_zones"]()`},
		{"starlark.aws.route53.list_records", `aws["route53"]["list_records"]("Z123")`},
		{"starlark.aws.route53.upsert_record", `aws["route53"]["upsert_record"](zone_id="Z123", name="www.example.com.", type="A", values=["192.0.2.1"])`},
		{"starlark.notify.teams", `notify["teams"]("https://example.webhook.office.com/x", "t", "x")`},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			fakes := installCloudFakes(t)
			teamsPosts := installTeamsFake(t)
			policy := fmt.Sprintf(`
package adssh.authz
default allow = true
allow = false { input.command == %q }
deny_reason = "denied by test" { input.command == %q }
`, tc.command, tc.command)
			_, err := evalCloud(t, cloudEnv(t, policy, false), tc.expr)
			if err == nil || !strings.Contains(err.Error(), "denied by test") {
				t.Fatalf("err = %v, want policy denial", err)
			}
			if fakes.calls.n != 0 || *teamsPosts != 0 {
				t.Fatalf("client used %d times, teams posted %d times; want 0 after a deny", fakes.calls.n, *teamsPosts)
			}
		})
	}
}

// A policy can deny DNS changes by capability while cloud reads still run.
func TestRoute53UpsertDeniedByDNSCapability(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.r53.zonePages = []*route53.ListHostedZonesOutput{{}}
	env := cloudEnv(t, `
package adssh.authz
default allow = true
allow = false { input.capabilities[_] == "dns" }
deny_reason = "dns changes denied" { input.capabilities[_] == "dns" }
`, false)
	if _, err := evalCloud(t, env, `aws["route53"]["list_zones"]()`); err != nil {
		t.Fatalf("list_zones under a dns-only deny: %v", err)
	}
	before := fakes.calls.n
	_, err := evalCloud(t, env, `aws["route53"]["upsert_record"](zone_id="Z1", name="a.example.com.", type="A", values=["192.0.2.1"])`)
	if err == nil || !strings.Contains(err.Error(), "dns changes denied") {
		t.Fatalf("err = %v, want dns denial", err)
	}
	if fakes.calls.n != before {
		t.Fatal("route53 client used after a dns denial")
	}
}

// The record name reaches the gate as the keyword argument "name"="<record>"
// (govern.go quotes both sides) so policy can match on it.
func TestRoute53UpsertPolicyMatchesRecordName(t *testing.T) {
	fakes := installCloudFakes(t)
	env := cloudEnv(t, `
package adssh.authz
import future.keywords.in
default allow = true
allow = false { "\"name\"=\"prod.example.com.\"" in input.args }
deny_reason = "prod record is protected" { "\"name\"=\"prod.example.com.\"" in input.args }
`, false)
	_, err := evalCloud(t, env, `aws["route53"]["upsert_record"](values=["192.0.2.9"], type="A", name="prod.example.com.", zone_id="Z1")`)
	if err == nil || !strings.Contains(err.Error(), "prod record is protected") {
		t.Fatalf("err = %v, want name-matched denial", err)
	}
	if fakes.calls.n != 0 {
		t.Fatal("route53 client used after a name-matched denial")
	}
	if _, err := evalCloud(t, env, `aws["route53"]["upsert_record"](zone_id="Z1", name="dev.example.com.", type="A", values=["192.0.2.9"])`); err != nil {
		t.Fatalf("other record: %v", err)
	}
}

func TestRoute53UpsertRefusesPositionalArgs(t *testing.T) {
	fakes := installCloudFakes(t)
	_, err := evalCloud(t, cloudEnv(t, allowAllPolicy, false), `aws["route53"]["upsert_record"]("Z1", "a.example.com.", "A", ["192.0.2.1"])`)
	if err == nil || !strings.Contains(err.Error(), "keyword arguments only") {
		t.Fatalf("err = %v, want keyword-only refusal", err)
	}
	if fakes.calls.n != 0 {
		t.Fatal("client used for a refused call")
	}
}

func TestCloudGapsAbsentWhenRestricted(t *testing.T) {
	env := cloudEnv(t, allowAllPolicy, true)
	for _, expr := range []string{
		`"gke" in gcp`, `"pubsub" in gcp`, `"run" in gcp`,
		`"cloudwatch" in aws`, `"route53" in aws`, `"teams" in notify`,
	} {
		v, err := evalCloud(t, env, expr)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if v != starlark.False {
			t.Fatalf("%s = %v in a restricted session, want False", expr, v)
		}
	}
	open := cloudEnv(t, allowAllPolicy, false)
	if v, err := evalCloud(t, open, `"route53" in aws and "gke" in gcp and "teams" in notify`); err != nil || v != starlark.True {
		t.Fatalf("unrestricted session = (%v, %v), want True", v, err)
	}
}

// ── GKE ───────────────────────────────────────────────────────────────────────

func TestGKEListClusters(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.gke.clusters = []*container.Cluster{{Name: "c1", Location: "us-central1", Status: "RUNNING", CurrentNodeCount: 3, CurrentMasterVersion: "1.30"}}
	v := mustEvalCloud(t, `gcp["gke"]["list_clusters"]("proj")`)
	if fakes.gke.got != "projects/proj/locations/-" {
		t.Fatalf("parent = %q, want all locations", fakes.gke.got)
	}
	if listLen(t, v) != 1 {
		t.Fatalf("got %v", v)
	}
	c := v.(*starlark.List).Index(0)
	if dictGet(t, c, "name") != starlark.String("c1") || dictGet(t, c, "node_count") != starlark.MakeInt(3) {
		t.Fatalf("cluster = %v", c)
	}
	mustEvalCloud(t, `gcp["gke"]["list_clusters"]("proj", location="europe-west1-b")`)
	if fakes.gke.got != "projects/proj/locations/europe-west1-b" {
		t.Fatalf("parent = %q", fakes.gke.got)
	}
}

func TestGKEDescribeOmitsMasterAuth(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.gke.cluster = &container.Cluster{
		Name: "c1", Location: "us-central1", Status: "RUNNING", Endpoint: "203.0.113.5",
		MasterAuth:     &container.MasterAuth{ClusterCaCertificate: "SECRET-CA", ClientKey: "SECRET-KEY"},
		NodePools:      []*container.NodePool{{Name: "pool-a"}},
		ReleaseChannel: &container.ReleaseChannel{Channel: "REGULAR"},
		Autopilot:      &container.Autopilot{Enabled: true},
	}
	v := mustEvalCloud(t, `gcp["gke"]["describe"]("proj", "us-central1", "c1")`)
	if fakes.gke.got != "projects/proj/locations/us-central1/clusters/c1" {
		t.Fatalf("name = %q", fakes.gke.got)
	}
	if strings.Contains(v.String(), "SECRET") {
		t.Fatalf("describe leaked masterAuth: %v", v)
	}
	if dictGet(t, v, "autopilot") != starlark.True || dictGet(t, v, "release_channel") != starlark.String("REGULAR") {
		t.Fatalf("describe = %v", v)
	}
}

func TestGCPRejectsPathInjection(t *testing.T) {
	fakes := installCloudFakes(t)
	env := cloudEnv(t, allowAllPolicy, false)
	for _, expr := range []string{
		`gcp["gke"]["describe"]("proj", "us-central1", "c1/../../other")`,
		`gcp["gke"]["list_clusters"]("proj?x=1")`,
		`gcp["pubsub"]["publish"]("proj", "t/../../x", "d")`,
		`gcp["pubsub"]["pull"]("proj", "..", ack=True)`,
		`gcp["run"]["list_services"]("", "us-central1")`,
		`gcp["run"]["list_services"]("proj", "us central1")`,
	} {
		if _, err := evalCloud(t, env, expr); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("%s: err = %v, want invalid name", expr, err)
		}
	}
	if fakes.calls.n != 0 {
		t.Fatalf("client used %d times for rejected names", fakes.calls.n)
	}
}

func TestGCPErrorDropsBodyAndHeaders(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.gke.err = &googleapi.Error{Code: 403, Message: "permission denied", Body: "SECRET-BODY", Header: map[string][]string{"X-Secret": {"SECRET-HDR"}}}
	_, err := evalCloud(t, cloudEnv(t, allowAllPolicy, false), `gcp["gke"]["list_clusters"]("proj")`)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403: permission denied") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
}

// ── Pub/Sub ───────────────────────────────────────────────────────────────────

func TestPubSubListTopics(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.pubsub.topics = []string{"projects/p/topics/alpha", "projects/p/topics/beta"}
	v := mustEvalCloud(t, `gcp["pubsub"]["list_topics"]("p")`)
	if v.String() != `["alpha", "beta"]` {
		t.Fatalf("topics = %v", v)
	}
}

func TestPubSubPublish(t *testing.T) {
	fakes := installCloudFakes(t)
	v := mustEvalCloud(t, `gcp["pubsub"]["publish"]("p", "events", "hello", attributes={"k": "v"})`)
	if v != starlark.String("msg-1") || fakes.pubsub.topic != "projects/p/topics/events" {
		t.Fatalf("publish = %v topic %q", v, fakes.pubsub.topic)
	}
	if fakes.pubsub.published.Data != base64.StdEncoding.EncodeToString([]byte("hello")) || fakes.pubsub.published.Attributes["k"] != "v" {
		t.Fatalf("message = %+v", fakes.pubsub.published)
	}
}

func TestPubSubPublishRejectsBadInput(t *testing.T) {
	fakes := installCloudFakes(t)
	env := cloudEnv(t, allowAllPolicy, false)
	big := strings.Repeat("x", pubsubMaxData+1)
	env["BIG"] = starlark.String(big)
	for expr, want := range map[string]string{
		`gcp["pubsub"]["publish"]("p", "t", BIG)`:                      "limit",
		`gcp["pubsub"]["publish"]("p", "t", 5)`:                        "string or bytes",
		`gcp["pubsub"]["publish"]("p", "t", "d", attributes={"k": 1})`: "attributes",
		`gcp["pubsub"]["publish"]("p", "t", "")`:                       "data or at least one attribute",
	} {
		if _, err := evalCloud(t, env, expr); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", expr, err, want)
		}
	}
	if fakes.calls.n != 0 {
		t.Fatalf("client used %d times for rejected publishes", fakes.calls.n)
	}
}

func TestPubSubPullAcks(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.pubsub.received = []*pubsubv1.ReceivedMessage{
		{AckId: "a1", Message: &pubsubv1.PubsubMessage{MessageId: "m1", Data: base64.StdEncoding.EncodeToString([]byte("one")), Attributes: map[string]string{"x": "y"}}},
		{AckId: "a2", Message: &pubsubv1.PubsubMessage{MessageId: "m2", Data: base64.StdEncoding.EncodeToString([]byte("two"))}},
	}
	v := mustEvalCloud(t, `gcp["pubsub"]["pull"]("p", "sub", max=5, ack=True)`)
	if fakes.pubsub.pullSub != "projects/p/subscriptions/sub" || fakes.pubsub.pullMax != 5 {
		t.Fatalf("pull = %q max %d", fakes.pubsub.pullSub, fakes.pubsub.pullMax)
	}
	if listLen(t, v) != 2 || dictGet(t, v.(*starlark.List).Index(0), "data") != starlark.String("one") {
		t.Fatalf("messages = %v", v)
	}
	if strings.Join(fakes.pubsub.acked, ",") != "a1,a2" {
		t.Fatalf("acked = %v", fakes.pubsub.acked)
	}
}

func TestPubSubPullNoAck(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.pubsub.received = []*pubsubv1.ReceivedMessage{{AckId: "a1", Message: &pubsubv1.PubsubMessage{MessageId: "m1", Data: ""}}}
	mustEvalCloud(t, `gcp["pubsub"]["pull"]("p", "sub", ack=False)`)
	if len(fakes.pubsub.acked) != 0 || fakes.pubsub.pullMax != 10 {
		t.Fatalf("acked = %v max = %d, want no ack and default max 10", fakes.pubsub.acked, fakes.pubsub.pullMax)
	}
}

func TestPubSubPullFailsClosed(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.pubsub.received = []*pubsubv1.ReceivedMessage{{AckId: "a1", Message: &pubsubv1.PubsubMessage{MessageId: "m1", Data: "aGk="}}}
	fakes.pubsub.ackErr = errors.New("ack failed")
	env := cloudEnv(t, allowAllPolicy, false)
	if _, err := evalCloud(t, env, `gcp["pubsub"]["pull"]("p", "sub", ack=True)`); err == nil || !strings.Contains(err.Error(), "ack") {
		t.Fatalf("err = %v, want ack failure", err)
	}
	for _, expr := range []string{`gcp["pubsub"]["pull"]("p", "sub", max=0, ack=True)`, `gcp["pubsub"]["pull"]("p", "sub", max=1001, ack=True)`} {
		if _, err := evalCloud(t, env, expr); err == nil || !strings.Contains(err.Error(), "max must be") {
			t.Fatalf("%s: err = %v", expr, err)
		}
	}
	fakes.pubsub.ackErr = nil
	fakes.pubsub.received = []*pubsubv1.ReceivedMessage{{AckId: "a1", Message: &pubsubv1.PubsubMessage{MessageId: "m1", Data: "!!not-base64"}}}
	if _, err := evalCloud(t, env, `gcp["pubsub"]["pull"]("p", "sub", ack=True)`); err == nil || !strings.Contains(err.Error(), "undecodable") {
		t.Fatalf("err = %v, want undecodable data", err)
	}
}

// ── Cloud Run ─────────────────────────────────────────────────────────────────

func TestRunListServices(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.run.services = []*runv2.GoogleCloudRunV2Service{{
		Name: "projects/p/locations/us-central1/services/api", Uri: "https://api-xyz.a.run.app",
		TerminalCondition: &runv2.GoogleCloudRunV2Condition{State: "CONDITION_SUCCEEDED"},
	}}
	v := mustEvalCloud(t, `gcp["run"]["list_services"]("p", "us-central1")`)
	if fakes.run.got != "projects/p/locations/us-central1" {
		t.Fatalf("parent = %q", fakes.run.got)
	}
	s := v.(*starlark.List).Index(0)
	if dictGet(t, s, "name") != starlark.String("api") || dictGet(t, s, "status") != starlark.String("CONDITION_SUCCEEDED") {
		t.Fatalf("service = %v", s)
	}
}

// ── CloudWatch ────────────────────────────────────────────────────────────────

func TestCloudWatchGetMetric(t *testing.T) {
	fakes := installCloudFakes(t)
	t1 := time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)
	t0 := t1.Add(-5 * time.Minute)
	fakes.cw.points = []cwtypes.Datapoint{
		{Timestamp: aws.Time(t1), Maximum: aws.Float64(9), Unit: cwtypes.StandardUnitPercent},
		{Timestamp: aws.Time(t0), Maximum: aws.Float64(4), Unit: cwtypes.StandardUnitPercent},
	}
	v := mustEvalCloud(t, `aws["cloudwatch"]["get_metric"]("AWS/EC2", "CPUUtilization", {"InstanceId": "i-1"}, stat="Maximum", period=60, minutes=10, region="eu-west-1")`)
	in := fakes.cw.getIn
	if fakes.region != "eu-west-1" || *in.Namespace != "AWS/EC2" || *in.Period != 60 || in.Statistics[0] != cwtypes.StatisticMaximum {
		t.Fatalf("input = %+v region %q", in, fakes.region)
	}
	if got := in.EndTime.Sub(*in.StartTime); got != 10*time.Minute {
		t.Fatalf("window = %v, want 10m", got)
	}
	if *in.Dimensions[0].Name != "InstanceId" || *in.Dimensions[0].Value != "i-1" {
		t.Fatalf("dimensions = %+v", in.Dimensions)
	}
	l := v.(*starlark.List)
	if dictGet(t, l.Index(0), "value") != starlark.Float(4) || dictGet(t, l.Index(1), "value") != starlark.Float(9) {
		t.Fatalf("datapoints not sorted by time: %v", v)
	}
}

func TestCloudWatchGetMetricRejectsBadInput(t *testing.T) {
	fakes := installCloudFakes(t)
	env := cloudEnv(t, allowAllPolicy, false)
	for expr, want := range map[string]string{
		`aws["cloudwatch"]["get_metric"]("AWS/EC2", "CPU", {}, stat="p99")`:     "unknown stat",
		`aws["cloudwatch"]["get_metric"]("AWS/EC2", "CPU", {}, period=0)`:       "period",
		`aws["cloudwatch"]["get_metric"]("AWS/EC2", "CPU", {}, minutes=0)`:      "minutes",
		`aws["cloudwatch"]["get_metric"]("AWS/EC2", "CPU", {}, minutes=100000)`: "minutes",
		`aws["cloudwatch"]["get_metric"]("AWS/EC2", "CPU", {"InstanceId": 1})`:  "dimensions",
		`aws["cloudwatch"]["get_metric"]("", "CPU", {})`:                        "required",
	} {
		if _, err := evalCloud(t, env, expr); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", expr, err, want)
		}
	}
	if fakes.calls.n != 0 {
		t.Fatalf("client used %d times for rejected input", fakes.calls.n)
	}
}

func TestCloudWatchListMetricsPaginates(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.cw.pages = []*cloudwatch.ListMetricsOutput{
		{Metrics: []cwtypes.Metric{{Namespace: aws.String("AWS/EC2"), MetricName: aws.String("CPUUtilization"),
			Dimensions: []cwtypes.Dimension{{Name: aws.String("InstanceId"), Value: aws.String("i-1")}}}}, NextToken: aws.String("tok")},
		{Metrics: []cwtypes.Metric{{Namespace: aws.String("AWS/EC2"), MetricName: aws.String("NetworkIn")}}},
	}
	v := mustEvalCloud(t, `aws["cloudwatch"]["list_metrics"]("AWS/EC2")`)
	if listLen(t, v) != 2 || len(fakes.cw.listIns) != 2 || aws.ToString(fakes.cw.listIns[1].NextToken) != "tok" {
		t.Fatalf("metrics = %v, inputs = %d", v, len(fakes.cw.listIns))
	}
	if dictGet(t, dictGet(t, v.(*starlark.List).Index(0), "dimensions"), "InstanceId") != starlark.String("i-1") {
		t.Fatalf("dimensions = %v", v)
	}
}

// ── Route 53 ──────────────────────────────────────────────────────────────────

func TestRoute53ListZonesPaginates(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.r53.zonePages = []*route53.ListHostedZonesOutput{
		{HostedZones: []r53types.HostedZone{{Id: aws.String("/hostedzone/Z1"), Name: aws.String("a.com.")}}, IsTruncated: true, NextMarker: aws.String("m")},
		{HostedZones: []r53types.HostedZone{{Id: aws.String("/hostedzone/Z2"), Name: aws.String("b.com."), Config: &r53types.HostedZoneConfig{PrivateZone: true}}}},
	}
	v := mustEvalCloud(t, `aws["route53"]["list_zones"]()`)
	l := v.(*starlark.List)
	if l.Len() != 2 || dictGet(t, l.Index(0), "id") != starlark.String("Z1") || dictGet(t, l.Index(1), "private") != starlark.True {
		t.Fatalf("zones = %v", v)
	}
}

func TestRoute53ListRecordsPaginates(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.r53.recPages = []*route53.ListResourceRecordSetsOutput{
		{ResourceRecordSets: []r53types.ResourceRecordSet{{Name: aws.String("a.com."), Type: r53types.RRTypeA, TTL: aws.Int64(60),
			ResourceRecords: []r53types.ResourceRecord{{Value: aws.String("192.0.2.1")}}}},
			IsTruncated: true, NextRecordName: aws.String("b.a.com."), NextRecordType: r53types.RRTypeCname},
		{ResourceRecordSets: []r53types.ResourceRecordSet{{Name: aws.String("b.a.com."), Type: r53types.RRTypeCname,
			AliasTarget: &r53types.AliasTarget{DNSName: aws.String("lb.example.net.")}}}},
	}
	v := mustEvalCloud(t, `aws["route53"]["list_records"]("/hostedzone/Z1")`)
	if listLen(t, v) != 2 || aws.ToString(fakes.r53.recIns[0].HostedZoneId) != "Z1" {
		t.Fatalf("records = %v", v)
	}
	if aws.ToString(fakes.r53.recIns[1].StartRecordName) != "b.a.com." || fakes.r53.recIns[1].StartRecordType != r53types.RRTypeCname {
		t.Fatalf("second page input = %+v", fakes.r53.recIns[1])
	}
}

func TestRoute53UpsertRecord(t *testing.T) {
	fakes := installCloudFakes(t)
	v := mustEvalCloud(t, `aws["route53"]["upsert_record"](zone_id="Z1", name="www.example.com.", type="a", values=["192.0.2.1", "192.0.2.2"], ttl=60)`)
	if dictGet(t, v, "change_id") != starlark.String("C123") || dictGet(t, v, "status") != starlark.String("PENDING") {
		t.Fatalf("result = %v", v)
	}
	ch := fakes.r53.change
	rr := ch.ChangeBatch.Changes[0].ResourceRecordSet
	if aws.ToString(ch.HostedZoneId) != "Z1" || ch.ChangeBatch.Changes[0].Action != r53types.ChangeActionUpsert ||
		aws.ToString(rr.Name) != "www.example.com." || rr.Type != r53types.RRTypeA || *rr.TTL != 60 || len(rr.ResourceRecords) != 2 {
		t.Fatalf("change = %+v rr = %+v", ch, rr)
	}
}

func TestRoute53UpsertRejectsBadInput(t *testing.T) {
	fakes := installCloudFakes(t)
	env := cloudEnv(t, allowAllPolicy, false)
	for expr, want := range map[string]string{
		`aws["route53"]["upsert_record"](zone_id="z1;x", name="a.com.", type="A", values=["192.0.2.1"])`:   "zone_id",
		`aws["route53"]["upsert_record"](zone_id="Z1", name="a b.com.", type="A", values=["192.0.2.1"])`:   "record name",
		`aws["route53"]["upsert_record"](zone_id="Z1", name="a.com.", type="BOGUS", values=["192.0.2.1"])`: "record type",
		`aws["route53"]["upsert_record"](zone_id="Z1", name="a.com.", type="A", values=[])`:                "values",
		`aws["route53"]["upsert_record"](zone_id="Z1", name="a.com.", type="A", values=[1])`:               "values[0]",
		`aws["route53"]["upsert_record"](zone_id="Z1", name="a.com.", type="A", values="192.0.2.1")`:       "values",
		`aws["route53"]["upsert_record"](zone_id="Z1", name="a.com.", type="A", values=["x"], ttl=-1)`:     "ttl",
	} {
		if _, err := evalCloud(t, env, expr); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", expr, err, want)
		}
	}
	if fakes.calls.n != 0 {
		t.Fatalf("client used %d times for rejected input", fakes.calls.n)
	}
}

func TestCloudErrorStripsURLAndControlChars(t *testing.T) {
	err := cloudError("op", &url.Error{Op: "Post", URL: "https://h.example/hook?sig=SECRET", Err: errors.New("dial failed\nforged line")})
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "\n") {
		t.Fatalf("err = %q", err)
	}
	long := cloudError("op", errors.New(strings.Repeat("x", 5000)))
	if len(long.Error()) > cloudErrorMax+20 {
		t.Fatalf("error not capped: %d bytes", len(long.Error()))
	}
}

// Route 53 treats case, a missing trailing dot and \NNN escapes as the same
// name, so only the canonical spelling reaches the gate and the SDK.
func TestRoute53RejectsNonCanonicalNames(t *testing.T) {
	fakes := installCloudFakes(t)
	env := cloudEnv(t, allowAllPolicy, false)
	for _, name := range []string{`PROD.example.com.`, `prod.example.com`, `\\052.example.com.`, `prod\\.example.com.`} {
		for _, expr := range []string{
			fmt.Sprintf(`aws["route53"]["upsert_record"](zone_id="Z1", name=%q, type="A", values=["192.0.2.1"])`, name),
			fmt.Sprintf(`aws["route53"]["delete_record"](zone_id="Z1", name=%q, type="A")`, name),
		} {
			_, err := evalCloud(t, env, expr)
			if err == nil || !strings.Contains(err.Error(), "canonical") {
				t.Fatalf("%s: err = %v, want a canonical-name refusal", expr, err)
			}
		}
	}
	if fakes.calls.n != 0 {
		t.Fatalf("client used %d times for non-canonical names", fakes.calls.n)
	}
}

func TestRoute53DeleteIsKeywordOnly(t *testing.T) {
	fakes := installCloudFakes(t)
	_, err := evalCloud(t, cloudEnv(t, allowAllPolicy, false), `aws["route53"]["delete_record"]("Z1", "a.example.com.", "A")`)
	if err == nil || !strings.Contains(err.Error(), "keyword arguments only") {
		t.Fatalf("err = %v, want keyword-only refusal", err)
	}
	if fakes.calls.n != 0 {
		t.Fatalf("client used %d times", fakes.calls.n)
	}
}

// A rule on the canonical name holds for both upsert and delete.
func TestRoute53GateSeesCanonicalName(t *testing.T) {
	fakes := installCloudFakes(t)
	env := cloudEnv(t, `
package adssh.authz
default allow = true
allow = false { input.args[_] == "\"name\"=\"prod.example.com.\"" }
deny_reason = "prod is frozen" { input.args[_] == "\"name\"=\"prod.example.com.\"" }
`, false)
	for _, expr := range []string{
		`aws["route53"]["upsert_record"](zone_id="Z1", name="prod.example.com.", type="A", values=["192.0.2.1"])`,
		`aws["route53"]["delete_record"](zone_id="Z1", name="prod.example.com.", type="A")`,
	} {
		if _, err := evalCloud(t, env, expr); err == nil || !strings.Contains(err.Error(), "prod is frozen") {
			t.Fatalf("%s: err = %v, want policy denial", expr, err)
		}
	}
	if fakes.calls.n != 0 {
		t.Fatalf("client used %d times after deny", fakes.calls.n)
	}
}

func TestRoute53DeleteRecord(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.r53.recPages = []*route53.ListResourceRecordSetsOutput{{ResourceRecordSets: []r53types.ResourceRecordSet{{
		Name: aws.String("www.example.com."), Type: r53types.RRTypeA, TTL: aws.Int64(60),
		ResourceRecords: []r53types.ResourceRecord{{Value: aws.String("192.0.2.1")}},
	}}}}
	v := mustEvalCloud(t, `aws["route53"]["delete_record"](zone_id="/hostedzone/Z1", name="www.example.com.", type="a")`)
	if v != starlark.String("/change/C123") {
		t.Fatalf("result = %v", v)
	}
	in := fakes.r53.recIns[0]
	if aws.ToString(in.HostedZoneId) != "Z1" || aws.ToString(in.StartRecordName) != "www.example.com." || in.StartRecordType != r53types.RRTypeA {
		t.Fatalf("list input = %+v", in)
	}
	ch := fakes.r53.change.ChangeBatch.Changes[0]
	if ch.Action != r53types.ChangeActionDelete || aws.ToString(ch.ResourceRecordSet.Name) != "www.example.com." {
		t.Fatalf("change = %+v", ch)
	}
}

// ListResourceRecordSets starts at the name; when the record is absent it
// returns the next one, which must not be deleted.
func TestRoute53DeleteRefusesNeighbourRecord(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.r53.recPages = []*route53.ListResourceRecordSetsOutput{{ResourceRecordSets: []r53types.ResourceRecordSet{{
		Name: aws.String("zzz.example.com."), Type: r53types.RRTypeA,
	}}}}
	_, err := evalCloud(t, cloudEnv(t, allowAllPolicy, false), `aws["route53"]["delete_record"](zone_id="Z1", name="www.example.com.", type="A")`)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not found", err)
	}
	if fakes.r53.change != nil {
		t.Fatalf("deleted %+v", fakes.r53.change)
	}
}

func TestRoute53DeleteWildcard(t *testing.T) {
	fakes := installCloudFakes(t)
	fakes.r53.recPages = []*route53.ListResourceRecordSetsOutput{{ResourceRecordSets: []r53types.ResourceRecordSet{{
		Name: aws.String(`\052.example.com.`), Type: r53types.RRTypeCname,
	}}}}
	mustEvalCloud(t, `aws["route53"]["delete_record"](zone_id="Z1", name="*.example.com.", type="CNAME")`)
	if fakes.r53.change == nil {
		t.Fatal("wildcard record was not deleted")
	}
}

// Whether pull acknowledges is a policy fact, so ack must reach the gate as
// "ack"=True or "ack"=False: it is a required keyword.
func TestPubSubPullAckIsVisibleToGate(t *testing.T) {
	fakes := installCloudFakes(t)
	env := cloudEnv(t, allowAllPolicy, false)
	for _, expr := range []string{
		`gcp["pubsub"]["pull"]("p", "sub")`,
		`gcp["pubsub"]["pull"]("p", "sub", 5, True)`,
	} {
		if _, err := evalCloud(t, env, expr); err == nil || !strings.Contains(err.Error(), "ack=") {
			t.Fatalf("%s: err = %v, want a required-ack refusal", expr, err)
		}
	}
	if fakes.calls.n != 0 {
		t.Fatalf("client used %d times", fakes.calls.n)
	}
	deny := cloudEnv(t, `
package adssh.authz
default allow = true
allow = false { input.command == "starlark.gcp.pubsub.pull"; input.args[_] == "\"ack\"=True" }
deny_reason = "destructive pull" { input.command == "starlark.gcp.pubsub.pull"; input.args[_] == "\"ack\"=True" }
`, false)
	if _, err := evalCloud(t, deny, `gcp["pubsub"]["pull"]("p", "sub", ack=True)`); err == nil || !strings.Contains(err.Error(), "destructive pull") {
		t.Fatalf("err = %v, want policy denial on ack=True", err)
	}
	if _, err := evalCloud(t, deny, `gcp["pubsub"]["pull"]("p", "sub", ack=False)`); err != nil {
		t.Fatalf("ack=False under an ack=True deny: %v", err)
	}
}
