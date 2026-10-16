package starlarkext

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"go.starlark.net/starlark"
)

// Threats: these builtins reach CloudWatch and Route 53 with the caller's AWS
// credentials. Each one is a governed builtin, so the policy gate sees
// starlark.aws.<svc>.<fn> with capability "cloud" before any request is made;
// route53.upsert_record and delete_record also carry capability "dns" so a
// policy can deny DNS changes while allowing reads. upsert_record and
// delete_record take keyword arguments only, so the gate always sees the
// record as the argument "name"="<record>" and a policy can match on it.
// Route 53 treats case, a missing trailing dot and \NNN escapes as the same
// name, so both refuse any name that is not lowercase, not dot-terminated or
// contains a backslash: the name the gate sees is the one Route 53 changes.
// Inputs are validated before the SDK is called (zone id charset,
// record type against the SDK enum, TTL range, value count and type, metric
// statistic). Lists are paginated with a hard cap. Errors go through
// cloudError. Every call has a 30s deadline. In restricted sessions the
// cloudwatch and route53 namespaces are absent. This does not limit what the
// credentials themselves may do; that is IAM's job.

// ExpandAWSAPIExtra adds cloudwatch and route53 sub-namespaces to the existing
// aws.* dict. In restricted sessions it adds nothing.
//
//	aws.cloudwatch.get_metric(namespace, metric, dimensions, stat="Average", period=300, minutes=60, region="")
//	aws.cloudwatch.list_metrics(namespace, region="")
//	aws.cloudwatch.list_alarms(region="", state="")
//	aws.cloudwatch.get_alarm_state(name="", region="")
//	aws.route53.list_zones()
//	aws.route53.list_records(zone_id)
//	aws.route53.upsert_record(zone_id=, name=, type=, values=[...], ttl=300)   # keyword-only
//	aws.route53.delete_record(zone_id=, name=, type="A")                       # keyword-only
func ExpandAWSAPIExtra(env starlark.StringDict, restricted bool) {
	if restricted {
		return
	}
	awsDict, ok := env["aws"].(*starlark.Dict)
	if !ok {
		return
	}

	cwDict := starlark.NewDict(4)
	_ = cwDict.SetKey(starlark.String("get_metric"), starlark.NewBuiltin("get_metric", awsCWGetMetric))
	_ = cwDict.SetKey(starlark.String("list_metrics"), starlark.NewBuiltin("list_metrics", awsCWListMetrics))
	_ = cwDict.SetKey(starlark.String("list_alarms"), starlark.NewBuiltin("list_alarms", awsCWListAlarms))
	_ = cwDict.SetKey(starlark.String("get_alarm_state"), starlark.NewBuiltin("get_alarm_state", awsCWGetAlarmState))
	_ = awsDict.SetKey(starlark.String("cloudwatch"), cwDict)

	r53Dict := starlark.NewDict(4)
	_ = r53Dict.SetKey(starlark.String("list_zones"), starlark.NewBuiltin("list_zones", awsR53ListZones))
	_ = r53Dict.SetKey(starlark.String("list_records"), starlark.NewBuiltin("list_records", awsR53ListRecords))
	_ = r53Dict.SetKey(starlark.String("upsert_record"), starlark.NewBuiltin("upsert_record", awsR53UpsertRecord))
	_ = r53Dict.SetKey(starlark.String("delete_record"), starlark.NewBuiltin("delete_record", awsR53DeleteRecord))
	_ = awsDict.SetKey(starlark.String("route53"), r53Dict)
}

// ── Clients (swapped for fakes in tests) ─────────────────────────────────────

// cloudWatchAPI is the subset of *cloudwatch.Client these builtins use.
type cloudWatchAPI interface {
	GetMetricStatistics(ctx context.Context, in *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
	ListMetrics(ctx context.Context, in *cloudwatch.ListMetricsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error)
}

// route53API is the subset of *route53.Client these builtins use.
type route53API interface {
	ListHostedZones(ctx context.Context, in *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, in *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
}

var newCloudWatchClient = func(region string) (cloudWatchAPI, error) {
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	return cloudwatch.NewFromConfig(cfg), nil
}

var newRoute53Client = func() (route53API, error) {
	cfg, err := awsLoadConfig("")
	if err != nil {
		return nil, err
	}
	return route53.NewFromConfig(cfg), nil
}

const (
	awsListLimit       = 10000
	cwMaxMinutes       = 60 * 24 * 15 // 15 days
	r53MaxValues       = 100
	r53MaxTTL          = 2147483647
	r53MaxRecordName   = 1024
	r53MaxValueLength  = 4000
	cwMaxDimensions    = 30
	cwMaxPeriodSeconds = 86400
)

var r53ZoneIDPattern = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)

// awsZoneID accepts "Z123" or "/hostedzone/Z123" and returns "Z123".
func awsZoneID(op, raw string) (string, error) {
	id := strings.TrimPrefix(raw, "/hostedzone/")
	if !r53ZoneIDPattern.MatchString(id) {
		return "", fmt.Errorf("%s: invalid zone_id %q", op, raw)
	}
	return id, nil
}

// ── CloudWatch ────────────────────────────────────────────────────────────────

func cwStatistic(stat string) (cwtypes.Statistic, bool) {
	for _, s := range cwtypes.Statistic("").Values() {
		if string(s) == stat {
			return s, true
		}
	}
	return "", false
}

func cwDatapointValue(dp cwtypes.Datapoint, stat cwtypes.Statistic) float64 {
	var v *float64
	switch stat {
	case cwtypes.StatisticAverage:
		v = dp.Average
	case cwtypes.StatisticSum:
		v = dp.Sum
	case cwtypes.StatisticMinimum:
		v = dp.Minimum
	case cwtypes.StatisticMaximum:
		v = dp.Maximum
	case cwtypes.StatisticSampleCount:
		v = dp.SampleCount
	}
	if v == nil {
		return 0
	}
	return *v
}

func awsCWGetMetric(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "aws.cloudwatch.get_metric"
	var namespace, metric, region string
	var dimsDict *starlark.Dict
	stat := "Average"
	period, minutes := 300, 60
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"namespace", &namespace,
		"metric", &metric,
		"dimensions", &dimsDict,
		"stat?", &stat,
		"period?", &period,
		"minutes?", &minutes,
		"region?", &region,
	); err != nil {
		return nil, err
	}
	if namespace == "" || metric == "" {
		return nil, fmt.Errorf("%s: namespace and metric are required", op)
	}
	statistic, ok := cwStatistic(stat)
	if !ok {
		return nil, fmt.Errorf("%s: unknown stat %q (want Average, Sum, Minimum, Maximum, or SampleCount)", op, stat)
	}
	if period < 1 || period > cwMaxPeriodSeconds {
		return nil, fmt.Errorf("%s: period must be between 1 and %d seconds", op, cwMaxPeriodSeconds)
	}
	if minutes < 1 || minutes > cwMaxMinutes {
		return nil, fmt.Errorf("%s: minutes must be between 1 and %d", op, cwMaxMinutes)
	}
	var dims []cwtypes.Dimension
	if dimsDict != nil {
		if dimsDict.Len() > cwMaxDimensions {
			return nil, fmt.Errorf("%s: %d dimensions, limit is %d", op, dimsDict.Len(), cwMaxDimensions)
		}
		for _, kv := range dimsDict.Items() {
			k, kok := starlark.AsString(kv[0])
			v, vok := starlark.AsString(kv[1])
			if !kok || !vok || k == "" {
				return nil, fmt.Errorf("%s: dimensions must map non-empty strings to strings", op)
			}
			dims = append(dims, cwtypes.Dimension{Name: aws.String(k), Value: aws.String(v)})
		}
	}

	client, err := newCloudWatchClient(region)
	if err != nil {
		return nil, cloudError("aws.cloudwatch", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	now := time.Now().UTC()
	out, err := client.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(namespace),
		MetricName: aws.String(metric),
		Dimensions: dims,
		Period:     aws.Int32(int32(period)),
		Statistics: []cwtypes.Statistic{statistic},
		StartTime:  aws.Time(now.Add(-time.Duration(minutes) * time.Minute)),
		EndTime:    aws.Time(now),
	})
	if err != nil {
		return nil, cloudError(op, err)
	}

	points := append([]cwtypes.Datapoint(nil), out.Datapoints...)
	sort.Slice(points, func(i, j int) bool {
		if points[i].Timestamp == nil || points[j].Timestamp == nil {
			return points[j].Timestamp != nil
		}
		return points[i].Timestamp.Before(*points[j].Timestamp)
	})
	results := make([]starlark.Value, 0, len(points))
	for _, dp := range points {
		ts := ""
		if dp.Timestamp != nil {
			ts = dp.Timestamp.UTC().Format(time.RFC3339)
		}
		results = append(results, makeDict(
			"timestamp", ts,
			"value", cwDatapointValue(dp, statistic),
			"unit", string(dp.Unit),
		))
	}
	return starlark.NewList(results), nil
}

func awsCWListMetrics(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "aws.cloudwatch.list_metrics"
	var namespace, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "namespace", &namespace, "region?", &region); err != nil {
		return nil, err
	}
	if namespace == "" {
		return nil, fmt.Errorf("%s: namespace is required", op)
	}
	client, err := newCloudWatchClient(region)
	if err != nil {
		return nil, cloudError("aws.cloudwatch", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()

	var results []starlark.Value
	input := &cloudwatch.ListMetricsInput{Namespace: aws.String(namespace)}
	for {
		out, err := client.ListMetrics(ctx, input)
		if err != nil {
			return nil, cloudError(op, err)
		}
		for _, m := range out.Metrics {
			if len(results) >= awsListLimit {
				return nil, fmt.Errorf("%s: more than %d metrics; narrow the namespace", op, awsListLimit)
			}
			dims := map[string]string{}
			for _, d := range m.Dimensions {
				dims[strDeref(d.Name)] = strDeref(d.Value)
			}
			results = append(results, makeDict(
				"namespace", strDeref(m.Namespace),
				"metric", strDeref(m.MetricName),
				"dimensions", dims,
			))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		input.NextToken = out.NextToken
	}
	return starlark.NewList(results), nil
}

func awsCWListAlarms(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region, state string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region, "state?", &state); err != nil {
		return nil, err
	}

	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}

	input := &cloudwatch.DescribeAlarmsInput{}
	if state != "" {
		input.StateValue = cwtypes.StateValue(state)
	}

	out, err := cloudwatch.NewFromConfig(cfg).DescribeAlarms(context.Background(), input)
	if err != nil {
		return nil, fmt.Errorf("aws.cloudwatch.list_alarms: %v", err)
	}

	var results []starlark.Value
	for _, a := range out.MetricAlarms {
		results = append(results, makeDict(
			"name", strDeref(a.AlarmName),
			"state", string(a.StateValue),
			"metric", strDeref(a.MetricName),
		))
	}
	return starlark.NewList(results), nil
}

func awsCWGetAlarmState(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "region?", &region); err != nil {
		return nil, err
	}

	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}

	out, err := cloudwatch.NewFromConfig(cfg).DescribeAlarms(context.Background(), &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []string{name},
	})
	if err != nil {
		return nil, fmt.Errorf("aws.cloudwatch.get_alarm_state: %v", err)
	}
	if len(out.MetricAlarms) == 0 {
		return starlark.None, nil
	}
	a := out.MetricAlarms[0]
	return makeDict(
		"state", string(a.StateValue),
		"reason", strDeref(a.StateReason),
	), nil
}

// ── Route 53 ──────────────────────────────────────────────────────────────────

func awsR53ListZones(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "aws.route53.list_zones"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
		return nil, err
	}
	client, err := newRoute53Client()
	if err != nil {
		return nil, cloudError("aws.route53", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()

	var results []starlark.Value
	input := &route53.ListHostedZonesInput{}
	for {
		out, err := client.ListHostedZones(ctx, input)
		if err != nil {
			return nil, cloudError(op, err)
		}
		for _, z := range out.HostedZones {
			if len(results) >= awsListLimit {
				return nil, fmt.Errorf("%s: more than %d zones", op, awsListLimit)
			}
			results = append(results, makeDict(
				"id", strings.TrimPrefix(strDeref(z.Id), "/hostedzone/"),
				"name", strDeref(z.Name),
				"private", z.Config != nil && z.Config.PrivateZone,
				"record_count", z.ResourceRecordSetCount,
			))
		}
		if !out.IsTruncated || out.NextMarker == nil {
			break
		}
		input.Marker = out.NextMarker
	}
	return starlark.NewList(results), nil
}

func awsR53ListRecords(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "aws.route53.list_records"
	var rawZone string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "zone_id", &rawZone); err != nil {
		return nil, err
	}
	zoneID, err := awsZoneID(op, rawZone)
	if err != nil {
		return nil, err
	}
	client, err := newRoute53Client()
	if err != nil {
		return nil, cloudError("aws.route53", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()

	var results []starlark.Value
	input := &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zoneID)}
	for {
		out, err := client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return nil, cloudError(op, err)
		}
		for _, rr := range out.ResourceRecordSets {
			if len(results) >= awsListLimit {
				return nil, fmt.Errorf("%s: more than %d records", op, awsListLimit)
			}
			vals := make([]string, 0, len(rr.ResourceRecords))
			for _, r := range rr.ResourceRecords {
				vals = append(vals, strDeref(r.Value))
			}
			alias := ""
			if rr.AliasTarget != nil {
				alias = strDeref(rr.AliasTarget.DNSName)
			}
			ttl := int64(0)
			if rr.TTL != nil {
				ttl = *rr.TTL
			}
			results = append(results, makeDict(
				"name", strDeref(rr.Name),
				"type", string(rr.Type),
				"ttl", ttl,
				"values", vals,
				"alias", alias,
				"set_identifier", strDeref(rr.SetIdentifier),
			))
		}
		if !out.IsTruncated || out.NextRecordName == nil {
			break
		}
		input.StartRecordName = out.NextRecordName
		input.StartRecordType = out.NextRecordType
		input.StartRecordIdentifier = out.NextRecordIdentifier
	}
	return starlark.NewList(results), nil
}

func r53RecordType(t string) (r53types.RRType, bool) {
	for _, v := range r53types.RRType("").Values() {
		if string(v) == t {
			return v, true
		}
	}
	return "", false
}

func validRecordName(name string) bool {
	if name == "" || len(name) > r53MaxRecordName {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// canonicalRecordName refuses a record name Route 53 would treat as another
// spelling of a canonical name, so a policy rule on the canonical form cannot
// be bypassed by case, a missing trailing dot or a \NNN escape.
func canonicalRecordName(op, name string) error {
	if !validRecordName(name) {
		return fmt.Errorf("%s: invalid record name %q", op, name)
	}
	if name != strings.ToLower(name) || !strings.HasSuffix(name, ".") || strings.Contains(name, `\`) {
		return fmt.Errorf("%s: record name %q is not canonical: use lowercase, end with a dot and no backslash escapes (e.g. %q)",
			op, name, strings.TrimSuffix(strings.ToLower(name), ".")+".")
	}
	return nil
}

// awsR53UpsertRecord creates or replaces one record set. It takes keyword
// arguments only so the policy gate always receives the record as "name"="<record>".
func awsR53UpsertRecord(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "aws.route53.upsert_record"
	if len(args) > 0 {
		return nil, fmt.Errorf("%s: takes keyword arguments only (zone_id=, name=, type=, values=, ttl=) so policy can match on the record name", op)
	}
	var rawZone, name, recType string
	var values starlark.Value
	ttl := 300
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"zone_id", &rawZone,
		"name", &name,
		"type", &recType,
		"values", &values,
		"ttl?", &ttl,
	); err != nil {
		return nil, err
	}
	zoneID, err := awsZoneID(op, rawZone)
	if err != nil {
		return nil, err
	}
	if err := canonicalRecordName(op, name); err != nil {
		return nil, err
	}
	rrType, ok := r53RecordType(strings.ToUpper(recType))
	if !ok {
		return nil, fmt.Errorf("%s: unknown record type %q", op, recType)
	}
	if ttl < 0 || ttl > r53MaxTTL {
		return nil, fmt.Errorf("%s: ttl must be between 0 and %d", op, r53MaxTTL)
	}
	var seq starlark.Indexable
	switch v := values.(type) {
	case *starlark.List:
		seq = v
	case starlark.Tuple:
		seq = v
	default:
		return nil, fmt.Errorf("%s: values must be a list of strings, got %s", op, values.Type())
	}
	if seq.Len() == 0 || seq.Len() > r53MaxValues {
		return nil, fmt.Errorf("%s: values must hold between 1 and %d entries", op, r53MaxValues)
	}
	records := make([]r53types.ResourceRecord, 0, seq.Len())
	for i := 0; i < seq.Len(); i++ {
		v, ok := starlark.AsString(seq.Index(i))
		if !ok || v == "" || len(v) > r53MaxValueLength {
			return nil, fmt.Errorf("%s: values[%d] must be a non-empty string of at most %d bytes", op, i, r53MaxValueLength)
		}
		records = append(records, r53types.ResourceRecord{Value: aws.String(v)})
	}

	client, err := newRoute53Client()
	if err != nil {
		return nil, cloudError("aws.route53", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	ttl64 := int64(ttl)
	out, err := client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Comment: aws.String("adssh aws.route53.upsert_record"),
			Changes: []r53types.Change{{
				Action: r53types.ChangeActionUpsert,
				ResourceRecordSet: &r53types.ResourceRecordSet{
					Name:            aws.String(name),
					Type:            rrType,
					TTL:             &ttl64,
					ResourceRecords: records,
				},
			}},
		},
	})
	if err != nil {
		return nil, cloudError(op, err)
	}
	changeID, status := "", ""
	if out.ChangeInfo != nil {
		changeID = strings.TrimPrefix(strDeref(out.ChangeInfo.Id), "/change/")
		status = string(out.ChangeInfo.Status)
	}
	return makeDict("change_id", changeID, "status", status), nil
}

// r53DecodeName turns the \NNN octal escapes Route 53 uses in listed names
// (a wildcard is listed as \052) back into characters.
func r53DecodeName(listed string) string {
	var b strings.Builder
	for i := 0; i < len(listed); i++ {
		if listed[i] == '\\' && i+3 < len(listed) {
			if n, err := strconv.ParseUint(listed[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(listed[i])
	}
	return b.String()
}

// awsR53DeleteRecord deletes the record set with exactly this name and type.
// Like upsert it takes keyword arguments only so the gate sees "name"=.
func awsR53DeleteRecord(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "aws.route53.delete_record"
	if len(args) > 0 {
		return nil, fmt.Errorf("%s: takes keyword arguments only (zone_id=, name=, type=) so policy can match on the record name", op)
	}
	var rawZone, name string
	recType := "A"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"zone_id", &rawZone,
		"name", &name,
		"type?", &recType,
	); err != nil {
		return nil, err
	}
	zoneID, err := awsZoneID(op, rawZone)
	if err != nil {
		return nil, err
	}
	if err := canonicalRecordName(op, name); err != nil {
		return nil, err
	}
	rrType, ok := r53RecordType(strings.ToUpper(recType))
	if !ok {
		return nil, fmt.Errorf("%s: unknown record type %q", op, recType)
	}

	client, err := newRoute53Client()
	if err != nil {
		return nil, cloudError("aws.route53", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloudCallTimeout)
	defer cancel()
	// Fetch the record set: a delete must match its current TTL and values.
	listOut, err := client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneID),
		StartRecordName: aws.String(name),
		StartRecordType: rrType,
		MaxItems:        aws.Int32(1),
	})
	if err != nil {
		return nil, cloudError(op+": list", err)
	}
	// The listing starts at name/type; when that record is absent it returns
	// the next one, which must not be deleted.
	if len(listOut.ResourceRecordSets) == 0 ||
		r53DecodeName(strDeref(listOut.ResourceRecordSets[0].Name)) != name || listOut.ResourceRecordSets[0].Type != rrType {
		return nil, fmt.Errorf("%s: record not found: %s %s", op, name, rrType)
	}
	rrset := listOut.ResourceRecordSets[0]

	out, err := client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Comment: aws.String("adssh aws.route53.delete_record"),
			Changes: []r53types.Change{{
				Action:            r53types.ChangeActionDelete,
				ResourceRecordSet: &rrset,
			}},
		},
	})
	if err != nil {
		return nil, cloudError(op, err)
	}
	changeID := ""
	if out.ChangeInfo != nil {
		changeID = strDeref(out.ChangeInfo.Id)
	}
	return starlark.String(changeID), nil
}
