package starlarkext

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"go.starlark.net/starlark"
)

// ExpandAWSAPIExtra adds cloudwatch and route53 sub-namespaces to the existing aws.* dict.
//
//	aws.cloudwatch.get_metric(namespace="AWS/EC2", metric="CPUUtilization", dimensions={"InstanceId":"i-xxx"}, period=300, stat="Average", region="")
//	aws.cloudwatch.list_alarms(region="", state="")
//	aws.cloudwatch.get_alarm_state(name="", region="")
//	aws.route53.list_zones()
//	aws.route53.list_records(zone_id="")
//	aws.route53.upsert_record(zone_id="", name="", type="A", ttl=300, values=[], region="")
//	aws.route53.delete_record(zone_id="", name="", type="A")
func ExpandAWSAPIExtra(env starlark.StringDict) {
	awsVal, ok := env["aws"]
	if !ok {
		return
	}
	awsDict, ok := awsVal.(*starlark.Dict)
	if !ok {
		return
	}

	cwDict := starlark.NewDict(3)
	cwDict.SetKey(starlark.String("get_metric"), starlark.NewBuiltin("get_metric", awsCWGetMetric))
	cwDict.SetKey(starlark.String("list_alarms"), starlark.NewBuiltin("list_alarms", awsCWListAlarms))
	cwDict.SetKey(starlark.String("get_alarm_state"), starlark.NewBuiltin("get_alarm_state", awsCWGetAlarmState))
	awsDict.SetKey(starlark.String("cloudwatch"), cwDict)

	r53Dict := starlark.NewDict(4)
	r53Dict.SetKey(starlark.String("list_zones"), starlark.NewBuiltin("list_zones", awsR53ListZones))
	r53Dict.SetKey(starlark.String("list_records"), starlark.NewBuiltin("list_records", awsR53ListRecords))
	r53Dict.SetKey(starlark.String("upsert_record"), starlark.NewBuiltin("upsert_record", awsR53UpsertRecord))
	r53Dict.SetKey(starlark.String("delete_record"), starlark.NewBuiltin("delete_record", awsR53DeleteRecord))
	awsDict.SetKey(starlark.String("route53"), r53Dict)
}

// ── CloudWatch ────────────────────────────────────────────────────────────────

func awsCWGetMetric(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace, metric, stat, region string
	var dimsDict *starlark.Dict
	var period int = 300
	namespace = "AWS/EC2"
	stat = "Average"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"namespace?", &namespace,
		"metric", &metric,
		"dimensions?", &dimsDict,
		"period?", &period,
		"stat?", &stat,
		"region?", &region,
	); err != nil {
		return nil, err
	}

	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}

	var dims []cwtypes.Dimension
	if dimsDict != nil {
		for _, kv := range dimsDict.Items() {
			k, _ := starlark.AsString(kv[0])
			v, _ := starlark.AsString(kv[1])
			dims = append(dims, cwtypes.Dimension{
				Name:  aws.String(k),
				Value: aws.String(v),
			})
		}
	}

	now := time.Now()
	startTime := now.Add(-time.Hour)
	out, err := cloudwatch.NewFromConfig(cfg).GetMetricStatistics(context.Background(), &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(namespace),
		MetricName: aws.String(metric),
		Dimensions: dims,
		Period:     aws.Int32(int32(period)),
		Statistics: []cwtypes.Statistic{cwtypes.Statistic(stat)},
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(now),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.cloudwatch.get_metric: %v", err)
	}

	var results []starlark.Value
	for _, dp := range out.Datapoints {
		ts := ""
		if dp.Timestamp != nil {
			ts = dp.Timestamp.Format(time.RFC3339)
		}
		val := 0.0
		switch cwtypes.Statistic(stat) {
		case cwtypes.StatisticAverage:
			if dp.Average != nil {
				val = *dp.Average
			}
		case cwtypes.StatisticSum:
			if dp.Sum != nil {
				val = *dp.Sum
			}
		case cwtypes.StatisticMinimum:
			if dp.Minimum != nil {
				val = *dp.Minimum
			}
		case cwtypes.StatisticMaximum:
			if dp.Maximum != nil {
				val = *dp.Maximum
			}
		case cwtypes.StatisticSampleCount:
			if dp.SampleCount != nil {
				val = *dp.SampleCount
			}
		default:
			if dp.Average != nil {
				val = *dp.Average
			}
		}
		results = append(results, makeDict("timestamp", ts, "value", val))
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
	if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
		return nil, err
	}

	cfg, err := awsLoadConfig("")
	if err != nil {
		return nil, err
	}

	out, err := route53.NewFromConfig(cfg).ListHostedZones(context.Background(), &route53.ListHostedZonesInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.route53.list_zones: %v", err)
	}

	var results []starlark.Value
	for _, z := range out.HostedZones {
		results = append(results, makeDict(
			"id", strDeref(z.Id),
			"name", strDeref(z.Name),
			"private", z.Config != nil && z.Config.PrivateZone,
		))
	}
	return starlark.NewList(results), nil
}

func awsR53ListRecords(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var zoneID string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "zone_id", &zoneID); err != nil {
		return nil, err
	}

	cfg, err := awsLoadConfig("")
	if err != nil {
		return nil, err
	}

	out, err := route53.NewFromConfig(cfg).ListResourceRecordSets(context.Background(), &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.route53.list_records: %v", err)
	}

	var results []starlark.Value
	for _, rr := range out.ResourceRecordSets {
		var vals []string
		for _, r := range rr.ResourceRecords {
			vals = append(vals, strDeref(r.Value))
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
		))
	}
	return starlark.NewList(results), nil
}

func awsR53UpsertRecord(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var zoneID, name, recType string
	var ttl int = 300
	var valuesList *starlark.List
	recType = "A"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"zone_id", &zoneID,
		"name", &name,
		"type?", &recType,
		"ttl?", &ttl,
		"values?", &valuesList,
	); err != nil {
		return nil, err
	}

	cfg, err := awsLoadConfig("")
	if err != nil {
		return nil, err
	}

	var records []r53types.ResourceRecord
	if valuesList != nil {
		for i := 0; i < valuesList.Len(); i++ {
			v, _ := starlark.AsString(valuesList.Index(i))
			records = append(records, r53types.ResourceRecord{Value: aws.String(v)})
		}
	}

	ttl64 := int64(ttl)
	out, err := route53.NewFromConfig(cfg).ChangeResourceRecordSets(context.Background(), &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{
				{
					Action: r53types.ChangeActionUpsert,
					ResourceRecordSet: &r53types.ResourceRecordSet{
						Name:            aws.String(name),
						Type:            r53types.RRType(recType),
						TTL:             &ttl64,
						ResourceRecords: records,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("aws.route53.upsert_record: %v", err)
	}
	changeID := ""
	if out.ChangeInfo.Id != nil {
		changeID = *out.ChangeInfo.Id
	}
	return starlark.String(changeID), nil
}

func awsR53DeleteRecord(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var zoneID, name, recType string
	recType = "A"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"zone_id", &zoneID,
		"name", &name,
		"type?", &recType,
	); err != nil {
		return nil, err
	}

	cfg, err := awsLoadConfig("")
	if err != nil {
		return nil, err
	}

	// Fetch existing records to get current TTL and values for deletion
	listOut, err := route53.NewFromConfig(cfg).ListResourceRecordSets(context.Background(), &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneID),
		StartRecordName: aws.String(name),
		StartRecordType: r53types.RRType(recType),
		MaxItems:        aws.Int32(1),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.route53.delete_record: list: %v", err)
	}
	if len(listOut.ResourceRecordSets) == 0 {
		return nil, fmt.Errorf("aws.route53.delete_record: record not found: %s %s", name, recType)
	}
	rrset := listOut.ResourceRecordSets[0]

	out, err := route53.NewFromConfig(cfg).ChangeResourceRecordSets(context.Background(), &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{
				{
					Action:            r53types.ChangeActionDelete,
					ResourceRecordSet: &rrset,
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("aws.route53.delete_record: %v", err)
	}
	changeID := ""
	if out.ChangeInfo.Id != nil {
		changeID = *out.ChangeInfo.Id
	}
	return starlark.String(changeID), nil
}
