package starlarkext

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"go.starlark.net/starlark"
)

// SetupAWSAPI registers the aws.* namespace into the Starlark environment.
//
// Starlark API:
//
//	aws.ec2.list_instances(region="us-east-1", state="running")
//	aws.ec2.start_instance(id="i-xxx", region="us-east-1")
//	aws.ec2.stop_instance(id="i-xxx", region="us-east-1")
//	aws.ec2.terminate_instance(id="i-xxx", region="us-east-1")
//	aws.s3.list_buckets()
//	aws.s3.put_object(bucket="b", key="k", body="data", region="us-east-1")
//	aws.s3.get_object(bucket="b", key="k", region="us-east-1")
//	aws.s3.delete_object(bucket="b", key="k", region="us-east-1")
//	aws.ecs.list_clusters(region="us-east-1")
//	aws.ecs.list_services(cluster="arn:...", region="us-east-1")
//	aws.lambda.list_functions(region="us-east-1")
//	aws.lambda.invoke(function="name", payload="{}", region="us-east-1")
//
// Credentials: standard AWS credential chain (env vars, ~/.aws/credentials,
// instance metadata, etc.)
func SetupAWSAPI(env starlark.StringDict) {
	ec2Dict := starlark.NewDict(4)
	ec2Dict.SetKey(starlark.String("list_instances"), starlark.NewBuiltin("list_instances", awsEC2ListInstances))
	ec2Dict.SetKey(starlark.String("start_instance"), starlark.NewBuiltin("start_instance", awsEC2StartInstance))
	ec2Dict.SetKey(starlark.String("stop_instance"), starlark.NewBuiltin("stop_instance", awsEC2StopInstance))
	ec2Dict.SetKey(starlark.String("terminate_instance"), starlark.NewBuiltin("terminate_instance", awsEC2TerminateInstance))

	s3Dict := starlark.NewDict(4)
	s3Dict.SetKey(starlark.String("list_buckets"), starlark.NewBuiltin("list_buckets", awsS3ListBuckets))
	s3Dict.SetKey(starlark.String("put_object"), starlark.NewBuiltin("put_object", awsS3PutObject))
	s3Dict.SetKey(starlark.String("get_object"), starlark.NewBuiltin("get_object", awsS3GetObject))
	s3Dict.SetKey(starlark.String("delete_object"), starlark.NewBuiltin("delete_object", awsS3DeleteObject))

	ecsDict := starlark.NewDict(2)
	ecsDict.SetKey(starlark.String("list_clusters"), starlark.NewBuiltin("list_clusters", awsECSListClusters))
	ecsDict.SetKey(starlark.String("list_services"), starlark.NewBuiltin("list_services", awsECSListServices))

	lambdaDict := starlark.NewDict(2)
	lambdaDict.SetKey(starlark.String("list_functions"), starlark.NewBuiltin("list_functions", awsLambdaListFunctions))
	lambdaDict.SetKey(starlark.String("invoke"), starlark.NewBuiltin("invoke", awsLambdaInvoke))

	awsDict := starlark.NewDict(4)
	awsDict.SetKey(starlark.String("ec2"), ec2Dict)
	awsDict.SetKey(starlark.String("s3"), s3Dict)
	awsDict.SetKey(starlark.String("ecs"), ecsDict)
	awsDict.SetKey(starlark.String("lambda"), lambdaDict)

	env["aws"] = awsDict
}

func awsLoadConfig(region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	return config.LoadDefaultConfig(context.Background(), opts...)
}

// ── EC2 ──────────────────────────────────────────────────────────────────────

func awsEC2ListInstances(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region, state string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region, "state?", &state); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	client := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{}
	if state != "" {
		input.Filters = []ec2types.Filter{{
			Name:   aws.String("instance-state-name"),
			Values: []string{state},
		}}
	}

	out, err := client.DescribeInstances(context.Background(), input)
	if err != nil {
		return nil, fmt.Errorf("aws.ec2.list_instances: %v", err)
	}

	var results []starlark.Value
	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			tags := make(map[string]string)
			for _, t := range inst.Tags {
				tags[strDeref(t.Key)] = strDeref(t.Value)
			}
			results = append(results, makeDict(
				"id", strDeref(inst.InstanceId),
				"type", string(inst.InstanceType),
				"state", string(inst.State.Name),
				"public_ip", strDeref(inst.PublicIpAddress),
				"private_ip", strDeref(inst.PrivateIpAddress),
				"image_id", strDeref(inst.ImageId),
				"tags", tags,
			))
		}
	}
	return starlark.NewList(results), nil
}

func awsEC2StartInstance(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	_, err = ec2.NewFromConfig(cfg).StartInstances(context.Background(), &ec2.StartInstancesInput{
		InstanceIds: []string{id},
	})
	if err != nil {
		return nil, fmt.Errorf("aws.ec2.start_instance: %v", err)
	}
	return starlark.String("started"), nil
}

func awsEC2StopInstance(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	_, err = ec2.NewFromConfig(cfg).StopInstances(context.Background(), &ec2.StopInstancesInput{
		InstanceIds: []string{id},
	})
	if err != nil {
		return nil, fmt.Errorf("aws.ec2.stop_instance: %v", err)
	}
	return starlark.String("stopped"), nil
}

func awsEC2TerminateInstance(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	_, err = ec2.NewFromConfig(cfg).TerminateInstances(context.Background(), &ec2.TerminateInstancesInput{
		InstanceIds: []string{id},
	})
	if err != nil {
		return nil, fmt.Errorf("aws.ec2.terminate_instance: %v", err)
	}
	return starlark.String("terminated"), nil
}

// ── S3 ───────────────────────────────────────────────────────────────────────

func awsS3ListBuckets(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	out, err := s3.NewFromConfig(cfg).ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.s3.list_buckets: %v", err)
	}
	var results []starlark.Value
	for _, b := range out.Buckets {
		results = append(results, makeDict("name", strDeref(b.Name)))
	}
	return starlark.NewList(results), nil
}

func awsS3PutObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var bucket, key, body, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "bucket", &bucket, "key", &key, "body", &body, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	_, err = s3.NewFromConfig(cfg).PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(body)),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.s3.put_object: %v", err)
	}
	return starlark.String("ok"), nil
}

func awsS3GetObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var bucket, key, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "bucket", &bucket, "key", &key, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	out, err := s3.NewFromConfig(cfg).GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.s3.get_object: %v", err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("aws.s3.get_object read: %v", err)
	}
	return starlark.String(string(data)), nil
}

func awsS3DeleteObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var bucket, key, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "bucket", &bucket, "key", &key, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	_, err = s3.NewFromConfig(cfg).DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.s3.delete_object: %v", err)
	}
	return starlark.String("deleted"), nil
}

// ── ECS ──────────────────────────────────────────────────────────────────────

func awsECSListClusters(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	out, err := ecs.NewFromConfig(cfg).ListClusters(context.Background(), &ecs.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.ecs.list_clusters: %v", err)
	}
	return toStarlark(out.ClusterArns), nil
}

func awsECSListServices(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var cluster, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cluster", &cluster, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	out, err := ecs.NewFromConfig(cfg).ListServices(context.Background(), &ecs.ListServicesInput{
		Cluster: aws.String(cluster),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.ecs.list_services: %v", err)
	}
	return toStarlark(out.ServiceArns), nil
}

// ── Lambda ───────────────────────────────────────────────────────────────────

func awsLambdaListFunctions(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	out, err := lambda.NewFromConfig(cfg).ListFunctions(context.Background(), &lambda.ListFunctionsInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.lambda.list_functions: %v", err)
	}
	var results []starlark.Value
	for _, f := range out.Functions {
		results = append(results, makeDict(
			"name", strDeref(f.FunctionName),
			"runtime", string(f.Runtime),
			"handler", strDeref(f.Handler),
			"description", strDeref(f.Description),
			"arn", strDeref(f.FunctionArn),
		))
	}
	return starlark.NewList(results), nil
}

func awsLambdaInvoke(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var function, payload, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "function", &function, "payload?", &payload, "region?", &region); err != nil {
		return nil, err
	}
	if payload == "" {
		payload = "{}"
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, fmt.Errorf("aws: %v", err)
	}
	out, err := lambda.NewFromConfig(cfg).Invoke(context.Background(), &lambda.InvokeInput{
		FunctionName: aws.String(function),
		Payload:      []byte(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.lambda.invoke: %v", err)
	}
	return makeDict(
		"status_code", int64(out.StatusCode),
		"payload", string(out.Payload),
		"function_error", strDeref(out.FunctionError),
	), nil
}
