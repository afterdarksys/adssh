package starlarkext

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.starlark.net/starlark"
)

// ExpandAWSAPI adds rds, eks, iam, sqs, ecr sub-namespaces to the existing
// aws.* dict registered by SetupAWSAPI.
//
//	aws.rds.list_instances(region="")
//	aws.rds.describe_instance(id="db-xxx", region="")
//	aws.rds.start_instance(id="db-xxx", region="")
//	aws.rds.stop_instance(id="db-xxx", region="")
//	aws.eks.list_clusters(region="")
//	aws.eks.describe_cluster(name="my-cluster", region="")
//	aws.iam.list_users()
//	aws.iam.list_roles()
//	aws.iam.get_caller_identity()
//	aws.sqs.list_queues(region="", prefix="")
//	aws.sqs.send_message(url="", body="", region="")
//	aws.sqs.receive_messages(url="", max=10, region="")
//	aws.sqs.delete_message(url="", handle="", region="")
//	aws.ecr.list_repos(region="")
//	aws.ecr.get_login_token(region="")
//	aws.ecr.describe_images(repo="", region="")
func ExpandAWSAPI(env starlark.StringDict) {
	awsVal, ok := env["aws"]
	if !ok {
		return
	}
	awsDict, ok := awsVal.(*starlark.Dict)
	if !ok {
		return
	}

	rdsDict := starlark.NewDict(4)
	rdsDict.SetKey(starlark.String("list_instances"), starlark.NewBuiltin("list_instances", awsRDSListInstances))
	rdsDict.SetKey(starlark.String("describe_instance"), starlark.NewBuiltin("describe_instance", awsRDSDescribeInstance))
	rdsDict.SetKey(starlark.String("start_instance"), starlark.NewBuiltin("start_instance", awsRDSStartInstance))
	rdsDict.SetKey(starlark.String("stop_instance"), starlark.NewBuiltin("stop_instance", awsRDSStopInstance))
	awsDict.SetKey(starlark.String("rds"), rdsDict)

	eksDict := starlark.NewDict(2)
	eksDict.SetKey(starlark.String("list_clusters"), starlark.NewBuiltin("list_clusters", awsEKSListClusters))
	eksDict.SetKey(starlark.String("describe_cluster"), starlark.NewBuiltin("describe_cluster", awsEKSDescribeCluster))
	awsDict.SetKey(starlark.String("eks"), eksDict)

	iamDict := starlark.NewDict(3)
	iamDict.SetKey(starlark.String("list_users"), starlark.NewBuiltin("list_users", awsIAMListUsers))
	iamDict.SetKey(starlark.String("list_roles"), starlark.NewBuiltin("list_roles", awsIAMListRoles))
	iamDict.SetKey(starlark.String("get_caller_identity"), starlark.NewBuiltin("get_caller_identity", awsIAMGetCallerIdentity))
	awsDict.SetKey(starlark.String("iam"), iamDict)

	sqsDict := starlark.NewDict(4)
	sqsDict.SetKey(starlark.String("list_queues"), starlark.NewBuiltin("list_queues", awsSQSListQueues))
	sqsDict.SetKey(starlark.String("send_message"), starlark.NewBuiltin("send_message", awsSQSSendMessage))
	sqsDict.SetKey(starlark.String("receive_messages"), starlark.NewBuiltin("receive_messages", awsSQSReceiveMessages))
	sqsDict.SetKey(starlark.String("delete_message"), starlark.NewBuiltin("delete_message", awsSQSDeleteMessage))
	awsDict.SetKey(starlark.String("sqs"), sqsDict)

	ecrDict := starlark.NewDict(3)
	ecrDict.SetKey(starlark.String("list_repos"), starlark.NewBuiltin("list_repos", awsECRListRepos))
	ecrDict.SetKey(starlark.String("get_login_token"), starlark.NewBuiltin("get_login_token", awsECRGetLoginToken))
	ecrDict.SetKey(starlark.String("describe_images"), starlark.NewBuiltin("describe_images", awsECRDescribeImages))
	awsDict.SetKey(starlark.String("ecr"), ecrDict)
}

// ── RDS ───────────────────────────────────────────────────────────────────────

func awsRDSListInstances(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := rds.NewFromConfig(cfg).DescribeDBInstances(context.Background(), &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.rds.list_instances: %v", err)
	}
	result := starlark.NewList(nil)
	for _, db := range out.DBInstances {
		result.Append(rdsInstanceToDict(db))
	}
	return result, nil
}

func awsRDSDescribeInstance(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := rds.NewFromConfig(cfg).DescribeDBInstances(context.Background(), &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(id),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.rds.describe_instance: %v", err)
	}
	if len(out.DBInstances) == 0 {
		return starlark.None, nil
	}
	return rdsInstanceToDict(out.DBInstances[0]), nil
}

func awsRDSStartInstance(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	if _, err := rds.NewFromConfig(cfg).StartDBInstance(context.Background(), &rds.StartDBInstanceInput{
		DBInstanceIdentifier: aws.String(id),
	}); err != nil {
		return nil, fmt.Errorf("aws.rds.start_instance: %v", err)
	}
	return starlark.String("starting"), nil
}

func awsRDSStopInstance(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	if _, err := rds.NewFromConfig(cfg).StopDBInstance(context.Background(), &rds.StopDBInstanceInput{
		DBInstanceIdentifier: aws.String(id),
	}); err != nil {
		return nil, fmt.Errorf("aws.rds.stop_instance: %v", err)
	}
	return starlark.String("stopping"), nil
}

func rdsInstanceToDict(db rdstypes.DBInstance) *starlark.Dict {
	return makeDict(
		"id", strDeref(db.DBInstanceIdentifier),
		"class", strDeref(db.DBInstanceClass),
		"engine", strDeref(db.Engine),
		"engine_version", strDeref(db.EngineVersion),
		"status", strDeref(db.DBInstanceStatus),
		"multi_az", db.MultiAZ,
	)
}

// ── EKS ───────────────────────────────────────────────────────────────────────

func awsEKSListClusters(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := eks.NewFromConfig(cfg).ListClusters(context.Background(), &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.eks.list_clusters: %v", err)
	}
	return toStarlark(out.Clusters), nil
}

func awsEKSDescribeCluster(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := eks.NewFromConfig(cfg).DescribeCluster(context.Background(), &eks.DescribeClusterInput{
		Name: aws.String(name),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.eks.describe_cluster: %v", err)
	}
	c := out.Cluster
	return makeDict(
		"name", strDeref(c.Name),
		"arn", strDeref(c.Arn),
		"version", strDeref(c.Version),
		"status", string(c.Status),
		"endpoint", strDeref(c.Endpoint),
	), nil
}

// ── IAM ───────────────────────────────────────────────────────────────────────

func awsIAMListUsers(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cfg, err := awsLoadConfig("")
	if err != nil {
		return nil, err
	}
	out, err := iam.NewFromConfig(cfg).ListUsers(context.Background(), &iam.ListUsersInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.iam.list_users: %v", err)
	}
	result := starlark.NewList(nil)
	for _, u := range out.Users {
		result.Append(makeDict("name", strDeref(u.UserName), "arn", strDeref(u.Arn), "id", strDeref(u.UserId)))
	}
	return result, nil
}

func awsIAMListRoles(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cfg, err := awsLoadConfig("")
	if err != nil {
		return nil, err
	}
	out, err := iam.NewFromConfig(cfg).ListRoles(context.Background(), &iam.ListRolesInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.iam.list_roles: %v", err)
	}
	result := starlark.NewList(nil)
	for _, r := range out.Roles {
		result.Append(makeDict("name", strDeref(r.RoleName), "arn", strDeref(r.Arn), "id", strDeref(r.RoleId)))
	}
	return result, nil
}

func awsIAMGetCallerIdentity(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cfg, err := awsLoadConfig("")
	if err != nil {
		return nil, err
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.iam.get_caller_identity: %v", err)
	}
	return makeDict(
		"account", strDeref(out.Account),
		"arn", strDeref(out.Arn),
		"user_id", strDeref(out.UserId),
	), nil
}

// ── SQS ───────────────────────────────────────────────────────────────────────

func awsSQSListQueues(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region, prefix string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region, "prefix?", &prefix); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	input := &sqs.ListQueuesInput{}
	if prefix != "" {
		input.QueueNamePrefix = aws.String(prefix)
	}
	out, err := sqs.NewFromConfig(cfg).ListQueues(context.Background(), input)
	if err != nil {
		return nil, fmt.Errorf("aws.sqs.list_queues: %v", err)
	}
	return toStarlark(out.QueueUrls), nil
}

func awsSQSSendMessage(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url, body, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &url, "body", &body, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := sqs.NewFromConfig(cfg).SendMessage(context.Background(), &sqs.SendMessageInput{
		QueueUrl:    aws.String(url),
		MessageBody: aws.String(body),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.sqs.send_message: %v", err)
	}
	return starlark.String(strDeref(out.MessageId)), nil
}

func awsSQSReceiveMessages(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url, region string
	var max int = 10
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &url, "max?", &max, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := sqs.NewFromConfig(cfg).ReceiveMessage(context.Background(), &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(url),
		MaxNumberOfMessages: int32(max),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.sqs.receive_messages: %v", err)
	}
	result := starlark.NewList(nil)
	for _, m := range out.Messages {
		result.Append(makeDict("id", strDeref(m.MessageId), "body", strDeref(m.Body), "handle", strDeref(m.ReceiptHandle)))
	}
	return result, nil
}

func awsSQSDeleteMessage(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url, handle, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &url, "handle", &handle, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	if _, err := sqs.NewFromConfig(cfg).DeleteMessage(context.Background(), &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(url),
		ReceiptHandle: aws.String(handle),
	}); err != nil {
		return nil, fmt.Errorf("aws.sqs.delete_message: %v", err)
	}
	return starlark.None, nil
}

// ── ECR ───────────────────────────────────────────────────────────────────────

func awsECRListRepos(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := ecr.NewFromConfig(cfg).DescribeRepositories(context.Background(), &ecr.DescribeRepositoriesInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.ecr.list_repos: %v", err)
	}
	result := starlark.NewList(nil)
	for _, r := range out.Repositories {
		result.Append(makeDict("name", strDeref(r.RepositoryName), "uri", strDeref(r.RepositoryUri), "arn", strDeref(r.RepositoryArn)))
	}
	return result, nil
}

func awsECRGetLoginToken(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := ecr.NewFromConfig(cfg).GetAuthorizationToken(context.Background(), &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.ecr.get_login_token: %v", err)
	}
	result := starlark.NewList(nil)
	for _, d := range out.AuthorizationData {
		result.Append(makeDict("token", strDeref(d.AuthorizationToken), "endpoint", strDeref(d.ProxyEndpoint)))
	}
	return result, nil
}

func awsECRDescribeImages(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var repo, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "repo", &repo, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsLoadConfig(region)
	if err != nil {
		return nil, err
	}
	out, err := ecr.NewFromConfig(cfg).DescribeImages(context.Background(), &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repo),
	})
	if err != nil {
		return nil, fmt.Errorf("aws.ecr.describe_images: %v", err)
	}
	result := starlark.NewList(nil)
	for _, img := range out.ImageDetails {
		tags := make([]string, len(img.ImageTags))
		copy(tags, img.ImageTags)
		result.Append(makeDict("digest", strDeref(img.ImageDigest), "tags", tags, "size", img.ImageSizeInBytes))
	}
	return result, nil
}
