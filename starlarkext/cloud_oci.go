package starlarkext

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"go.starlark.net/starlark"
)

// SetupOCIAPI registers the oci.* namespace into the Starlark environment.
//
// Starlark API:
//
//	oci.compute.list_instances(compartment_id="ocid1...")
//	oci.compute.start_instance(id="ocid1...")
//	oci.compute.stop_instance(id="ocid1...")
//	oci.storage.list_buckets(namespace="ns", compartment_id="ocid1...")
//	oci.storage.get_object(namespace="ns", bucket="b", name="k")
//	oci.storage.put_object(namespace="ns", bucket="b", name="k", body="data")
//	oci.storage.delete_object(namespace="ns", bucket="b", name="k")
//
// Credentials: ~/.oci/config (standard OCI CLI config)
func SetupOCIAPI(env starlark.StringDict) {
	computeDict := starlark.NewDict(3)
	computeDict.SetKey(starlark.String("list_instances"), starlark.NewBuiltin("list_instances", ociComputeListInstances))
	computeDict.SetKey(starlark.String("start_instance"), starlark.NewBuiltin("start_instance", ociComputeStartInstance))
	computeDict.SetKey(starlark.String("stop_instance"), starlark.NewBuiltin("stop_instance", ociComputeStopInstance))

	storageDict := starlark.NewDict(4)
	storageDict.SetKey(starlark.String("list_buckets"), starlark.NewBuiltin("list_buckets", ociStorageListBuckets))
	storageDict.SetKey(starlark.String("get_object"), starlark.NewBuiltin("get_object", ociStorageGetObject))
	storageDict.SetKey(starlark.String("put_object"), starlark.NewBuiltin("put_object", ociStoragePutObject))
	storageDict.SetKey(starlark.String("delete_object"), starlark.NewBuiltin("delete_object", ociStorageDeleteObject))

	ociDict := starlark.NewDict(2)
	ociDict.SetKey(starlark.String("compute"), computeDict)
	ociDict.SetKey(starlark.String("storage"), storageDict)

	env["oci"] = ociDict
}

// ── Compute ───────────────────────────────────────────────────────────────────

func ociComputeListInstances(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var compartmentID string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "compartment_id", &compartmentID); err != nil {
		return nil, err
	}
	client, err := core.NewComputeClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return nil, fmt.Errorf("oci.compute: %v", err)
	}
	resp, err := client.ListInstances(context.Background(), core.ListInstancesRequest{
		CompartmentId: &compartmentID,
	})
	if err != nil {
		return nil, fmt.Errorf("oci.compute.list_instances: %v", err)
	}
	var results []starlark.Value
	for _, inst := range resp.Items {
		results = append(results, makeDict(
			"id", strDeref(inst.Id),
			"display_name", strDeref(inst.DisplayName),
			"shape", strDeref(inst.Shape),
			"state", string(inst.LifecycleState),
			"region", strDeref(inst.Region),
			"availability_domain", strDeref(inst.AvailabilityDomain),
		))
	}
	return starlark.NewList(results), nil
}

func ociComputeStartInstance(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	client, err := core.NewComputeClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return nil, fmt.Errorf("oci.compute: %v", err)
	}
	action := core.InstanceActionActionStart
	_, err = client.InstanceAction(context.Background(), core.InstanceActionRequest{
		InstanceId: &id,
		Action:     action,
	})
	if err != nil {
		return nil, fmt.Errorf("oci.compute.start_instance: %v", err)
	}
	return starlark.String("started"), nil
}

func ociComputeStopInstance(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	client, err := core.NewComputeClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return nil, fmt.Errorf("oci.compute: %v", err)
	}
	action := core.InstanceActionActionSoftstop
	_, err = client.InstanceAction(context.Background(), core.InstanceActionRequest{
		InstanceId: &id,
		Action:     action,
	})
	if err != nil {
		return nil, fmt.Errorf("oci.compute.stop_instance: %v", err)
	}
	return starlark.String("stopped"), nil
}

// ── Object Storage ────────────────────────────────────────────────────────────

func ociStorageListBuckets(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace, compartmentID string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "namespace", &namespace, "compartment_id", &compartmentID); err != nil {
		return nil, err
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return nil, fmt.Errorf("oci.storage: %v", err)
	}
	resp, err := client.ListBuckets(context.Background(), objectstorage.ListBucketsRequest{
		NamespaceName: &namespace,
		CompartmentId: &compartmentID,
	})
	if err != nil {
		return nil, fmt.Errorf("oci.storage.list_buckets: %v", err)
	}
	var results []starlark.Value
	for _, bkt := range resp.Items {
		results = append(results, makeDict(
			"name", strDeref(bkt.Name),
			"namespace", strDeref(bkt.Namespace),
			"compartment_id", strDeref(bkt.CompartmentId),
		))
	}
	return starlark.NewList(results), nil
}

func ociStorageGetObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace, bucket, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "namespace", &namespace, "bucket", &bucket, "name", &name); err != nil {
		return nil, err
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return nil, fmt.Errorf("oci.storage: %v", err)
	}
	resp, err := client.GetObject(context.Background(), objectstorage.GetObjectRequest{
		NamespaceName: &namespace,
		BucketName:    &bucket,
		ObjectName:    &name,
	})
	if err != nil {
		return nil, fmt.Errorf("oci.storage.get_object: %v", err)
	}
	defer resp.Content.Close()
	data, err := io.ReadAll(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("oci.storage.get_object read: %v", err)
	}
	return starlark.String(string(data)), nil
}

func ociStoragePutObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace, bucket, name, body string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "namespace", &namespace, "bucket", &bucket, "name", &name, "body", &body); err != nil {
		return nil, err
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return nil, fmt.Errorf("oci.storage: %v", err)
	}
	contentLen := int64(len(body))
	_, err = client.PutObject(context.Background(), objectstorage.PutObjectRequest{
		NamespaceName: &namespace,
		BucketName:    &bucket,
		ObjectName:    &name,
		ContentLength: &contentLen,
		PutObjectBody: io.NopCloser(strings.NewReader(body)),
	})
	if err != nil {
		return nil, fmt.Errorf("oci.storage.put_object: %v", err)
	}
	return starlark.String("ok"), nil
}

func ociStorageDeleteObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace, bucket, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "namespace", &namespace, "bucket", &bucket, "name", &name); err != nil {
		return nil, err
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return nil, fmt.Errorf("oci.storage: %v", err)
	}
	_, err = client.DeleteObject(context.Background(), objectstorage.DeleteObjectRequest{
		NamespaceName: &namespace,
		BucketName:    &bucket,
		ObjectName:    &name,
	})
	if err != nil {
		return nil, fmt.Errorf("oci.storage.delete_object: %v", err)
	}
	return starlark.String("deleted"), nil
}
