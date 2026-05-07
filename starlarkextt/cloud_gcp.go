package starlarkext

import (
	"context"
	"fmt"
	"io"
	"strings"

	"cloud.google.com/go/storage"
	"go.starlark.net/starlark"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
)

// SetupGCPAPI registers the gcp.* namespace into the Starlark environment.
//
// Starlark API:
//
//	gcp.compute.list_instances(project="my-project", zone="us-central1-a")
//	gcp.compute.start_instance(project="p", zone="z", name="n")
//	gcp.compute.stop_instance(project="p", zone="z", name="n")
//	gcp.storage.list_buckets(project="my-project")
//	gcp.storage.get_object(bucket="b", object="k")
//	gcp.storage.put_object(bucket="b", object="k", body="data")
//	gcp.storage.delete_object(bucket="b", object="k")
//
// Credentials: GOOGLE_APPLICATION_CREDENTIALS env var or Application Default
// Credentials (~/.config/gcloud/application_default_credentials.json).
func SetupGCPAPI(env starlark.StringDict) {
	computeDict := starlark.NewDict(3)
	computeDict.SetKey(starlark.String("list_instances"), starlark.NewBuiltin("list_instances", gcpComputeListInstances))
	computeDict.SetKey(starlark.String("start_instance"), starlark.NewBuiltin("start_instance", gcpComputeStartInstance))
	computeDict.SetKey(starlark.String("stop_instance"), starlark.NewBuiltin("stop_instance", gcpComputeStopInstance))

	storageDict := starlark.NewDict(4)
	storageDict.SetKey(starlark.String("list_buckets"), starlark.NewBuiltin("list_buckets", gcpStorageListBuckets))
	storageDict.SetKey(starlark.String("get_object"), starlark.NewBuiltin("get_object", gcpStorageGetObject))
	storageDict.SetKey(starlark.String("put_object"), starlark.NewBuiltin("put_object", gcpStoragePutObject))
	storageDict.SetKey(starlark.String("delete_object"), starlark.NewBuiltin("delete_object", gcpStorageDeleteObject))

	gcpDict := starlark.NewDict(2)
	gcpDict.SetKey(starlark.String("compute"), computeDict)
	gcpDict.SetKey(starlark.String("storage"), storageDict)

	env["gcp"] = gcpDict
}

// ── Compute ───────────────────────────────────────────────────────────────────

func gcpComputeListInstances(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, zone string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "zone?", &zone); err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.compute: %v", err)
	}

	var results []starlark.Value

	if zone != "" {
		list, err := svc.Instances.List(project, zone).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("gcp.compute.list_instances: %v", err)
		}
		for _, inst := range list.Items {
			results = append(results, gcpInstanceToStarlark(inst))
		}
	} else {
		// Aggregate across all zones
		agg, err := svc.Instances.AggregatedList(project).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("gcp.compute.list_instances: %v", err)
		}
		for _, items := range agg.Items {
			for _, inst := range items.Instances {
				results = append(results, gcpInstanceToStarlark(inst))
			}
		}
	}
	return starlark.NewList(results), nil
}

func gcpInstanceToStarlark(inst *compute.Instance) *starlark.Dict {
	status := inst.Status
	name := inst.Name
	machineType := inst.MachineType
	// MachineType is a full URL; extract the short name
	if idx := strings.LastIndex(machineType, "/"); idx >= 0 {
		machineType = machineType[idx+1:]
	}
	return makeDict(
		"name", name,
		"status", status,
		"machine_type", machineType,
		"zone", inst.Zone,
		"id", fmt.Sprintf("%d", inst.Id),
	)
}

func gcpComputeStartInstance(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, zone, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "zone", &zone, "name", &name); err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.compute: %v", err)
	}
	if _, err := svc.Instances.Start(project, zone, name).Context(ctx).Do(); err != nil {
		return nil, fmt.Errorf("gcp.compute.start_instance: %v", err)
	}
	return starlark.String("started"), nil
}

func gcpComputeStopInstance(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, zone, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "zone", &zone, "name", &name); err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.compute: %v", err)
	}
	if _, err := svc.Instances.Stop(project, zone, name).Context(ctx).Do(); err != nil {
		return nil, fmt.Errorf("gcp.compute.stop_instance: %v", err)
	}
	return starlark.String("stopped"), nil
}

// ── Cloud Storage ─────────────────────────────────────────────────────────────

func gcpStorageListBuckets(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project); err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.storage: %v", err)
	}
	defer client.Close()

	var results []starlark.Value
	it := client.Buckets(ctx, project)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gcp.storage.list_buckets: %v", err)
		}
		results = append(results, makeDict("name", attrs.Name, "location", attrs.Location))
	}
	return starlark.NewList(results), nil
}

func gcpStorageGetObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var bucket, object string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "bucket", &bucket, "object", &object); err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.storage: %v", err)
	}
	defer client.Close()

	rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.storage.get_object: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("gcp.storage.get_object read: %v", err)
	}
	return starlark.String(string(data)), nil
}

func gcpStoragePutObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var bucket, object, body string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "bucket", &bucket, "object", &object, "body", &body); err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.storage: %v", err)
	}
	defer client.Close()

	wc := client.Bucket(bucket).Object(object).NewWriter(ctx)
	if _, err := io.Copy(wc, strings.NewReader(body)); err != nil {
		wc.Close()
		return nil, fmt.Errorf("gcp.storage.put_object: %v", err)
	}
	if err := wc.Close(); err != nil {
		return nil, fmt.Errorf("gcp.storage.put_object close: %v", err)
	}
	return starlark.String("ok"), nil
}

func gcpStorageDeleteObject(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var bucket, object string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "bucket", &bucket, "object", &object); err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.storage: %v", err)
	}
	defer client.Close()
	if err := client.Bucket(bucket).Object(object).Delete(ctx); err != nil {
		return nil, fmt.Errorf("gcp.storage.delete_object: %v", err)
	}
	return starlark.String("deleted"), nil
}
