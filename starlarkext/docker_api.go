package starlarkext

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types/container"
	dockerimage "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	dockervolume "github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"go.starlark.net/starlark"
)

// SetupDockerAPI registers the docker.* namespace into the Starlark environment.
//
// This namespace provides direct Docker Engine API access for image, network,
// volume, and container management. For audited ephemeral container execution
// see the existing containers.* namespace.
//
// Starlark API:
//
//	docker.ps(all=False)                            # list containers
//	docker.inspect(id)                             # inspect a container
//	docker.logs(id, tail=100)                      # fetch container logs
//
//	docker.images.list()
//	docker.images.pull(ref, platform="")
//	docker.images.remove(id, force=False)
//
//	docker.networks.list()
//	docker.networks.create(name, driver="bridge")
//	docker.networks.remove(id)
//
//	docker.volumes.list()
//	docker.volumes.create(name)
//	docker.volumes.remove(name, force=False)
func SetupDockerAPI(env starlark.StringDict) {
	imagesDict := starlark.NewDict(3)
	imagesDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", dockerImagesList))
	imagesDict.SetKey(starlark.String("pull"), starlark.NewBuiltin("pull", dockerImagesPull))
	imagesDict.SetKey(starlark.String("remove"), starlark.NewBuiltin("remove", dockerImagesRemove))

	networksDict := starlark.NewDict(3)
	networksDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", dockerNetworksList))
	networksDict.SetKey(starlark.String("create"), starlark.NewBuiltin("create", dockerNetworksCreate))
	networksDict.SetKey(starlark.String("remove"), starlark.NewBuiltin("remove", dockerNetworksRemove))

	volumesDict := starlark.NewDict(3)
	volumesDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", dockerVolumesList))
	volumesDict.SetKey(starlark.String("create"), starlark.NewBuiltin("create", dockerVolumesCreate))
	volumesDict.SetKey(starlark.String("remove"), starlark.NewBuiltin("remove", dockerVolumesRemove))

	dockerDict := starlark.NewDict(6)
	dockerDict.SetKey(starlark.String("ps"), starlark.NewBuiltin("ps", dockerPS))
	dockerDict.SetKey(starlark.String("inspect"), starlark.NewBuiltin("inspect", dockerInspect))
	dockerDict.SetKey(starlark.String("logs"), starlark.NewBuiltin("logs", dockerLogs))
	dockerDict.SetKey(starlark.String("images"), imagesDict)
	dockerDict.SetKey(starlark.String("networks"), networksDict)
	dockerDict.SetKey(starlark.String("volumes"), volumesDict)
	env["docker"] = dockerDict
}

func newDockerClient() (*client.Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker: %v", err)
	}
	return cli, nil
}

// ── Containers ────────────────────────────────────────────────────────────────

func dockerPS(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var all bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "all?", &all); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(context.Background(), container.ListOptions{All: all})
	if err != nil {
		return nil, fmt.Errorf("docker.ps: %v", err)
	}
	result := starlark.NewList(nil)
	for _, c := range containers {
		d := starlark.NewDict(5)
		id := c.ID
		if len(id) > 12 {
			id = id[:12]
		}
		d.SetKey(starlark.String("id"), starlark.String(id))
		d.SetKey(starlark.String("image"), starlark.String(c.Image))
		d.SetKey(starlark.String("status"), starlark.String(c.Status))
		d.SetKey(starlark.String("state"), starlark.String(c.State))
		names := starlark.NewList(nil)
		for _, n := range c.Names {
			names.Append(starlark.String(strings.TrimPrefix(n, "/")))
		}
		d.SetKey(starlark.String("names"), names)
		result.Append(d)
	}
	return result, nil
}

func dockerInspect(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	info, _, err := cli.ContainerInspectWithRaw(context.Background(), id, false)
	if err != nil {
		return nil, fmt.Errorf("docker.inspect: %v", err)
	}
	d := starlark.NewDict(6)
	d.SetKey(starlark.String("id"), starlark.String(info.ID))
	d.SetKey(starlark.String("name"), starlark.String(strings.TrimPrefix(info.Name, "/")))
	if info.Config != nil {
		d.SetKey(starlark.String("image"), starlark.String(info.Config.Image))
	}
	if info.State != nil {
		d.SetKey(starlark.String("status"), starlark.String(info.State.Status))
		d.SetKey(starlark.String("running"), starlark.Bool(info.State.Running))
		d.SetKey(starlark.String("started_at"), starlark.String(info.State.StartedAt))
	}
	return d, nil
}

func dockerLogs(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	var tail int = 100
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "tail?", &tail); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	rc, err := cli.ContainerLogs(context.Background(), id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", tail),
	})
	if err != nil {
		return nil, fmt.Errorf("docker.logs: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("docker.logs: %v", err)
	}
	return starlark.String(string(data)), nil
}

// ── Images ────────────────────────────────────────────────────────────────────

func dockerImagesList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	images, err := cli.ImageList(context.Background(), dockerimage.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker.images.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, img := range images {
		d := starlark.NewDict(4)
		d.SetKey(starlark.String("id"), starlark.String(img.ID))
		d.SetKey(starlark.String("size"), starlark.MakeInt64(img.Size))
		d.SetKey(starlark.String("created"), starlark.MakeInt64(img.Created))
		tags := starlark.NewList(nil)
		for _, t := range img.RepoTags {
			tags.Append(starlark.String(t))
		}
		d.SetKey(starlark.String("tags"), tags)
		result.Append(d)
	}
	return result, nil
}

func dockerImagesPull(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ref, platform string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ref", &ref, "platform?", &platform); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	opts := dockerimage.PullOptions{}
	if platform != "" {
		opts.Platform = platform
	}
	rc, err := cli.ImagePull(context.Background(), ref, opts)
	if err != nil {
		return nil, fmt.Errorf("docker.images.pull: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("docker.images.pull: %v", err)
	}
	return starlark.String(string(data)), nil
}

func dockerImagesRemove(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	var force bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "force?", &force); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	_, err = cli.ImageRemove(context.Background(), id, dockerimage.RemoveOptions{Force: force})
	if err != nil {
		return nil, fmt.Errorf("docker.images.remove: %v", err)
	}
	return starlark.None, nil
}

// ── Networks ──────────────────────────────────────────────────────────────────

func dockerNetworksList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	nets, err := cli.NetworkList(context.Background(), network.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker.networks.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, n := range nets {
		d := starlark.NewDict(4)
		id := n.ID
		if len(id) > 12 {
			id = id[:12]
		}
		d.SetKey(starlark.String("id"), starlark.String(id))
		d.SetKey(starlark.String("name"), starlark.String(n.Name))
		d.SetKey(starlark.String("driver"), starlark.String(n.Driver))
		d.SetKey(starlark.String("scope"), starlark.String(n.Scope))
		result.Append(d)
	}
	return result, nil
}

func dockerNetworksCreate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	driver := "bridge"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "driver?", &driver); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	resp, err := cli.NetworkCreate(context.Background(), name, network.CreateOptions{Driver: driver})
	if err != nil {
		return nil, fmt.Errorf("docker.networks.create: %v", err)
	}
	d := starlark.NewDict(2)
	d.SetKey(starlark.String("id"), starlark.String(resp.ID))
	d.SetKey(starlark.String("warning"), starlark.String(resp.Warning))
	return d, nil
}

func dockerNetworksRemove(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	if err := cli.NetworkRemove(context.Background(), id); err != nil {
		return nil, fmt.Errorf("docker.networks.remove: %v", err)
	}
	return starlark.None, nil
}

// ── Volumes ───────────────────────────────────────────────────────────────────

func dockerVolumesList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	resp, err := cli.VolumeList(context.Background(), dockervolume.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker.volumes.list: %v", err)
	}
	result := starlark.NewList(nil)
	for _, v := range resp.Volumes {
		d := starlark.NewDict(3)
		d.SetKey(starlark.String("name"), starlark.String(v.Name))
		d.SetKey(starlark.String("driver"), starlark.String(v.Driver))
		d.SetKey(starlark.String("mountpoint"), starlark.String(v.Mountpoint))
		result.Append(d)
	}
	return result, nil
}

func dockerVolumesCreate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	vol, err := cli.VolumeCreate(context.Background(), dockervolume.CreateOptions{Name: name})
	if err != nil {
		return nil, fmt.Errorf("docker.volumes.create: %v", err)
	}
	d := starlark.NewDict(3)
	d.SetKey(starlark.String("name"), starlark.String(vol.Name))
	d.SetKey(starlark.String("driver"), starlark.String(vol.Driver))
	d.SetKey(starlark.String("mountpoint"), starlark.String(vol.Mountpoint))
	return d, nil
}

func dockerVolumesRemove(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var force bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "force?", &force); err != nil {
		return nil, err
	}
	cli, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	if err := cli.VolumeRemove(context.Background(), name, force); err != nil {
		return nil, fmt.Errorf("docker.volumes.remove: %v", err)
	}
	return starlark.None, nil
}
