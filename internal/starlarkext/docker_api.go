package starlarkext

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// SetupDockerAPI registers the docker.* namespace into the Starlark environment.
//
// Docker access is implemented through the docker CLI instead of the Docker Go
// SDK so adssh does not link vulnerable Moby daemon packages into its binaries.
func SetupDockerAPI(env starlark.StringDict) {
	imagesDict := starlark.NewDict(3)
	_ = imagesDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", dockerImagesList))
	_ = imagesDict.SetKey(starlark.String("pull"), starlark.NewBuiltin("pull", dockerImagesPull))
	_ = imagesDict.SetKey(starlark.String("remove"), starlark.NewBuiltin("remove", dockerImagesRemove))

	networksDict := starlark.NewDict(3)
	_ = networksDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", dockerNetworksList))
	_ = networksDict.SetKey(starlark.String("create"), starlark.NewBuiltin("create", dockerNetworksCreate))
	_ = networksDict.SetKey(starlark.String("remove"), starlark.NewBuiltin("remove", dockerNetworksRemove))

	volumesDict := starlark.NewDict(3)
	_ = volumesDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", dockerVolumesList))
	_ = volumesDict.SetKey(starlark.String("create"), starlark.NewBuiltin("create", dockerVolumesCreate))
	_ = volumesDict.SetKey(starlark.String("remove"), starlark.NewBuiltin("remove", dockerVolumesRemove))

	dockerDict := starlark.NewDict(6)
	_ = dockerDict.SetKey(starlark.String("ps"), starlark.NewBuiltin("ps", dockerPS))
	_ = dockerDict.SetKey(starlark.String("inspect"), starlark.NewBuiltin("inspect", dockerInspect))
	_ = dockerDict.SetKey(starlark.String("logs"), starlark.NewBuiltin("logs", dockerLogs))
	_ = dockerDict.SetKey(starlark.String("images"), imagesDict)
	_ = dockerDict.SetKey(starlark.String("networks"), networksDict)
	_ = dockerDict.SetKey(starlark.String("volumes"), volumesDict)
	env["docker"] = dockerDict
}

func dockerCLI(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("docker %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func dockerJSONLines(args ...string) (starlark.Value, error) {
	out, err := dockerCLI(context.Background(), args...)
	if err != nil {
		return nil, err
	}
	result := starlark.NewList(nil)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var item interface{}
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return nil, fmt.Errorf("docker json: %v", err)
		}
		_ = result.Append(toStarlark(item))
	}
	return result, nil
}

func dockerJSON(args ...string) (starlark.Value, error) {
	out, err := dockerCLI(context.Background(), args...)
	if err != nil {
		return nil, err
	}
	var item interface{}
	if err := json.Unmarshal(out, &item); err != nil {
		return nil, fmt.Errorf("docker json: %v", err)
	}
	return toStarlark(item), nil
}

func dockerPS(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var all bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "all?", &all); err != nil {
		return nil, err
	}
	cmdArgs := []string{"ps", "--format", "{{json .}}"}
	if all {
		cmdArgs = []string{"ps", "-a", "--format", "{{json .}}"}
	}
	return dockerJSONLines(cmdArgs...)
}

func dockerInspect(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	return dockerJSON("inspect", id)
}

func dockerLogs(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	tail := 100
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "tail?", &tail); err != nil {
		return nil, err
	}
	out, err := dockerCLI(context.Background(), "logs", "--tail", strconv.Itoa(tail), id)
	if err != nil {
		return nil, err
	}
	return starlark.String(string(out)), nil
}

func dockerImagesList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return dockerJSONLines("images", "--format", "{{json .}}")
}

func dockerImagesPull(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ref, platform string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ref", &ref, "platform?", &platform); err != nil {
		return nil, err
	}
	cmdArgs := []string{"pull"}
	if platform != "" {
		cmdArgs = append(cmdArgs, "--platform", platform)
	}
	cmdArgs = append(cmdArgs, ref)
	out, err := dockerCLI(context.Background(), cmdArgs...)
	if err != nil {
		return nil, err
	}
	return starlark.String(string(out)), nil
}

func dockerImagesRemove(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	var force bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id, "force?", &force); err != nil {
		return nil, err
	}
	cmdArgs := []string{"rmi"}
	if force {
		cmdArgs = append(cmdArgs, "-f")
	}
	cmdArgs = append(cmdArgs, id)
	if _, err := dockerCLI(context.Background(), cmdArgs...); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func dockerNetworksList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return dockerJSONLines("network", "ls", "--format", "{{json .}}")
}

func dockerNetworksCreate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	driver := "bridge"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "driver?", &driver); err != nil {
		return nil, err
	}
	out, err := dockerCLI(context.Background(), "network", "create", "--driver", driver, name)
	if err != nil {
		return nil, err
	}
	return makeDict("id", strings.TrimSpace(string(out))), nil
}

func dockerNetworksRemove(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "id", &id); err != nil {
		return nil, err
	}
	if _, err := dockerCLI(context.Background(), "network", "rm", id); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func dockerVolumesList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return dockerJSONLines("volume", "ls", "--format", "{{json .}}")
}

func dockerVolumesCreate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	out, err := dockerCLI(context.Background(), "volume", "create", name)
	if err != nil {
		return nil, err
	}
	return makeDict("name", strings.TrimSpace(string(out))), nil
}

func dockerVolumesRemove(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var force bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "force?", &force); err != nil {
		return nil, err
	}
	cmdArgs := []string{"volume", "rm"}
	if force {
		cmdArgs = append(cmdArgs, "-f")
	}
	cmdArgs = append(cmdArgs, name)
	if _, err := dockerCLI(context.Background(), cmdArgs...); err != nil {
		return nil, err
	}
	return starlark.None, nil
}
