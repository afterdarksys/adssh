package devops

import (
	"fmt"
	"strings"
)

// GenerateCommand generates a raw CLI command from structured intents.
func GenerateCommand(provider, resource, action string, args map[string]string) (string, error) {
	switch provider {
	case "docker":
		return generateDocker(resource, action, args)
	case "kubectl":
		return generateKubectl(resource, action, args)
	case "aws":
		return generateAWS(resource, action, args)
	default:
		return "", fmt.Errorf("unknown cloud provider: %s", provider)
	}
}

func generateDocker(resource, action string, args map[string]string) (string, error) {
	if resource == "container" && action == "run" {
		cmd := []string{"docker", "run"}
		if val, ok := args["detach"]; ok && (val == "true" || val == "1") {
			cmd = append(cmd, "-d")
		}
		if val, ok := args["ports"]; ok {
			cmd = append(cmd, "-p", val)
		}
		if val, ok := args["name"]; ok {
			cmd = append(cmd, "--name", val)
		}
		if val, ok := args["image"]; ok {
			cmd = append(cmd, val)
		} else {
			return "", fmt.Errorf("docker run requires an 'image' argument")
		}
		return strings.Join(cmd, " "), nil
	}
	return "", fmt.Errorf("unsupported docker resource/action: %s/%s", resource, action)
}

func generateKubectl(resource, action string, args map[string]string) (string, error) {
	if resource == "pod" && action == "create" {
		cmd := []string{"kubectl", "run"}
		if val, ok := args["name"]; ok {
			cmd = append(cmd, val)
		} else {
			return "", fmt.Errorf("kubectl pod create requires a 'name' argument")
		}
		if val, ok := args["image"]; ok {
			cmd = append(cmd, "--image="+val)
		} else {
			return "", fmt.Errorf("kubectl pod create requires an 'image' argument")
		}
		if val, ok := args["port"]; ok {
			cmd = append(cmd, "--port="+val)
		}
		return strings.Join(cmd, " "), nil
	}
	return "", fmt.Errorf("unsupported kubectl resource/action: %s/%s", resource, action)
}

func generateAWS(resource, action string, args map[string]string) (string, error) {
	if resource == "ec2" && action == "create" {
		cmd := []string{"aws", "ec2", "run-instances"}
		if val, ok := args["image_id"]; ok {
			cmd = append(cmd, "--image-id", val)
		} else {
			return "", fmt.Errorf("aws ec2 create requires an 'image_id' argument")
		}
		if val, ok := args["type"]; ok {
			cmd = append(cmd, "--instance-type", val)
		}
		if val, ok := args["name"]; ok {
			cmd = append(cmd, "--tag-specifications", fmt.Sprintf("ResourceType=instance,Tags=[{Key=Name,Value=%s}]", val))
		}
		return strings.Join(cmd, " "), nil
	}
	return "", fmt.Errorf("unsupported aws resource/action: %s/%s", resource, action)
}
