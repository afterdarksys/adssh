package starlarkext

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"google.golang.org/api/option"
	gsmv1 "google.golang.org/api/secretmanager/v1"

	"go.starlark.net/starlark"
)

// SetupSecretsAPI registers the secrets.* namespace into the Starlark environment.
//
// Starlark API:
//
//	# HashiCorp Vault (addr/token from VAULT_ADDR / VAULT_TOKEN if not provided)
//	val = secrets.vault.read(path="secret/data/myapp")
//	secrets.vault.write(path="secret/data/myapp", data={"key":"val"})
//	keys = secrets.vault.list(path="secret/metadata/myapp/")
//	secrets.vault.delete(path="secret/data/myapp")
//
//	# AWS Secrets Manager
//	val = secrets.aws.get(name="myapp/prod", region="us-east-1")
//	secrets.aws.put(name="myapp/prod", value="...", region="us-east-1")
//	secrets.aws.delete(name="myapp/prod", region="us-east-1")
//
//	# Azure Key Vault
//	val = secrets.az.get(vault="myvault", name="my-secret")
//	secrets.az.set(vault="myvault", name="my-secret", value="...")
//	secrets.az.delete(vault="myvault", name="my-secret")
//
//	# GCP Secret Manager
//	val = secrets.gcp.get(project="my-project", name="MY_SECRET", version="latest")
//	secrets.gcp.create(project="my-project", name="MY_SECRET", value="...")
func SetupSecretsAPI(env starlark.StringDict) {
	vaultDict := starlark.NewDict(4)
	vaultDict.SetKey(starlark.String("read"), starlark.NewBuiltin("read", secretsVaultRead))
	vaultDict.SetKey(starlark.String("write"), starlark.NewBuiltin("write", secretsVaultWrite))
	vaultDict.SetKey(starlark.String("list"), starlark.NewBuiltin("list", secretsVaultList))
	vaultDict.SetKey(starlark.String("delete"), starlark.NewBuiltin("delete", secretsVaultDelete))

	awsDict := starlark.NewDict(3)
	awsDict.SetKey(starlark.String("get"), starlark.NewBuiltin("get", secretsAWSGet))
	awsDict.SetKey(starlark.String("put"), starlark.NewBuiltin("put", secretsAWSPut))
	awsDict.SetKey(starlark.String("delete"), starlark.NewBuiltin("delete", secretsAWSDelete))

	azDict := starlark.NewDict(3)
	azDict.SetKey(starlark.String("get"), starlark.NewBuiltin("get", secretsAzGet))
	azDict.SetKey(starlark.String("set"), starlark.NewBuiltin("set", secretsAzSet))
	azDict.SetKey(starlark.String("delete"), starlark.NewBuiltin("delete", secretsAzDelete))

	gcpDict := starlark.NewDict(2)
	gcpDict.SetKey(starlark.String("get"), starlark.NewBuiltin("get", secretsGCPGet))
	gcpDict.SetKey(starlark.String("create"), starlark.NewBuiltin("create", secretsGCPCreate))

	d := starlark.NewDict(4)
	d.SetKey(starlark.String("vault"), vaultDict)
	d.SetKey(starlark.String("aws"), awsDict)
	d.SetKey(starlark.String("az"), azDict)
	d.SetKey(starlark.String("gcp"), gcpDict)
	env["secrets"] = d
}

// ── Vault ─────────────────────────────────────────────────────────────────────

func vaultClient(addr, token string) (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	if addr != "" {
		cfg.Address = addr
	}
	// else uses VAULT_ADDR env var
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault: %v", err)
	}
	if token != "" {
		client.SetToken(token)
	}
	// else uses VAULT_TOKEN env var (already handled by DefaultConfig)
	return client, nil
}

func secretsVaultRead(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, addr, token string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path, "addr?", &addr, "token?", &token); err != nil {
		return nil, err
	}
	client, err := vaultClient(addr, token)
	if err != nil {
		return nil, err
	}
	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("secrets.vault.read: %v", err)
	}
	if secret == nil {
		return starlark.None, nil
	}
	return toStarlark(secret.Data), nil
}

func secretsVaultWrite(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, addr, token string
	var data *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path, "data", &data, "addr?", &addr, "token?", &token); err != nil {
		return nil, err
	}
	client, err := vaultClient(addr, token)
	if err != nil {
		return nil, err
	}
	goData := starlarkDictToGo(data)
	if _, err := client.Logical().Write(path, goData); err != nil {
		return nil, fmt.Errorf("secrets.vault.write: %v", err)
	}
	return starlark.None, nil
}

func secretsVaultList(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, addr, token string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path, "addr?", &addr, "token?", &token); err != nil {
		return nil, err
	}
	client, err := vaultClient(addr, token)
	if err != nil {
		return nil, err
	}
	secret, err := client.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("secrets.vault.list: %v", err)
	}
	if secret == nil || secret.Data == nil {
		return starlark.NewList(nil), nil
	}
	if keys, ok := secret.Data["keys"]; ok {
		return toStarlark(keys), nil
	}
	return starlark.NewList(nil), nil
}

func secretsVaultDelete(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, addr, token string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path, "addr?", &addr, "token?", &token); err != nil {
		return nil, err
	}
	client, err := vaultClient(addr, token)
	if err != nil {
		return nil, err
	}
	if _, err := client.Logical().Delete(path); err != nil {
		return nil, fmt.Errorf("secrets.vault.delete: %v", err)
	}
	return starlark.None, nil
}

// ── AWS Secrets Manager ───────────────────────────────────────────────────────

func secretsAWSGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("secrets.aws.get: %v", err)
	}
	out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(name),
	})
	if err != nil {
		return nil, fmt.Errorf("secrets.aws.get: %v", err)
	}
	if out.SecretString != nil {
		return starlark.String(*out.SecretString), nil
	}
	if out.SecretBinary != nil {
		return starlark.String(base64.StdEncoding.EncodeToString(out.SecretBinary)), nil
	}
	return starlark.None, nil
}

func secretsAWSPut(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, value, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "value", &value, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("secrets.aws.put: %v", err)
	}
	svc := secretsmanager.NewFromConfig(cfg)
	// Try update first, fall back to create
	_, err = svc.PutSecretValue(context.Background(), &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(name),
		SecretString: aws.String(value),
	})
	if err != nil {
		// If it doesn't exist, create it
		if _, cerr := svc.CreateSecret(context.Background(), &secretsmanager.CreateSecretInput{
			Name:         aws.String(name),
			SecretString: aws.String(value),
		}); cerr != nil {
			return nil, fmt.Errorf("secrets.aws.put: %v", err)
		}
	}
	return starlark.None, nil
}

func secretsAWSDelete(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, region string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "region?", &region); err != nil {
		return nil, err
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("secrets.aws.delete: %v", err)
	}
	if _, err := secretsmanager.NewFromConfig(cfg).DeleteSecret(context.Background(), &secretsmanager.DeleteSecretInput{
		SecretId: aws.String(name),
	}); err != nil {
		return nil, fmt.Errorf("secrets.aws.delete: %v", err)
	}
	return starlark.None, nil
}

// ── Azure Key Vault ───────────────────────────────────────────────────────────

func azKVClient(vault string) (*azsecrets.Client, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("secrets.az: credential: %v", err)
	}
	url := fmt.Sprintf("https://%s.vault.azure.net", vault)
	client, err := azsecrets.NewClient(url, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets.az: %v", err)
	}
	return client, nil
}

func secretsAzGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var vault, name, version string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "vault", &vault, "name", &name, "version?", &version); err != nil {
		return nil, err
	}
	client, err := azKVClient(vault)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetSecret(context.Background(), name, version, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets.az.get: %v", err)
	}
	if resp.Value != nil {
		return starlark.String(*resp.Value), nil
	}
	return starlark.None, nil
}

func secretsAzSet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var vault, name, value string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "vault", &vault, "name", &name, "value", &value); err != nil {
		return nil, err
	}
	client, err := azKVClient(vault)
	if err != nil {
		return nil, err
	}
	params := azsecrets.SetSecretParameters{Value: &value}
	if _, err := client.SetSecret(context.Background(), name, params, nil); err != nil {
		return nil, fmt.Errorf("secrets.az.set: %v", err)
	}
	return starlark.None, nil
}

func secretsAzDelete(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var vault, name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "vault", &vault, "name", &name); err != nil {
		return nil, err
	}
	client, err := azKVClient(vault)
	if err != nil {
		return nil, err
	}
	if _, err := client.DeleteSecret(context.Background(), name, nil); err != nil {
		return nil, fmt.Errorf("secrets.az.delete: %v", err)
	}
	return starlark.None, nil
}

// ── GCP Secret Manager ────────────────────────────────────────────────────────

func gcpSMService() (*gsmv1.Service, error) {
	ctx := context.Background()
	opts := []option.ClientOption{}
	if sa := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); sa != "" {
		opts = append(opts, option.WithCredentialsFile(sa))
	}
	svc, err := gsmv1.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("secrets.gcp: %v", err)
	}
	return svc, nil
}

func secretsGCPGet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, name, version string
	version = "latest"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "name", &name, "version?", &version); err != nil {
		return nil, err
	}
	svc, err := gcpSMService()
	if err != nil {
		return nil, err
	}
	resourceName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", project, name, version)
	resp, err := svc.Projects.Secrets.Versions.Access(resourceName).Context(context.Background()).Do()
	if err != nil {
		return nil, fmt.Errorf("secrets.gcp.get: %v", err)
	}
	data, err := base64.StdEncoding.DecodeString(resp.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("secrets.gcp.get decode: %v", err)
	}
	return starlark.String(string(data)), nil
}

func secretsGCPCreate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var project, name, value string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "project", &project, "name", &name, "value", &value); err != nil {
		return nil, err
	}
	svc, err := gcpSMService()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	parent := fmt.Sprintf("projects/%s", project)
	// Create the secret (may already exist — ignore error)
	svc.Projects.Secrets.Create(parent, &gsmv1.Secret{
		Replication: &gsmv1.Replication{Automatic: &gsmv1.Automatic{}},
	}).SecretId(name).Context(ctx).Do()

	// Add a new version
	secretName := fmt.Sprintf("projects/%s/secrets/%s", project, name)
	_, err = svc.Projects.Secrets.AddVersion(secretName, &gsmv1.AddSecretVersionRequest{
		Payload: &gsmv1.SecretPayload{
			Data: base64.StdEncoding.EncodeToString([]byte(value)),
		},
	}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("secrets.gcp.create: %v", err)
	}
	return starlark.None, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// starlarkDictToGo converts a *starlark.Dict to map[string]interface{}.
func starlarkDictToGo(d *starlark.Dict) map[string]interface{} {
	if d == nil {
		return nil
	}
	out := make(map[string]interface{}, d.Len())
	for _, kv := range d.Items() {
		k, _ := starlark.AsString(kv[0])
		out[k] = starlarkValueToGo(kv[1])
	}
	return out
}

// starlarkValueToGo converts any Starlark value to a Go interface{} suitable
// for JSON encoding.
func starlarkValueToGo(v starlark.Value) interface{} {
	switch val := v.(type) {
	case starlark.NoneType:
		return nil
	case starlark.Bool:
		return bool(val)
	case starlark.Int:
		i, _ := val.Int64()
		return i
	case starlark.Float:
		return float64(val)
	case starlark.String:
		return string(val)
	case *starlark.Dict:
		return starlarkDictToGo(val)
	case *starlark.List:
		out := make([]interface{}, val.Len())
		for i := 0; i < val.Len(); i++ {
			out[i] = starlarkValueToGo(val.Index(i))
		}
		return out
	default:
		return val.String()
	}
}
