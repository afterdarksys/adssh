package security

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	vaultapi "github.com/hashicorp/vault/api"
	"google.golang.org/api/option"
	gsmv1 "google.golang.org/api/secretmanager/v1"
)

func readVaultLeaseSecret(ctx context.Context, spec string) ([]byte, error) {
	path, query, err := parseLeaseSourceSpec(spec)
	if err != nil {
		return nil, err
	}
	field := query.Get("field")

	cfg := vaultapi.DefaultConfig()
	if addr := query.Get("addr"); addr != "" {
		cfg.Address = addr
	}
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("lease: vault client: %w", err)
	}
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
	}
	secret, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("lease: vault read: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("lease: vault secret %q not found", path)
	}
	return extractLeaseSecretValue("vault", secret.Data, field)
}

func readAWSSecretsManagerLeaseSecret(ctx context.Context, spec string) ([]byte, error) {
	name, query, err := parseLeaseSourceSpec(spec)
	if err != nil {
		return nil, err
	}
	opts := []func(*awsconfig.LoadOptions) error{}
	if region := query.Get("region"); region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("lease: aws secrets manager config: %w", err)
	}
	out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(name),
	})
	if err != nil {
		return nil, fmt.Errorf("lease: aws secrets manager get: %w", err)
	}
	if out.SecretString != nil {
		return []byte(*out.SecretString), nil
	}
	if out.SecretBinary != nil {
		return []byte(base64.StdEncoding.EncodeToString(out.SecretBinary)), nil
	}
	return nil, fmt.Errorf("lease: aws secret %q is empty", name)
}

func readAzureKeyVaultLeaseSecret(ctx context.Context, spec string) ([]byte, error) {
	path, query, err := parseLeaseSourceSpec(spec)
	if err != nil {
		return nil, err
	}
	vault, name, ok := strings.Cut(path, "/")
	if !ok || vault == "" || name == "" {
		return nil, fmt.Errorf("lease: azure-kv source must be vault/name")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("lease: azure credential: %w", err)
	}
	client, err := azsecrets.NewClient(fmt.Sprintf("https://%s.vault.azure.net", vault), cred, nil)
	if err != nil {
		return nil, fmt.Errorf("lease: azure key vault client: %w", err)
	}
	resp, err := client.GetSecret(ctx, name, query.Get("version"), nil)
	if err != nil {
		return nil, fmt.Errorf("lease: azure key vault get: %w", err)
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("lease: azure secret %q is empty", name)
	}
	return []byte(*resp.Value), nil
}

func readGCPSecretManagerLeaseSecret(ctx context.Context, spec string) ([]byte, error) {
	path, query, err := parseLeaseSourceSpec(spec)
	if err != nil {
		return nil, err
	}
	project, name, ok := strings.Cut(path, "/")
	if !ok || project == "" || name == "" {
		return nil, fmt.Errorf("lease: gcp-sm source must be project/name")
	}
	version := query.Get("version")
	if version == "" {
		version = "latest"
	}
	opts := []option.ClientOption{}
	if credentials := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); credentials != "" {
		opts = append(opts, option.WithCredentialsFile(credentials))
	}
	svc, err := gsmv1.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("lease: gcp secret manager client: %w", err)
	}
	resource := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", project, name, version)
	resp, err := svc.Projects.Secrets.Versions.Access(resource).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("lease: gcp secret manager access: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(resp.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("lease: gcp secret manager decode: %w", err)
	}
	return data, nil
}

func parseLeaseSourceSpec(spec string) (string, url.Values, error) {
	path, rawQuery, _ := strings.Cut(spec, "?")
	if path == "" {
		return "", nil, fmt.Errorf("lease: secret source path is empty")
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", nil, fmt.Errorf("lease: parse secret source query: %w", err)
	}
	return path, query, nil
}

func extractLeaseSecretValue(provider string, data map[string]interface{}, field string) ([]byte, error) {
	if nested, ok := data["data"].(map[string]interface{}); ok {
		data = nested
	}
	if field != "" {
		value, ok := data[field]
		if !ok {
			return nil, fmt.Errorf("lease: %s secret field %q not found", provider, field)
		}
		return leaseSecretValueBytes(provider, value)
	}
	for _, candidate := range []string{"value", "password", "token", "secret"} {
		if value, ok := data[candidate]; ok {
			return leaseSecretValueBytes(provider, value)
		}
	}
	if len(data) == 1 {
		for _, value := range data {
			return leaseSecretValueBytes(provider, value)
		}
	}
	return nil, fmt.Errorf("lease: %s secret has multiple fields; add ?field=NAME", provider)
}

func leaseSecretValueBytes(provider string, value interface{}) ([]byte, error) {
	switch typed := value.(type) {
	case string:
		return []byte(typed), nil
	case []byte:
		return typed, nil
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return nil, fmt.Errorf("lease: %s secret value is not string-compatible", provider)
		}
		return data, nil
	}
}
