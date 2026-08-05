package security

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"mvdan.cc/sh/v3/interp"
)

type leaseBinary struct{}

func (leaseBinary) Name() string { return "lease" }
func (leaseBinary) Description() string {
	return "Inject an environment, private-file, or vault-backed secret into one governed command with a bounded TTL"
}
func (leaseBinary) Usage() string {
	return "lease --from env:NAME|file:path|vault:path?field=KEY|aws-sm:name?region=REGION|azure-kv:vault/name|gcp-sm:project/name --as DEST [--ttl duration] -- command [args...]"
}

func (leaseBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	source := ""
	destination := ""
	ttl := 5 * time.Minute
	delimiter := -1
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			delimiter = i
			break
		}
		switch args[i] {
		case "--from":
			if i+1 >= len(args) {
				return fmt.Errorf("lease: --from requires a source")
			}
			i++
			source = args[i]
		case "--as":
			if i+1 >= len(args) {
				return fmt.Errorf("lease: --as requires an environment variable name")
			}
			i++
			destination = args[i]
		case "--ttl":
			if i+1 >= len(args) {
				return fmt.Errorf("lease: --ttl requires a duration")
			}
			i++
			parsed, err := time.ParseDuration(args[i])
			if err != nil || parsed <= 0 || parsed > 24*time.Hour {
				return fmt.Errorf("lease: ttl must be a positive duration no greater than 24h")
			}
			ttl = parsed
		default:
			return fmt.Errorf("lease: unknown option %q", args[i])
		}
	}
	if source == "" || destination == "" || delimiter < 0 || delimiter+1 >= len(args) {
		return fmt.Errorf("lease: usage: %s", leaseBinary{}.Usage())
	}
	if !validEnvironmentName(destination) {
		return fmt.Errorf("lease: invalid destination environment variable %q", destination)
	}
	secret, err := loadLeaseSecret(ctx, source)
	if err != nil {
		return err
	}
	defer zeroBytes(secret)
	if len(secret) == 0 {
		return fmt.Errorf("lease: secret source is empty")
	}
	if bytes.IndexByte(secret, 0) >= 0 {
		return fmt.Errorf("lease: secret contains a NUL byte and cannot be placed in an environment variable")
	}

	leaseCtx, cancel := context.WithTimeout(ctx, ttl)
	defer cancel()
	secretValue := string(secret)
	var unsetEnv []string
	if kind, name, found := strings.Cut(source, ":"); found && kind == "env" {
		unsetEnv = []string{name}
	}
	result, err := engineFromContext(ctx).runGovernedCommand(leaseCtx, SessionIDFromContext(ctx), governedCommand{
		Args:     args[delimiter+1:],
		Dir:      hc.Dir,
		Env:      map[string]string{destination: secretValue},
		UnsetEnv: unsetEnv,
	}, nil)
	result.Stdout = redactSecret(result.Stdout, secret)
	result.Stderr = redactSecret(result.Stderr, secret)
	result.Stdout = redactSensitiveBytes(result.Stdout)
	result.Stderr = redactSensitiveBytes(result.Stderr)
	if len(result.Stdout) > 0 {
		_, _ = hc.Stdout.Write(result.Stdout)
	}
	if len(result.Stderr) > 0 {
		_, _ = hc.Stderr.Write(result.Stderr)
	}
	if err != nil {
		return fmt.Errorf("lease: child command: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("lease: child command exited with status %d", result.ExitCode)
	}
	return nil
}

type leaseSecretReader func(context.Context, string) ([]byte, error)

var leaseSecretReaders = map[string]leaseSecretReader{
	"env":      readEnvLeaseSecret,
	"file":     readFileLeaseSecret,
	"vault":    readVaultLeaseSecret,
	"aws-sm":   readAWSSecretsManagerLeaseSecret,
	"azure-kv": readAzureKeyVaultLeaseSecret,
	"gcp-sm":   readGCPSecretManagerLeaseSecret,
}

func loadLeaseSecret(ctx context.Context, source string) ([]byte, error) {
	kind, name, found := strings.Cut(source, ":")
	if !found || name == "" {
		return nil, fmt.Errorf("lease: source must be env:NAME, file:path, vault:path, aws-sm:name, azure-kv:vault/name, or gcp-sm:project/name")
	}
	reader, ok := leaseSecretReaders[kind]
	if !ok {
		return nil, fmt.Errorf("lease: unsupported source type %q", kind)
	}
	secret, err := reader(ctx, name)
	if err != nil {
		return nil, err
	}
	if len(secret) > 1<<20 {
		zeroBytes(secret)
		return nil, fmt.Errorf("lease: secret exceeds 1 MiB")
	}
	return bytes.TrimSuffix(bytes.TrimSuffix(secret, []byte("\n")), []byte("\r")), nil
}

func readEnvLeaseSecret(_ context.Context, name string) ([]byte, error) {
	if !validEnvironmentName(name) {
		return nil, fmt.Errorf("lease: invalid source environment variable %q", name)
	}
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("lease: source environment variable %s is not set", name)
	}
	return []byte(value), nil
}

func readFileLeaseSecret(_ context.Context, name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("lease: inspect secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("lease: secret file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("lease: secret file permissions must not grant group or other access")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("lease: open secret file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("lease: inspect opened secret file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("lease: secret file changed while it was being opened")
	}
	if openedInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("lease: secret file permissions must not grant group or other access")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("lease: read secret file: %w", err)
	}
	if len(data) > 1<<20 {
		zeroBytes(data)
		return nil, fmt.Errorf("lease: secret file exceeds 1 MiB")
	}
	return data, nil
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, r := range name {
		if r == '_' || unicode.IsLetter(r) || (index > 0 && unicode.IsDigit(r)) {
			continue
		}
		return false
	}
	return true
}

func redactSecret(data, secret []byte) []byte {
	if len(secret) == 0 || len(data) == 0 {
		return data
	}
	return bytes.ReplaceAll(data, secret, []byte("[REDACTED]"))
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
