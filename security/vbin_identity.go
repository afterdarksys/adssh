package security

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"golang.org/x/crypto/ssh"
	"mvdan.cc/sh/v3/interp"
)

type identityBinary struct{}

type sshGeneratedKey struct {
	PrivatePEM []byte
	Public     ssh.PublicKey
}

func (identityBinary) Name() string { return "identity" }
func (identityBinary) Description() string {
	return "Import OIDC identity and issue short-lived SSH user certificates"
}
func (identityBinary) Usage() string {
	return `identity status [--json]
identity oidc import (--token token|--token-file path|--env name) [--issuer iss] [--audience aud] [--jwks-url url|--discover] [--user-claim claim] [--group-claim claim]
identity ssh-ca init --out ca_key
identity ssh-ca issue --ca ca_key --pub user.pub --principal name [--principal group] --for duration --out user-cert.pub`
}

func (identityBinary) Run(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("identity: usage: %s", identityBinary{}.Usage())
	}
	switch args[1] {
	case "status":
		return identityStatus(ctx, args[2:])
	case "oidc":
		if len(args) >= 3 && args[2] == "import" {
			return identityOIDCImport(ctx, args[3:])
		}
	case "ssh-ca":
		if len(args) >= 3 {
			switch args[2] {
			case "init":
				return identitySSHCAInit(ctx, args[3:])
			case "issue":
				return identitySSHCAIssue(ctx, args[3:])
			}
		}
	}
	return fmt.Errorf("identity: unsupported command\nusage: %s", identityBinary{}.Usage())
}

func identityStatus(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	jsonOutput := false
	for _, arg := range args {
		if arg == "--json" {
			jsonOutput = true
		} else {
			return fmt.Errorf("identity status: unknown option %q", arg)
		}
	}
	session := sys.GetSession(SessionIDFromContext(ctx))
	if session == nil {
		return fmt.Errorf("identity: requires an active registered session")
	}
	info := session.Info()
	if jsonOutput {
		return json.NewEncoder(hc.Stdout).Encode(map[string]any{
			"session_id": info.ID,
			"user":       info.User,
			"principals": info.Principals,
			"elevation":  info.Elevation,
		})
	}
	fmt.Fprintf(hc.Stdout, "identity: user=%s", emptyDash(info.User))
	if len(info.Principals) > 0 {
		fmt.Fprintf(hc.Stdout, " principals=%s", strings.Join(info.Principals, ","))
	}
	if info.Elevation != nil {
		fmt.Fprintf(hc.Stdout, " elevation=%s", info.Elevation.Role)
	}
	fmt.Fprintln(hc.Stdout)
	return nil
}

func identityOIDCImport(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	opts := oidcImportOptions{UserClaim: "email", GroupClaim: "groups"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--token":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --token requires a value")
			}
			opts.Token = args[i]
		case "--token-file":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --token-file requires a path")
			}
			data, err := os.ReadFile(args[i])
			if err != nil {
				return fmt.Errorf("identity oidc import: read token file: %w", err)
			}
			opts.Token = strings.TrimSpace(string(data))
		case "--env":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --env requires a variable name")
			}
			opts.Token = os.Getenv(args[i])
		case "--issuer":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --issuer requires a value")
			}
			opts.Issuer = args[i]
		case "--audience":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --audience requires a value")
			}
			opts.Audience = args[i]
		case "--jwks-url":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --jwks-url requires a value")
			}
			opts.JWKSURL = args[i]
		case "--discover":
			opts.Discover = true
		case "--user-claim":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --user-claim requires a value")
			}
			opts.UserClaim = args[i]
		case "--group-claim":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --group-claim requires a value")
			}
			opts.GroupClaim = args[i]
		default:
			return fmt.Errorf("identity oidc import: unknown option %q", args[i])
		}
	}
	if opts.Token == "" {
		return fmt.Errorf("identity oidc import: token is required")
	}
	claims, user, groups, err := parseOIDCIdentity(ctx, opts)
	if err != nil {
		return err
	}
	session := sys.GetSession(SessionIDFromContext(ctx))
	if session == nil {
		return fmt.Errorf("identity: requires an active registered session")
	}
	session.SetIdentity(user, groups)
	engineFromContext(ctx).LogEvent(fmt.Sprintf("IDENTITY_OIDC_IMPORT: session=%s user=%s issuer=%s groups=%s",
		session.ID, user, stringClaim(claims, "iss"), strings.Join(groups, ",")))
	fmt.Fprintf(hc.Stdout, "identity: user=%s principals=%s issuer=%s\n",
		user, strings.Join(groups, ","), stringClaim(claims, "iss"))
	return nil
}

type oidcImportOptions struct {
	Token      string
	Issuer     string
	Audience   string
	UserClaim  string
	GroupClaim string
	JWKSURL    string
	Discover   bool
}

func parseOIDCIdentity(ctx context.Context, opts oidcImportOptions) (map[string]any, string, []string, error) {
	parts := strings.Split(opts.Token, ".")
	if len(parts) != 3 {
		return nil, "", nil, fmt.Errorf("identity oidc import: token must be a JWT")
	}
	if opts.JWKSURL != "" || opts.Discover {
		if err := verifyOIDCTokenSignature(ctx, opts); err != nil {
			return nil, "", nil, err
		}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", nil, fmt.Errorf("identity oidc import: decode token payload: %w", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, "", nil, fmt.Errorf("identity oidc import: parse token payload: %w", err)
	}
	if opts.Issuer != "" && stringClaim(claims, "iss") != opts.Issuer {
		return nil, "", nil, fmt.Errorf("identity oidc import: issuer mismatch")
	}
	if opts.Audience != "" && !claimContains(claims["aud"], opts.Audience) {
		return nil, "", nil, fmt.Errorf("identity oidc import: audience mismatch")
	}
	if exp, ok := numericClaim(claims, "exp"); ok && time.Now().Unix() >= int64(exp) {
		return nil, "", nil, fmt.Errorf("identity oidc import: token is expired")
	}
	user := stringClaim(claims, opts.UserClaim)
	if user == "" {
		user = stringClaim(claims, "sub")
	}
	if user == "" {
		return nil, "", nil, fmt.Errorf("identity oidc import: no user claim found")
	}
	groups := stringSliceClaim(claims, opts.GroupClaim)
	return claims, user, groups, nil
}

type oidcJWTHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type oidcJWKSet struct {
	Keys []oidcJWK `json:"keys"`
}

type oidcJWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
}

func verifyOIDCTokenSignature(ctx context.Context, opts oidcImportOptions) error {
	parts := strings.Split(opts.Token, ".")
	var header oidcJWTHeader
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("identity oidc import: decode token header: %w", err)
	}
	if err := json.Unmarshal(headerData, &header); err != nil {
		return fmt.Errorf("identity oidc import: parse token header: %w", err)
	}
	if header.Algorithm != "RS256" {
		return fmt.Errorf("identity oidc import: unsupported signing algorithm %q", header.Algorithm)
	}
	jwks, err := fetchOIDCJWKS(ctx, opts)
	if err != nil {
		return err
	}
	publicKey, err := selectOIDCRSAKey(jwks, header.KeyID, header.Algorithm)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("identity oidc import: decode token signature: %w", err)
	}
	signed := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return fmt.Errorf("identity oidc import: signature verification failed")
	}
	return nil
}

func fetchOIDCJWKS(ctx context.Context, opts oidcImportOptions) (oidcJWKSet, error) {
	jwksURL := opts.JWKSURL
	if opts.Discover {
		if opts.Issuer == "" {
			return oidcJWKSet{}, fmt.Errorf("identity oidc import: --discover requires --issuer")
		}
		discoveryURL := strings.TrimRight(opts.Issuer, "/") + "/.well-known/openid-configuration"
		var discovery struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := fetchOIDCJSON(ctx, discoveryURL, &discovery); err != nil {
			return oidcJWKSet{}, fmt.Errorf("identity oidc import: discover issuer metadata: %w", err)
		}
		if discovery.JWKSURI == "" {
			return oidcJWKSet{}, fmt.Errorf("identity oidc import: issuer metadata did not include jwks_uri")
		}
		jwksURL = discovery.JWKSURI
	}
	if jwksURL == "" {
		return oidcJWKSet{}, fmt.Errorf("identity oidc import: --jwks-url or --discover is required for signature verification")
	}
	var jwks oidcJWKSet
	if err := fetchOIDCJSON(ctx, jwksURL, &jwks); err != nil {
		return oidcJWKSet{}, fmt.Errorf("identity oidc import: fetch jwks: %w", err)
	}
	return jwks, nil
}

func fetchOIDCJSON(ctx context.Context, url string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, target)
}

func selectOIDCRSAKey(jwks oidcJWKSet, keyID, algorithm string) (*rsa.PublicKey, error) {
	for _, key := range jwks.Keys {
		if key.KeyType != "RSA" {
			continue
		}
		if keyID != "" && key.KeyID != keyID {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != algorithm {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		return jwkRSAPublicKey(key)
	}
	return nil, fmt.Errorf("identity oidc import: no matching RSA signing key in JWKS")
}

func jwkRSAPublicKey(key oidcJWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("identity oidc import: decode jwk modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("identity oidc import: decode jwk exponent: %w", err)
	}
	exponent := 0
	for _, b := range eBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent == 0 {
		return nil, fmt.Errorf("identity oidc import: jwk exponent is empty")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}, nil
}

func identitySSHCAInit(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	out := ""
	for i := 0; i < len(args); i++ {
		if args[i] != "--out" {
			return fmt.Errorf("identity ssh-ca init: unknown option %q", args[i])
		}
		i++
		if i >= len(args) {
			return fmt.Errorf("identity ssh-ca init: --out requires a path")
		}
		out = args[i]
	}
	if out == "" {
		return fmt.Errorf("identity ssh-ca init: --out is required")
	}
	key, err := sshKeygenRSA()
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, key.PrivatePEM, 0o600); err != nil {
		return fmt.Errorf("identity ssh-ca init: write private key: %w", err)
	}
	if err := os.WriteFile(out+".pub", ssh.MarshalAuthorizedKey(key.Public), 0o644); err != nil {
		return fmt.Errorf("identity ssh-ca init: write public key: %w", err)
	}
	engineFromContext(ctx).LogEvent(fmt.Sprintf("IDENTITY_SSH_CA_INIT: path=%s", out))
	fmt.Fprintf(hc.Stdout, "identity: ssh ca private=%s public=%s.pub\n", out, out)
	return nil
}

func identitySSHCAIssue(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	opts := sshIssueOptions{TTL: 15 * time.Minute}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ca":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity ssh-ca issue: --ca requires a path")
			}
			opts.CAPath = args[i]
		case "--pub":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity ssh-ca issue: --pub requires a path")
			}
			opts.PubPath = args[i]
		case "--principal":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity ssh-ca issue: --principal requires a value")
			}
			opts.Principals = append(opts.Principals, args[i])
		case "--for":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity ssh-ca issue: --for requires a duration")
			}
			ttl, err := time.ParseDuration(args[i])
			if err != nil || ttl <= 0 || ttl > 24*time.Hour {
				return fmt.Errorf("identity ssh-ca issue: --for must be a positive duration no greater than 24h")
			}
			opts.TTL = ttl
		case "--out":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity ssh-ca issue: --out requires a path")
			}
			opts.OutPath = args[i]
		default:
			return fmt.Errorf("identity ssh-ca issue: unknown option %q", args[i])
		}
	}
	cert, err := issueSSHCertificate(opts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(opts.OutPath, ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		return fmt.Errorf("identity ssh-ca issue: write certificate: %w", err)
	}
	engineFromContext(ctx).LogEvent(fmt.Sprintf("IDENTITY_SSH_CERT_ISSUE: out=%s principals=%s ttl=%s",
		opts.OutPath, strings.Join(opts.Principals, ","), opts.TTL))
	fmt.Fprintf(hc.Stdout, "identity: ssh cert=%s principals=%s valid_for=%s\n",
		opts.OutPath, strings.Join(opts.Principals, ","), opts.TTL)
	return nil
}

type sshIssueOptions struct {
	CAPath     string
	PubPath    string
	OutPath    string
	Principals []string
	TTL        time.Duration
}

func issueSSHCertificate(opts sshIssueOptions) (*ssh.Certificate, error) {
	if opts.CAPath == "" || opts.PubPath == "" || opts.OutPath == "" || len(opts.Principals) == 0 {
		return nil, fmt.Errorf("identity ssh-ca issue: --ca, --pub, --principal, and --out are required")
	}
	caData, err := os.ReadFile(opts.CAPath)
	if err != nil {
		return nil, fmt.Errorf("identity ssh-ca issue: read ca key: %w", err)
	}
	caSigner, err := ssh.ParsePrivateKey(caData)
	if err != nil {
		return nil, fmt.Errorf("identity ssh-ca issue: parse ca key: %w", err)
	}
	pubData, err := os.ReadFile(opts.PubPath)
	if err != nil {
		return nil, fmt.Errorf("identity ssh-ca issue: read public key: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		return nil, fmt.Errorf("identity ssh-ca issue: parse public key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("adssh-%d", serial),
		ValidPrincipals: opts.Principals,
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(opts.TTL).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("identity ssh-ca issue: sign certificate: %w", err)
	}
	return cert, nil
}

func randomSerial() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("identity ssh-ca issue: random serial: %w", err)
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

func sshKeygenRSA() (sshGeneratedKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return sshGeneratedKey{}, fmt.Errorf("identity ssh-ca init: generate key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(private),
	})
	public, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		return sshGeneratedKey{}, fmt.Errorf("identity ssh-ca init: public key: %w", err)
	}
	return sshGeneratedKey{PrivatePEM: privatePEM, Public: public}, nil
}

func stringClaim(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return value
}

func numericClaim(claims map[string]any, key string) (float64, bool) {
	value, ok := claims[key].(float64)
	return value, ok
}

func stringSliceClaim(claims map[string]any, key string) []string {
	switch value := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if value == "" {
			return nil
		}
		return strings.Split(value, ",")
	default:
		return nil
	}
}

func claimContains(value any, needle string) bool {
	switch v := value.(type) {
	case string:
		return v == needle
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == needle {
				return true
			}
		}
	}
	return false
}

func init() { Register(identityBinary{}) }
