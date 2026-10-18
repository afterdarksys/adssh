//go:build ee

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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
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
	return "Log in with an opaque device bearer, import OIDC identity, and issue short-lived SSH user certificates"
}
func (identityBinary) Usage() string {
	return `identity status [--json]
identity device login --username USER [--url ADSSH_CONTROLPLANE_URL] [--token-file PATH] [--interval duration] [--timeout duration]
identity oidc import (--token token|--token-file path|--env name) [--provider login|admin] [--user-claim claim] [--group-claim claim]
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
	case "device":
		if len(args) >= 3 && args[2] == "login" {
			return identityDeviceLogin(ctx, args[3:])
		}
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

func identityDeviceLogin(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	req := DeviceLoginRequest{}
	for i := 0; i < len(args); i++ {
		needsValue := true
		switch args[i] {
		case "--url", "--username", "--token-file", "--interval", "--timeout":
		default:
			return fmt.Errorf("identity device login: unknown option %q", args[i])
		}
		if needsValue {
			if i+1 >= len(args) {
				return fmt.Errorf("identity device login: %s requires a value", args[i])
			}
			i++
		}
		switch args[i-1] {
		case "--url":
			req.URL = args[i]
		case "--username":
			req.Username = args[i]
		case "--token-file":
			req.TokenFile = args[i]
		case "--interval":
			interval, err := parseFlexibleDuration(args[i])
			if err != nil {
				return fmt.Errorf("identity device login: --interval must be a duration or seconds")
			}
			req.Interval = interval
			req.IntervalSet = true
		case "--timeout":
			timeout, err := parseFlexibleDuration(args[i])
			if err != nil {
				return fmt.Errorf("identity device login: --timeout must be a duration or seconds")
			}
			req.Timeout = timeout
		}
	}
	if req.Username == "" {
		return fmt.Errorf("identity device login: --username is required")
	}
	result, err := DeviceLogin(ctx, req)
	if err != nil {
		return err
	}
	fmt.Fprintf(hc.Stdout, "token_file=%s\nfingerprint=%s\n", result.TokenFile, result.Fingerprint)
	return nil
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
		payload := map[string]any{
			"session_id": info.ID,
			"user":       info.User,
			"principals": info.Principals,
			"elevation":  info.Elevation,
		}
		if info.OIDCProvider != "" {
			payload["oidc_provider"] = info.OIDCProvider
		}
		if len(info.EligibleRoles) > 0 {
			payload["eligible_roles"] = info.EligibleRoles
		}
		if info.AgentID != "" {
			payload["agent_id"] = info.AgentID
		}
		return json.NewEncoder(hc.Stdout).Encode(payload)
	}
	fmt.Fprintf(hc.Stdout, "identity: user=%s", emptyDash(info.User))
	if len(info.Principals) > 0 {
		fmt.Fprintf(hc.Stdout, " principals=%s", strings.Join(info.Principals, ","))
	}
	if info.Elevation != nil {
		fmt.Fprintf(hc.Stdout, " elevation=%s", info.Elevation.Role)
	}
	if info.OIDCProvider != "" {
		fmt.Fprintf(hc.Stdout, " oidc_provider=%s", info.OIDCProvider)
	}
	if len(info.EligibleRoles) > 0 {
		fmt.Fprintf(hc.Stdout, " eligible_roles=%s", strings.Join(info.EligibleRoles, ","))
	}
	if info.AgentID != "" {
		fmt.Fprintf(hc.Stdout, " agent_id=%s", info.AgentID)
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
		case "--provider":
			i++
			if i >= len(args) {
				return fmt.Errorf("identity oidc import: --provider requires a value")
			}
			opts.Provider = args[i]
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
	principals := FilterUnprivileged(groups)
	var eligible []string
	if opts.Provider == OIDCProviderAdmin {
		eligible = PrivilegedEligible(groups)
	}
	// Log the fingerprint only. The raw JWT must not appear in the format
	// string, or redaction would hide it and the chain check would be weaker.
	// The audit line is written before the identity changes; a failed write
	// leaves the session as it was.
	if err := engineFromContext(ctx).LogEvent(fmt.Sprintf("IDENTITY_OIDC_IMPORT: session=%s user=%s issuer=%s provider=%s fingerprint=%s groups=%s eligible=%s",
		session.ID, user, stringClaim(claims, "iss"), opts.Provider, fingerprintSecret(opts.Token), strings.Join(principals, ","), strings.Join(eligible, ","))); err != nil {
		return fmt.Errorf("identity oidc import: audit write failed")
	}
	switch opts.Provider {
	case OIDCProviderAdmin:
		session.SetIdentity(user, principals)
		session.SetOIDC(OIDCProviderAdmin, eligible)
	case OIDCProviderLogin:
		session.SetIdentity(user, principals)
		session.SetOIDC(OIDCProviderLogin, nil)
	default:
		session.SetIdentity(user, principals)
		session.SetOIDC("", nil)
	}
	// parseOIDCIdentity verified the RS256 signature against the pinned JWKS,
	// the pinned issuer and audience, and the token times. Only that path
	// reaches here, so the new user may decide four-eyes requests.
	session.SetIdentitySource(sys.IdentitySourceOIDCVerified)
	fmt.Fprintf(hc.Stdout, "identity: user=%s principals=%s issuer=%s",
		user, strings.Join(principals, ","), stringClaim(claims, "iss"))
	if opts.Provider != "" {
		fmt.Fprintf(hc.Stdout, " provider=%s", opts.Provider)
	}
	if len(eligible) > 0 {
		fmt.Fprintf(hc.Stdout, " eligible=%s", strings.Join(eligible, ","))
	}
	fmt.Fprintln(hc.Stdout)
	return nil
}

type oidcImportOptions struct {
	Token      string
	Provider   string
	UserClaim  string
	GroupClaim string
}

// oidcProviderConfig is the operator-pinned trust anchor for one provider.
type oidcProviderConfig struct {
	Issuer   string
	JWKSURL  string
	Audience string
	// OtherAudience is the other provider's audience. A token naming it is
	// refused so one token cannot serve both providers.
	OtherAudience string
}

// oidcMaxLifetime caps exp-now and exp-iat. A token valid for longer is
// refused so a long-lived token cannot hold an identity indefinitely.
const oidcMaxLifetime = 24 * time.Hour

// oidcClockSkew is the leeway for nbf and iat in the future.
const oidcClockSkew = time.Minute

// oidcResponseLimit caps a JWKS response body.
const oidcResponseLimit = 1 << 20

// Threats: an import renames the session user and, for --provider admin,
// makes privileged roles eligible, so every import must verify a JWT signed
// by a key the operator trusts. The issuer and JWKS URL come only from
// operator config (ADSSH_OIDC_ISSUER/ADSSH_OIDC_JWKS_URL for the default and
// login providers, ADSSH_OIDC_ADMIN_ISSUER/ADSSH_OIDC_ADMIN_JWKS_URL for
// admin); an unset value fails closed and the caller cannot name another key
// source. The audience is pinned the same way (ADSSH_OIDC_LOGIN_AUDIENCE for
// the default and login providers, ADSSH_OIDC_ADMIN_AUDIENCE for admin), both
// must be set and must differ, and a token whose aud also names the other
// provider's audience is refused, so a token the same IdP issued for another
// relying party (or for the login audience) cannot be replayed to rename the
// session user or to make privileged roles eligible. The JWKS is fetched over https with TLS 1.3, no redirects, a
// timeout, a 1 MiB cap, and private/metadata hosts refused. RS256 is the only
// algorithm. iss must equal the configured issuer; aud must contain the
// configured audience; exp is
// required, unexpired, and at most 24h out (and at most 24h after iat); nbf
// and iat, when present, may not be in the future. A login-audience groups
// claim never grants os-root, adssh-admin, or gridops. The raw token is not
// logged; only its SHA-256 fingerprint is. Non-goals: this does not stop a
// stolen, unexpired token from the configured issuer, and it does not detect
// a compromised identity provider.
func oidcProviderSettings(provider string) (oidcProviderConfig, error) {
	var cfg oidcProviderConfig
	loginAud := strings.TrimSpace(os.Getenv("ADSSH_OIDC_LOGIN_AUDIENCE"))
	adminAud := strings.TrimSpace(os.Getenv("ADSSH_OIDC_ADMIN_AUDIENCE"))
	switch provider {
	case "", OIDCProviderLogin:
		cfg = oidcProviderConfig{Issuer: os.Getenv("ADSSH_OIDC_ISSUER"), JWKSURL: os.Getenv("ADSSH_OIDC_JWKS_URL"),
			Audience: loginAud, OtherAudience: adminAud}
	case OIDCProviderAdmin:
		cfg = oidcProviderConfig{Issuer: os.Getenv("ADSSH_OIDC_ADMIN_ISSUER"), JWKSURL: os.Getenv("ADSSH_OIDC_ADMIN_JWKS_URL"),
			Audience: adminAud, OtherAudience: loginAud}
	default:
		return oidcProviderConfig{}, fmt.Errorf("identity oidc import: --provider must be login or admin")
	}
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.JWKSURL = strings.TrimSpace(cfg.JWKSURL)
	if cfg.Issuer == "" || cfg.JWKSURL == "" || cfg.Audience == "" {
		vars := "ADSSH_OIDC_ISSUER, ADSSH_OIDC_JWKS_URL and ADSSH_OIDC_LOGIN_AUDIENCE"
		if provider == OIDCProviderAdmin {
			vars = "ADSSH_OIDC_ADMIN_ISSUER, ADSSH_OIDC_ADMIN_JWKS_URL and ADSSH_OIDC_ADMIN_AUDIENCE"
		}
		return oidcProviderConfig{}, fmt.Errorf("identity oidc import: oidc provider not configured: set %s", vars)
	}
	if cfg.Audience == cfg.OtherAudience {
		return oidcProviderConfig{}, fmt.Errorf("identity oidc import: login and admin audiences must differ")
	}
	return cfg, nil
}

func parseOIDCIdentity(ctx context.Context, opts oidcImportOptions) (map[string]any, string, []string, error) {
	parts := strings.Split(opts.Token, ".")
	if len(parts) != 3 {
		return nil, "", nil, fmt.Errorf("identity oidc import: token must be a JWT")
	}
	provider, err := oidcProviderSettings(opts.Provider)
	if err != nil {
		return nil, "", nil, err
	}
	if err := verifyOIDCTokenSignature(ctx, opts.Token, provider.JWKSURL); err != nil {
		return nil, "", nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", nil, fmt.Errorf("identity oidc import: decode token payload: %w", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, "", nil, fmt.Errorf("identity oidc import: parse token payload: %w", err)
	}
	if iss := stringClaim(claims, "iss"); iss == "" || iss != provider.Issuer {
		return nil, "", nil, fmt.Errorf("identity oidc import: issuer mismatch")
	}
	if !claimContains(claims["aud"], provider.Audience) ||
		(provider.OtherAudience != "" && claimContains(claims["aud"], provider.OtherAudience)) {
		return nil, "", nil, fmt.Errorf("identity oidc import: audience mismatch")
	}
	if err := checkOIDCTimes(claims, time.Now()); err != nil {
		return nil, "", nil, err
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

// checkOIDCTimes requires exp and enforces the lifetime cap, nbf, and iat.
func checkOIDCTimes(claims map[string]any, now time.Time) error {
	exp, ok := numericClaim(claims, "exp")
	if !ok {
		return fmt.Errorf("identity oidc import: token has no exp")
	}
	expAt := time.Unix(int64(exp), 0)
	if !now.Before(expAt) {
		return fmt.Errorf("identity oidc import: token is expired")
	}
	if expAt.Sub(now) > oidcMaxLifetime {
		return fmt.Errorf("identity oidc import: token lifetime exceeds 24h")
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok {
		if time.Unix(int64(nbf), 0).After(now.Add(oidcClockSkew)) {
			return fmt.Errorf("identity oidc import: token is not yet valid")
		}
	} else if _, present := claims["nbf"]; present {
		return fmt.Errorf("identity oidc import: token nbf is invalid")
	}
	if iat, ok := numericClaim(claims, "iat"); ok {
		iatAt := time.Unix(int64(iat), 0)
		if iatAt.After(now.Add(oidcClockSkew)) {
			return fmt.Errorf("identity oidc import: token is not yet valid")
		}
		if expAt.Sub(iatAt) > oidcMaxLifetime {
			return fmt.Errorf("identity oidc import: token lifetime exceeds 24h")
		}
	} else if _, present := claims["iat"]; present {
		return fmt.Errorf("identity oidc import: token iat is invalid")
	}
	return nil
}

func verifyOIDCTokenSignature(ctx context.Context, token, jwksURL string) error {
	parts := strings.Split(token, ".")
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
	var jwks oidcJWKSet
	if err := fetchOIDCJSON(ctx, jwksURL, &jwks); err != nil {
		return fmt.Errorf("identity oidc import: fetch jwks: %w", err)
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

// fetchOIDCJSON GETs an operator-configured https URL through the callback
// client: validated host, TLS 1.3, no redirects, timeout, and a size cap.
func fetchOIDCJSON(ctx context.Context, rawURL string, target any) error {
	parsed, err := validateCallbackURL(rawURL)
	if errors.Is(err, errPrivateHost) {
		host := ""
		if p, perr := url.Parse(rawURL); perr == nil {
			host = p.Hostname()
		}
		return fmt.Errorf("url_rejected: host %s is a private address; set ADSSH_CALLBACK_ALLOW_PRIVATE=1 to allow it", host)
	}
	if err != nil || parsed.Scheme != "https" {
		return fmt.Errorf("url_rejected")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return fmt.Errorf("url_rejected")
	}
	resp, err := callbackHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		if errors.Is(err, errRedirectDenied) {
			return errRedirectDenied
		}
		return fmt.Errorf("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, oidcResponseLimit+1))
	if err != nil {
		return fmt.Errorf("read failed")
	}
	if len(body) > oidcResponseLimit {
		return fmt.Errorf("response too large")
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
	if err := engineFromContext(ctx).LogEvent(fmt.Sprintf("IDENTITY_SSH_CA_INIT: path=%s", out)); err != nil {
		return fmt.Errorf("identity ssh-ca init: audit: %w", err)
	}
	if err := os.WriteFile(out, key.PrivatePEM, 0o600); err != nil {
		return fmt.Errorf("identity ssh-ca init: write private key: %w", err)
	}
	if err := os.WriteFile(out+".pub", ssh.MarshalAuthorizedKey(key.Public), 0o644); err != nil {
		return fmt.Errorf("identity ssh-ca init: write public key: %w", err)
	}
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
	if err := engineFromContext(ctx).LogEvent(fmt.Sprintf("IDENTITY_SSH_CERT_ISSUE: out=%s principals=%s ttl=%s",
		opts.OutPath, strings.Join(opts.Principals, ","), opts.TTL)); err != nil {
		return fmt.Errorf("identity ssh-ca issue: audit: %w", err)
	}
	if err := os.WriteFile(opts.OutPath, ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		return fmt.Errorf("identity ssh-ca issue: write certificate: %w", err)
	}
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
