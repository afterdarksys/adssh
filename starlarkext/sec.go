package starlarkext

import (
	"github.com/afterdarksys/adssh/security"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go.starlark.net/starlark"
	"io"
	"os"
)

var isRestricted bool

func SetupSecurityAPI(env starlark.StringDict, restricted bool) {
	isRestricted = restricted
	secDict := starlark.NewDict(4)
	secDict.SetKey(starlark.String("audit"), starlark.NewBuiltin("audit", builtinSecAudit))
	secDict.SetKey(starlark.String("is_restricted"), starlark.NewBuiltin("is_restricted", builtinSecIsRestricted))
	secDict.SetKey(starlark.String("file_hash"), starlark.NewBuiltin("file_hash", builtinSecFileHash))
	secDict.SetKey(starlark.String("check_policy"), starlark.NewBuiltin("check_policy", builtinSecCheckPolicy))
	env["sec"] = secDict
}

func builtinSecAudit(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "msg", &msg); err != nil {
		return nil, err
	}
	security.LogEvent("STARLARK_AUDIT: " + msg)
	return starlark.None, nil
}

func builtinSecIsRestricted(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.Bool(isRestricted), nil
}

func builtinSecFileHash(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("file_hash error: %v", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("file_hash read error: %v", err)
	}
	return starlark.String(hex.EncodeToString(h.Sum(nil))), nil
}

func builtinSecCheckPolicy(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var command string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "command", &command); err != nil {
		return nil, err
	}

	pctx := security.BuildPolicyContext(command, nil, "")
	allowed, reason, err := security.EvaluatePolicy(pctx)
	if err != nil {
		return nil, fmt.Errorf("check_policy error: %v", err)
	}

	result := starlark.NewDict(2)
	result.SetKey(starlark.String("allowed"), starlark.Bool(allowed))
	result.SetKey(starlark.String("reason"), starlark.String(reason))
	return result, nil
}
