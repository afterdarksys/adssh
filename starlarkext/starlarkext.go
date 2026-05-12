package starlarkext

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"

	"github.com/dlclark/regexp2"
	"go.starlark.net/starlark"
	"sync"
)

var (
	CustomCompleters = make(map[string]starlark.Callable)
	CompletersMu     sync.RWMutex
)

// SetupExtensions injects all standard library extensions into the given dict
func SetupExtensions(env starlark.StringDict, restricted bool) {
	// Cloud providers
	SetupAWSAPI(env)
	ExpandAWSAPI(env) // adds rds, eks, iam, sqs, ecr
	SetupOCIAPI(env)
	SetupGCPAPI(env)
	SetupAzureAPI(env)

	// Kubernetes
	SetupK8sAPI(env)

	// Secrets management (Vault, AWS SM, Azure KV, GCP SM)
	SetupSecretsAPI(env)

	// Databases (postgres, mysql, redis)
	SetupDatabaseAPI(env)

	// Notifications (Slack, webhook, PagerDuty)
	SetupNotifyAPI(env)

	// Interactive process automation (PTY-backed expect)
	SetupExpectAPI(env)

	// Docker Engine API (images, networks, volumes, container management)
	SetupDockerAPI(env)

	// VCS: git + GitHub
	SetupVCSAPI(env)

	// Ephemeral containers with audit trail
	SetupContainersAPI(env)

	// Security
	SetupSecurityAPI(env, restricted)
	// Crypto
	cryptoDict := starlark.NewDict(2)
	cryptoDict.SetKey(starlark.String("md5"), starlark.NewBuiltin("md5", builtinMD5))
	cryptoDict.SetKey(starlark.String("sha256"), starlark.NewBuiltin("sha256", builtinSHA256))
	env["crypto"] = cryptoDict

	// Networking
	netDict := starlark.NewDict(4)
	if !restricted {
		netDict.SetKey(starlark.String("tcp_send"), starlark.NewBuiltin("tcp_send", builtinTCPSend))
		netDict.SetKey(starlark.String("http_get"), starlark.NewBuiltin("http_get", builtinHTTPGet))
		netDict.SetKey(starlark.String("dial"), starlark.NewBuiltin("dial", builtinDial))
		netDict.SetKey(starlark.String("dial_tls"), starlark.NewBuiltin("dial_tls", builtinDialTLS))
	}
	env["net"] = netDict

	// Regex (POSIX/RE2, PCRE)
	reDict := starlark.NewDict(2)
	reDict.SetKey(starlark.String("match"), starlark.NewBuiltin("re_match", builtinReMatch))
	reDict.SetKey(starlark.String("pcre_match"), starlark.NewBuiltin("pcre_match", builtinPcreMatch))
	env["re"] = reDict

	// Sys
	sysDict := starlark.NewDict(8)
	sysDict.SetKey(starlark.String("getenv"), starlark.NewBuiltin("getenv", builtinGetEnv))
	sysDict.SetKey(starlark.String("setenv"), starlark.NewBuiltin("setenv", builtinSetEnv))
	sysDict.SetKey(starlark.String("load_plugin"), createLoadPlugin(env))
	sysDict.SetKey(starlark.String("load_agent"), createLoadAgent(env))
	if !restricted {
		sysDict.SetKey(starlark.String("read_file"), starlark.NewBuiltin("read_file", builtinReadFile))
		sysDict.SetKey(starlark.String("write_file"), starlark.NewBuiltin("write_file", builtinWriteFile))
		sysDict.SetKey(starlark.String("exec_cmd"), starlark.NewBuiltin("exec_cmd", createExecCmd(env, restricted)))
		sysDict.SetKey(starlark.String("exec_async"), starlark.NewBuiltin("exec_async", createExecAsync(env, restricted)))
		sysDict.SetKey(starlark.String("exec_json"), starlark.NewBuiltin("exec_json", createExecJSON(env, restricted)))
		sysDict.SetKey(starlark.String("register_command"), createRegisterCommand(env))
		sysDict.SetKey(starlark.String("register_completer"), starlark.NewBuiltin("register_completer", builtinRegisterCompleter))
	}
	env["sys"] = sysDict

	// Ensure __custom_commands__ dict exists in env
	if _, ok := env["__custom_commands__"]; !ok {
		env["__custom_commands__"] = starlark.NewDict(16)
	}

	// Ensure plugins dict exists in env
	if _, ok := env["plugins"]; !ok {
		env["plugins"] = starlark.NewDict(16)
	}

	// Data
	dataDict := starlark.NewDict(4)
	dataDict.SetKey(starlark.String("json_parse"), starlark.NewBuiltin("json_parse", builtinJSONParse))
	dataDict.SetKey(starlark.String("json_dump"), starlark.NewBuiltin("json_dump", builtinJSONDump))
	dataDict.SetKey(starlark.String("yaml_parse"), starlark.NewBuiltin("yaml_parse", builtinYAMLParse))
	dataDict.SetKey(starlark.String("yaml_dump"), starlark.NewBuiltin("yaml_dump", builtinYAMLDump))
	env["data"] = dataDict

	// i18n
	i18nDict := starlark.NewDict(3)
	i18nDict.SetKey(starlark.String("load"), starlark.NewBuiltin("load", builtinI18nLoad))
	i18nDict.SetKey(starlark.String("set_lang"), starlark.NewBuiltin("set_lang", builtinI18nSetLang))
	i18nDict.SetKey(starlark.String("T"), starlark.NewBuiltin("T", builtinI18nT))
	env["i18n"] = i18nDict

	// DevOps / Cloud Engine
	cloudDict := starlark.NewDict(2)
	cloudDict.SetKey(starlark.String("gen"), starlark.NewBuiltin("gen", builtinCloudGen))
	cloudDict.SetKey(starlark.String("register_mapper"), starlark.NewBuiltin("register_mapper", builtinRegisterMapper))
	env["cloud"] = cloudDict
}

func builtinMD5(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	hash := md5.Sum([]byte(data))
	return starlark.String(hex.EncodeToString(hash[:])), nil
}

func builtinSHA256(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(data))
	return starlark.String(hex.EncodeToString(hash[:])), nil
}

func builtinReMatch(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern, text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &pattern, "text", &text); err != nil {
		return nil, err
	}
	matched, err := regexp.MatchString(pattern, text)
	if err != nil {
		return nil, err
	}
	return starlark.Bool(matched), nil
}

func builtinPcreMatch(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern, text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &pattern, "text", &text); err != nil {
		return nil, err
	}
	re, err := regexp2.Compile(pattern, 0)
	if err != nil {
		return nil, err
	}
	matched, err := re.MatchString(text)
	if err != nil {
		return nil, fmt.Errorf("pcre_match error: %v", err)
	}
	return starlark.Bool(matched), nil
}

func builtinReadFile(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read_file error: %v", err)
	}
	return starlark.String(string(data)), nil
}

func builtinWriteFile(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, data string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path, "data", &data); err != nil {
		return nil, err
	}
	err := os.WriteFile(path, []byte(data), 0600)
	if err != nil {
		return nil, fmt.Errorf("write_file error: %v", err)
	}
	return starlark.None, nil
}

func createRegisterCommand(env starlark.StringDict) *starlark.Builtin {
	return starlark.NewBuiltin("register_command", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		var callable starlark.Callable
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "callable", &callable); err != nil {
			return nil, err
		}

		dictVal, ok := env["__custom_commands__"]
		if !ok {
			return nil, fmt.Errorf("register_command: missing __custom_commands__ env dict")
		}
		dict, ok := dictVal.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("register_command: __custom_commands__ is not a dict")
		}

		err := dict.SetKey(starlark.String(name), callable)
		return starlark.None, err
	})
}

func builtinRegisterCompleter(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var cmd string
	var callable starlark.Callable
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cmd", &cmd, "callable", &callable); err != nil {
		return nil, err
	}
	CompletersMu.Lock()
	defer CompletersMu.Unlock()
	CustomCompleters[cmd] = callable
	return starlark.None, nil
}
