package security

// Starlark plugins are directories under the adssh config plugins directory.
// Each directory holds manifest.yaml and plugin.star. Nothing there runs until
// an operator loads it. sys.load_plugin of a Go shared library is a separate path.
//
// Threats:
//   - A path outside the plugins directory. Names are a single safe component.
//     The directory is opened without following a symlink, and each file is
//     opened with O_NOFOLLOW.
//   - A file someone else can replace. The root, each plugin directory, and
//     each file must be owned by the effective user, checked with fstat on
//     the opened descriptor. Group-writable and world-writable directories
//     and files are rejected. The size of each file is capped.
//   - A manifest that asks for more than it says. Unknown fields, aliases,
//     extra documents, and a name that does not match the directory fail closed.
//   - A bad neighbor. plugin load --all checks every entry first. If any check
//     or execution fails, session command registrations from that call are
//     restored and no plugin from the batch stays loaded.
//   - Restricted mode. The shell command refuses to load, and sys.load_plugins
//     is not provided.
//   - Startup. This package does not load plugins on its own.
// It does not sandbox a plugin that passed those checks. Loading one runs its
// top-level Starlark in the session. A command the plugin starts during that
// run is not rolled back. Policy on the session builtins still applies.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/internal/safefile"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/interp"
)

const (
	pluginManifestMax           = 16 * 1024
	pluginSourceMax             = 1 << 20
	pluginDescriptionMax        = 256
	pluginEntryMax              = 64
	pluginNameMax               = 64
	pluginSteps          uint64 = 100_000
)

const (
	pluginManifestName = "manifest.yaml"
	pluginSourceName   = "plugin.star"
)

// pluginKeywords are Starlark keywords and reserved words. assert is not one of them.
var pluginKeywords = map[string]struct{}{
	"and": {}, "break": {}, "continue": {}, "def": {}, "elif": {}, "else": {},
	"for": {}, "if": {}, "in": {}, "lambda": {}, "load": {}, "not": {},
	"or": {}, "pass": {}, "return": {}, "while": {},
	"as": {}, "async": {}, "await": {}, "class": {}, "del": {}, "except": {},
	"finally": {}, "from": {}, "global": {}, "import": {}, "is": {},
	"nonlocal": {}, "raise": {}, "try": {}, "with": {}, "yield": {},
}

type pluginSource struct {
	name        string
	description string
	star        []byte
}

// pluginOwned reports whether info, from fstat on an open descriptor, is
// owned by the effective user. Tests replace it because they cannot chown.
var pluginOwned = func(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

func pluginDir() string {
	if dir := os.Getenv("ADSSH_PLUGIN_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(config.XDGConfigHome(), "plugins")
}

// validPluginName allows 1..64 ASCII letters, digits, '-' and '_'. That
// allowlist already excludes separators, dots, NUL and spaces, so the name is
// one path component.
func validPluginName(name string) bool {
	if name == "" || len(name) > pluginNameMax {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func checkPluginNames(names []string) error {
	for _, name := range names {
		if !validPluginName(name) {
			return fmt.Errorf("plugin: invalid name")
		}
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, ok := seen[name]; ok {
			return fmt.Errorf("plugin: name %q already exists", name)
		}
		seen[name] = struct{}{}
	}
	if len(names) > pluginEntryMax {
		return fmt.Errorf("plugin: too many names")
	}
	return nil
}

func pluginDefinedName(name string) bool {
	if name == "sys" || name == "plugins" || strings.HasPrefix(name, "__") {
		return false
	}
	if !validStarlarkIdent(name) {
		return false
	}
	if _, reserved := pluginKeywords[name]; reserved {
		return false
	}
	return true
}

func validStarlarkIdent(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func attachClose(err, cerr error) error {
	if err != nil && cerr != nil {
		return fmt.Errorf("%w (close: %v)", err, cerr)
	}
	if cerr != nil {
		return fmt.Errorf("plugin: %w", cerr)
	}
	return err
}

func mapFileErr(filename string, err error) error {
	if errors.Is(err, safefile.ErrSymlink) || errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
		return fmt.Errorf("plugin: %s is a symlink", filename)
	}
	if os.IsNotExist(err) {
		return fmt.Errorf("plugin: %s not found", filename)
	}
	return fmt.Errorf("plugin: %w", err)
}

func mapDirErr(name string, err error) error {
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
		return fmt.Errorf("plugin: %s is a symlink", name)
	}
	if errors.Is(err, syscall.ENOTDIR) {
		return fmt.Errorf("plugin: unexpected entry")
	}
	if os.IsNotExist(err) {
		return fmt.Errorf("plugin: %s not found", name)
	}
	return fmt.Errorf("plugin: %w", err)
}

func openPluginRoot() (*os.File, error) {
	dir := pluginDir()
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("plugin: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("plugin: root is a symlink")
	}
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, fmt.Errorf("plugin: root is a symlink")
		}
		return nil, fmt.Errorf("plugin: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		return nil, attachClose(fmt.Errorf("plugin: %w", err), f.Close())
	}
	if !pluginOwned(st) {
		return nil, attachClose(fmt.Errorf("plugin: root is not owned by the current user"), f.Close())
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, attachClose(fmt.Errorf("plugin: root is group/world writable"), f.Close())
	}
	if !st.IsDir() {
		return nil, attachClose(fmt.Errorf("plugin: root is not a directory"), f.Close())
	}
	return f, nil
}

func isSymlinkAt(parent *os.File, name string) bool {
	var st unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	runtime.KeepAlive(parent)
	return err == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK
}

func openAt(parent *os.File, name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	runtime.KeepAlive(parent)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		if cerr := syscall.Close(fd); cerr != nil {
			return nil, fmt.Errorf("plugin: %w", cerr)
		}
		return nil, fmt.Errorf("plugin: open failed")
	}
	return f, nil
}

// readCheckedFile opens filename in dir through internal/safefile, which
// refuses a symlink or a non-regular file and checks the opened descriptor,
// then requires the effective user as owner and no group/world write bit.
// With read false it only checks.
func readCheckedFile(dir *os.File, filename string, max int64, read bool) ([]byte, error) {
	f, st, err := safefile.Open(dir, filename)
	if err != nil {
		if errors.Is(err, safefile.ErrNotRegular) {
			return nil, fmt.Errorf("plugin: %s is not a regular file", filename)
		}
		return nil, mapFileErr(filename, err)
	}
	if !pluginOwned(st) {
		return nil, attachClose(fmt.Errorf("plugin: %s is not owned by the current user", filename), f.Close())
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, attachClose(fmt.Errorf("plugin: %s is group/world writable", filename), f.Close())
	}
	if st.Size() > max {
		return nil, attachClose(fmt.Errorf("plugin: %s is too large", filename), f.Close())
	}
	if !read {
		if cerr := f.Close(); cerr != nil {
			return nil, fmt.Errorf("plugin: %w", cerr)
		}
		return nil, nil
	}
	body, err := safefile.ReadAll(f, st, max)
	cerr := f.Close()
	if errors.Is(err, safefile.ErrTooLarge) {
		return nil, fmt.Errorf("plugin: %s is too large", filename)
	}
	if err != nil {
		return nil, attachClose(fmt.Errorf("plugin: %w", err), cerr)
	}
	if cerr != nil {
		return nil, fmt.Errorf("plugin: %w", cerr)
	}
	return body, nil
}

func readPlugin(root *os.File, name string, parse bool) (pluginSource, error) {
	dir, err := openAt(root, name, syscall.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil {
		// Darwin reports a symlink opened with O_DIRECTORY as ENOTDIR.
		if errors.Is(err, syscall.ENOTDIR) && isSymlinkAt(root, name) {
			return pluginSource{}, fmt.Errorf("plugin: %s is a symlink", name)
		}
		return pluginSource{}, mapDirErr(name, err)
	}
	st, err := dir.Stat()
	if err != nil {
		return pluginSource{}, attachClose(fmt.Errorf("plugin: %w", err), dir.Close())
	}
	if !pluginOwned(st) {
		return pluginSource{}, attachClose(fmt.Errorf("plugin: %s is not owned by the current user", name), dir.Close())
	}
	if st.Mode().Perm()&0o022 != 0 {
		return pluginSource{}, attachClose(fmt.Errorf("plugin: %s is group/world writable", name), dir.Close())
	}
	manifest, err := readCheckedFile(dir, pluginManifestName, pluginManifestMax, true)
	if err != nil {
		return pluginSource{}, attachClose(err, dir.Close())
	}
	star, err := readCheckedFile(dir, pluginSourceName, pluginSourceMax, parse)
	if err != nil {
		return pluginSource{}, attachClose(err, dir.Close())
	}
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return pluginSource{}, attachClose(fmt.Errorf("plugin: %w", err), dir.Close())
	}
	for _, ent := range entries {
		n := ent.Name()
		if n == pluginManifestName || n == pluginSourceName {
			continue
		}
		return pluginSource{}, attachClose(fmt.Errorf("plugin: unexpected entry"), dir.Close())
	}
	if cerr := dir.Close(); cerr != nil {
		return pluginSource{}, fmt.Errorf("plugin: %w", cerr)
	}
	desc, err := parseManifest(name, manifest)
	if err != nil {
		return pluginSource{}, err
	}
	if parse {
		if err := parseStar(name, star); err != nil {
			return pluginSource{}, err
		}
	}
	return pluginSource{name: name, description: desc, star: star}, nil
}

func inspectRootEntry(root *os.File, ent os.DirEntry, parse bool) (pluginSource, error) {
	name := ent.Name()
	if !validPluginName(name) {
		return pluginSource{}, fmt.Errorf("plugin: unexpected entry")
	}
	typ := ent.Type()
	if typ&os.ModeSymlink != 0 {
		return pluginSource{}, fmt.Errorf("plugin: %s is a symlink", name)
	}
	if typ != 0 && !typ.IsDir() {
		return pluginSource{}, fmt.Errorf("plugin: unexpected entry")
	}
	return readPlugin(root, name, parse)
}

func preflightAll(root *os.File) ([]pluginSource, error) {
	entries, err := root.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("plugin: %w", err)
	}
	if len(entries) > pluginEntryMax {
		return nil, fmt.Errorf("plugin: too many entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var sources []pluginSource
	var first error
	for _, ent := range entries {
		src, err := inspectRootEntry(root, ent, true)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		sources = append(sources, src)
	}
	if first != nil {
		return nil, first
	}
	return sources, nil
}

func preflightNames(root *os.File, names []string) ([]pluginSource, error) {
	var sources []pluginSource
	var first error
	for _, name := range names {
		src, err := readPlugin(root, name, true)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		sources = append(sources, src)
	}
	if first != nil {
		return nil, first
	}
	return sources, nil
}

func parseManifest(dirName string, raw []byte) (string, error) {
	if strings.TrimSpace(string(raw)) == "" {
		return "", fmt.Errorf("plugin: manifest is not valid")
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return "", fmt.Errorf("plugin: manifest is not valid")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != nil {
		if !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("plugin: trailing document")
		}
	} else {
		return "", fmt.Errorf("plugin: trailing document")
	}
	if err := rejectYAMLAliases(&doc); err != nil {
		return "", fmt.Errorf("plugin: %w", err)
	}
	return manifestFields(dirName, &doc)
}

func manifestFields(dirName string, doc *yaml.Node) (string, error) {
	node := doc
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) != 1 {
			return "", fmt.Errorf("plugin: manifest is not valid")
		}
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return "", fmt.Errorf("plugin: manifest is not valid")
	}
	seen := map[string]struct{}{}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode {
			return "", fmt.Errorf("plugin: manifest is not valid")
		}
		if key.Value == "<<" || key.Tag == "!!merge" {
			return "", fmt.Errorf("plugin: unknown field")
		}
		if key.Tag != "!!str" {
			return "", fmt.Errorf("plugin: manifest is not valid")
		}
		if key.Value != "name" && key.Value != "description" {
			return "", fmt.Errorf("plugin: unknown field")
		}
		if _, ok := seen[key.Value]; ok {
			return "", fmt.Errorf("plugin: duplicate field")
		}
		seen[key.Value] = struct{}{}
	}
	var name, desc string
	hasName := false
	hasDesc := false
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		switch key.Value {
		case "name":
			if val.Kind != yaml.ScalarNode || val.Tag != "!!str" {
				return "", fmt.Errorf("plugin: name must be a string")
			}
			name = val.Value
			hasName = true
		case "description":
			if val.Kind != yaml.ScalarNode || val.Tag != "!!str" {
				return "", fmt.Errorf("plugin: description must be a string")
			}
			desc = val.Value
			hasDesc = true
		}
	}
	if !hasName {
		return "", fmt.Errorf("plugin: manifest is not valid")
	}
	if name != dirName {
		return "", fmt.Errorf("plugin: name does not match directory")
	}
	if !hasDesc {
		return "", nil
	}
	if len(desc) > pluginDescriptionMax {
		return "", fmt.Errorf("plugin: description is too large")
	}
	for i := 0; i < len(desc); i++ {
		if desc[i] < 0x20 || desc[i] == 0x7f {
			return "", fmt.Errorf("plugin: description contains a control character")
		}
	}
	return desc, nil
}

func parseStar(name string, src []byte) error {
	if _, err := syntax.Parse(name+"/"+pluginSourceName, src, 0); err != nil {
		return fmt.Errorf("plugin: syntax error")
	}
	return nil
}

// LoadStarlarkPlugins reads checked Starlark plugins into globals.
// A batch that fails any check or execution leaves the session unchanged.
func LoadStarlarkPlugins(globals starlark.StringDict, names []string, all bool) ([]string, error) {
	if len(names) > 0 && all {
		return nil, fmt.Errorf("plugin: pass names or all, not both")
	}
	if len(names) == 0 && !all {
		return nil, fmt.Errorf("plugin: pass names or all=True")
	}
	if !all {
		if err := checkPluginNames(names); err != nil {
			return nil, err
		}
	}
	if globals == nil {
		return nil, fmt.Errorf("plugin: session is not available")
	}
	if err := requirePluginDicts(globals); err != nil {
		return nil, err
	}
	root, err := openPluginRoot()
	if err != nil {
		if os.IsNotExist(err) {
			if all {
				return nil, nil
			}
			return nil, fmt.Errorf("plugin: %s not found", names[0])
		}
		return nil, err
	}
	var sources []pluginSource
	if all {
		sources, err = preflightAll(root)
	} else {
		sources, err = preflightNames(root, names)
	}
	cerr := root.Close()
	if err != nil {
		if cerr != nil {
			return nil, fmt.Errorf("%w (close: %v)", err, cerr)
		}
		return nil, err
	}
	if cerr != nil {
		return nil, fmt.Errorf("plugin: %w", cerr)
	}
	if len(sources) == 0 {
		return nil, nil
	}
	return executePlugins(globals, sources)
}

func requirePluginDicts(g starlark.StringDict) error {
	if _, ok := g["__custom_commands__"].(*starlark.Dict); !ok {
		return fmt.Errorf("plugin: plugins record is not valid")
	}
	plugins, ok := g["plugins"].(*starlark.Dict)
	if !ok {
		return fmt.Errorf("plugin: plugins record is not valid")
	}
	if v, present := g["__completers__"]; present {
		if _, isDict := v.(*starlark.Dict); !isDict {
			return fmt.Errorf("plugin: plugins record is not valid")
		}
	}
	for _, item := range plugins.Items() {
		rec, ok := item[1].(*starlark.Dict)
		if !ok {
			return fmt.Errorf("plugin: plugins record is not valid")
		}
		exp, found, err := rec.Get(starlark.String("exports"))
		if err != nil || (found && (exp == nil || exp == starlark.None)) {
			return fmt.Errorf("plugin: plugins record is not valid")
		}
		if !found {
			continue
		}
		if _, ok := exp.(*starlark.List); !ok {
			return fmt.Errorf("plugin: plugins record is not valid")
		}
	}
	return nil
}

type sessionSnap struct {
	top           starlark.StringDict
	commands      *starlark.Dict
	plugins       *starlark.Dict
	completers    *starlark.Dict
	hadCompleters bool
	// restoreGlobal puts back the process-global completer map. Nil when no
	// snapshot hook is installed.
	restoreGlobal func()
}

var (
	globalCompleterMu       sync.Mutex
	globalCompleterSnapshot func() (restore func())
)

// SetGlobalCompleterSnapshot installs the hook that snapshots the deprecated
// process-global completer map, which lives in a package this one cannot
// import. The hook returns a function that restores the snapshot. A failed
// plugin load calls it so a completer the plugin registered does not outlive
// the rollback.
func SetGlobalCompleterSnapshot(fn func() (restore func())) {
	globalCompleterMu.Lock()
	globalCompleterSnapshot = fn
	globalCompleterMu.Unlock()
}

func cloneDict(d *starlark.Dict) (*starlark.Dict, error) {
	out := starlark.NewDict(d.Len())
	for _, item := range d.Items() {
		val, err := cloneValue(item[1])
		if err != nil {
			return nil, err
		}
		if err := out.SetKey(item[0], val); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func cloneList(l *starlark.List) (*starlark.List, error) {
	items := make([]starlark.Value, 0, l.Len())
	iter := l.Iterate()
	defer iter.Done()
	var v starlark.Value
	for iter.Next(&v) {
		c, err := cloneValue(v)
		if err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return starlark.NewList(items), nil
}

func cloneValue(v starlark.Value) (starlark.Value, error) {
	switch v := v.(type) {
	case *starlark.Dict:
		return cloneDict(v)
	case *starlark.List:
		return cloneList(v)
	default:
		return v, nil
	}
}

func snapshotSession(g starlark.StringDict) (*sessionSnap, error) {
	// Snapshot clones bags so failure can put them back.
	top := make(starlark.StringDict, len(g))
	for k, v := range g {
		top[k] = v
	}
	commands, ok := g["__custom_commands__"].(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("plugin: plugins record is not valid")
	}
	clonedCommands, err := cloneDict(commands)
	if err != nil {
		return nil, err
	}
	plugins, ok := g["plugins"].(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("plugin: plugins record is not valid")
	}
	clonedPlugins, err := cloneDict(plugins)
	if err != nil {
		return nil, err
	}
	snap := &sessionSnap{top: top, commands: clonedCommands, plugins: clonedPlugins}
	if v, present := g["__completers__"]; present {
		d, ok := v.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("plugin: plugins record is not valid")
		}
		cloned, err := cloneDict(d)
		if err != nil {
			return nil, err
		}
		snap.completers = cloned
		snap.hadCompleters = true
	}
	globalCompleterMu.Lock()
	hook := globalCompleterSnapshot
	globalCompleterMu.Unlock()
	if hook != nil {
		snap.restoreGlobal = hook()
	}
	return snap, nil
}

func restoreSession(g starlark.StringDict, snap *sessionSnap) {
	for k := range g {
		delete(g, k)
	}
	for k, v := range snap.top {
		g[k] = v
	}
	g["__custom_commands__"] = snap.commands
	g["plugins"] = snap.plugins
	if snap.hadCompleters {
		g["__completers__"] = snap.completers
	} else {
		delete(g, "__completers__")
	}
	if snap.restoreGlobal != nil {
		snap.restoreGlobal()
	}
}

func previousExports(snap *sessionSnap, name string) (map[string]struct{}, error) {
	rec, found, err := snap.plugins.Get(starlark.String(name))
	if err != nil {
		return nil, fmt.Errorf("plugin: plugins record is not valid")
	}
	if !found || rec == nil || rec == starlark.None {
		return map[string]struct{}{}, nil
	}
	d, ok := rec.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("plugin: plugins record is not valid")
	}
	exp, found, err := d.Get(starlark.String("exports"))
	if err != nil {
		return nil, fmt.Errorf("plugin: plugins record is not valid")
	}
	if !found || exp == nil {
		return map[string]struct{}{}, nil
	}
	if exp == starlark.None {
		return nil, fmt.Errorf("plugin: plugins record is not valid")
	}
	lst, ok := exp.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("plugin: plugins record is not valid")
	}
	out := map[string]struct{}{}
	iter := lst.Iterate()
	defer iter.Done()
	var item starlark.Value
	for iter.Next(&item) {
		s, ok := item.(starlark.String)
		if !ok {
			return nil, fmt.Errorf("plugin: plugins record is not valid")
		}
		out[string(s)] = struct{}{}
	}
	return out, nil
}

func hideExports(g starlark.StringDict, names map[string]struct{}) {
	// Hide so reload can rebind.
	for name := range names {
		if name == "sys" || name == "plugins" || strings.HasPrefix(name, "__") {
			continue
		}
		delete(g, name)
	}
}

type loadedModule struct {
	src  pluginSource
	dict starlark.StringDict
	prev map[string]struct{}
}

func executePlugins(g starlark.StringDict, sources []pluginSource) (loaded []string, err error) {
	snap, snapErr := snapshotSession(g)
	if snapErr != nil {
		return nil, snapErr
	}
	defer func() {
		if err != nil {
			restoreSession(g, snap)
		}
	}()
	mods := make([]loadedModule, 0, len(sources))
	for _, src := range sources {
		prev, herr := previousExports(snap, src.name)
		if herr != nil {
			return nil, herr
		}
		hideExports(g, prev)
		thread := &starlark.Thread{Name: "plugin-" + src.name}
		thread.SetMaxExecutionSteps(pluginSteps)
		dict, eerr := starlark.ExecFileOptions(syntax.LegacyFileOptions(), thread, src.name+"/"+pluginSourceName, src.star, g)
		if eerr != nil {
			return nil, eerr
		}
		if dict == nil {
			dict = starlark.StringDict{}
		}
		mods = append(mods, loadedModule{src: src, dict: dict, prev: prev})
	}
	if cerr := commitPlugins(g, snap, mods); cerr != nil {
		return nil, cerr
	}
	loaded = make([]string, len(sources))
	for i, src := range sources {
		loaded[i] = src.name
	}
	return loaded, nil
}

func commitPlugins(g starlark.StringDict, snap *sessionSnap, mods []loadedModule) error {
	type binding struct {
		name string
		val  starlark.Value
	}
	type planned struct {
		plugin   string
		desc     string
		exports  []string
		bindings []binding
	}
	claimed := map[string]struct{}{}
	plans := make([]planned, 0, len(mods))
	for _, m := range mods {
		keys := make([]string, 0, len(m.dict))
		for k := range m.dict {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		plan := planned{plugin: m.src.name, desc: m.src.description}
		for _, k := range keys {
			if !pluginDefinedName(k) {
				return fmt.Errorf("plugin: name %q cannot be defined by a plugin", k)
			}
			if _, ok := claimed[k]; ok {
				return fmt.Errorf("plugin: name %q already exists", k)
			}
			if _, inTop := snap.top[k]; inTop {
				if _, prev := m.prev[k]; !prev {
					return fmt.Errorf("plugin: name %q already exists", k)
				}
			}
			claimed[k] = struct{}{}
			plan.bindings = append(plan.bindings, binding{name: k, val: m.dict[k]})
			plan.exports = append(plan.exports, k)
		}
		plans = append(plans, plan)
	}
	plugins, ok := g["plugins"].(*starlark.Dict)
	if !ok {
		return fmt.Errorf("plugin: plugins record is not valid")
	}
	for _, plan := range plans {
		for _, b := range plan.bindings {
			g[b.name] = b.val
		}
		rec := starlark.NewDict(3)
		if err := rec.SetKey(starlark.String("name"), starlark.String(plan.plugin)); err != nil {
			return err
		}
		if err := rec.SetKey(starlark.String("description"), starlark.String(plan.desc)); err != nil {
			return err
		}
		vals := make([]starlark.Value, len(plan.exports))
		for i, name := range plan.exports {
			vals[i] = starlark.String(name)
		}
		if err := rec.SetKey(starlark.String("exports"), starlark.NewList(vals)); err != nil {
			return err
		}
		if err := plugins.SetKey(starlark.String(plan.plugin), rec); err != nil {
			return err
		}
	}
	return nil
}

type pluginBinary struct{}

func (pluginBinary) Name() string { return "plugin" }

func (pluginBinary) Description() string {
	return "Load checked Starlark plugins from the config plugins directory"
}

func (pluginBinary) Usage() string {
	return "plugin <list|load NAME|load --all|reload NAME|reload --all>"
}

func pluginUsageError() error {
	return fmt.Errorf("plugin: usage: %s", pluginBinary{}.Usage())
}

func parsePluginArgs(args []string) (list bool, names []string, all bool, err error) {
	if len(args) < 2 {
		return false, nil, false, pluginUsageError()
	}
	rest := args[2:]
	switch args[1] {
	case "list":
		if len(rest) != 0 {
			return false, nil, false, pluginUsageError()
		}
		return true, nil, false, nil
	case "load", "reload":
		if len(rest) != 1 {
			return false, nil, false, pluginUsageError()
		}
		if rest[0] == "--all" {
			return false, nil, true, nil
		}
		if rest[0] == "" || strings.HasPrefix(rest[0], "-") {
			return false, nil, false, pluginUsageError()
		}
		return false, []string{rest[0]}, false, nil
	default:
		return false, nil, false, pluginUsageError()
	}
}

func (pluginBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	restricted, globals, ok := VBinSession(ctx)
	if !ok {
		return fmt.Errorf("plugin: session is not available")
	}
	list, names, all, err := parsePluginArgs(args)
	if err != nil {
		return err
	}
	if list {
		return runPluginList(ctx)
	}
	if restricted {
		return fmt.Errorf("plugin: restricted: cannot load plugins")
	}
	if globals == nil {
		return fmt.Errorf("plugin: session is not available")
	}
	loaded, err := LoadStarlarkPlugins(globals, names, all)
	if err != nil {
		return err
	}
	return printLoaded(ctx, loaded)
}

var errPluginNoShell = errors.New("plugin: no shell context")

// pluginHandlerCtx returns the shell handler context of ctx. Run accepts a
// nil or bare context, and interp.HandlerCtx panics on one, so a missing
// handler context is reported instead.
func pluginHandlerCtx(ctx context.Context) (hc interp.HandlerContext, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return interp.HandlerCtx(ctx), true
}

func runPluginList(ctx context.Context) error {
	root, err := openPluginRoot()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	text, err := buildPluginList(root)
	cerr := root.Close()
	if err != nil {
		if cerr != nil {
			return fmt.Errorf("%w (close: %v)", err, cerr)
		}
		return err
	}
	if cerr != nil {
		return fmt.Errorf("plugin: %w", cerr)
	}
	if text == "" {
		return nil
	}
	hc, ok := pluginHandlerCtx(ctx)
	if !ok {
		return errPluginNoShell
	}
	out := hc.Stdout
	if out == nil {
		out = io.Discard
	}
	if _, werr := io.WriteString(out, text); werr != nil {
		return werr
	}
	return nil
}

func buildPluginList(root *os.File) (string, error) {
	entries, err := root.ReadDir(-1)
	if err != nil {
		return "", fmt.Errorf("plugin: %w", err)
	}
	if len(entries) > pluginEntryMax {
		return "", fmt.Errorf("plugin: too many entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var b strings.Builder
	for _, ent := range entries {
		src, err := inspectRootEntry(root, ent, false)
		if err != nil {
			if _, werr := fmt.Fprintf(&b, "%-24s ERROR: %v\n", ent.Name(), err); werr != nil {
				return "", werr
			}
			continue
		}
		if _, werr := fmt.Fprintf(&b, "%-24s %s\n", src.name, src.description); werr != nil {
			return "", werr
		}
	}
	return b.String(), nil
}

func printLoaded(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	var b strings.Builder
	for _, name := range names {
		if _, err := fmt.Fprintf(&b, "loaded %s\n", name); err != nil {
			return err
		}
	}
	hc, ok := pluginHandlerCtx(ctx)
	if !ok {
		return errPluginNoShell
	}
	out := hc.Stdout
	if out == nil {
		out = io.Discard
	}
	if _, err := io.WriteString(out, b.String()); err != nil {
		return err
	}
	return nil
}
