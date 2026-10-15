// Package guard is the SSH listener jail. It counts failed handshakes and
// connection rate per peer address and refuses a banned peer before the
// handshake.
//
// Threats: a missing config uses built-in defaults. A corrupt, oversized,
// symlink, or group/world-writable config fails closed. A corrupt, oversized,
// symlink, or loose-mode state file refuses the listener. A failed state
// write denies non-ignored peers until reload. Ignored addresses are not
// counted. This does not install firewall rules and does not log key
// material. The state file is not signed. A local user who can write that
// file can remove a ban. A successful handshake does not clear strikes. An
// explicit empty ignore list does not spare loopback. ADSSH_GUARD=off skips
// the files so a bad file cannot block startup.
package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	maxConfigBytes = 64 * 1024
	maxStateBytes  = 1 << 20
	stateVersion   = 1
	maxBanHorizon  = 366 * 24 * time.Hour
)

// ErrNotBanned is returned when unban is asked to remove an address that is
// not in the ban table.
var ErrNotBanned = errors.New("not_banned")

// ErrBadPeer is returned when an address is not an IP or host:port.
var ErrBadPeer = errors.New("bad_peer")

// ErrInactive is returned when the jail has not been configured, or when
// ADSSH_GUARD forces it off.
var ErrInactive = errors.New("guard is not active")

// Options selects the config file, the ban file, and the process switch.
type Options struct {
	ConfigPath string
	StatePath  string
	Switch     string
}

// Decision is the result of Admit.
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
	Addr   string `json:"addr,omitempty"`
}

// Event is one audit record. Action and Reason are fixed tokens.
type Event struct {
	Action string
	Addr   string
	Reason string
}

// Ban is one active ban.
type Ban struct {
	Addr   string    `json:"addr"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

// Snapshot is the operator view of the jail.
type Snapshot struct {
	Enabled    bool     `json:"enabled"`
	ForcedOff  bool     `json:"forced_off"`
	Tripped    string   `json:"tripped,omitempty"`
	ConfigPath string   `json:"config_path"`
	StatePath  string   `json:"state_path"`
	FindTime   string   `json:"find_time"`
	MaxRetry   int      `json:"max_retry"`
	BanTime    string   `json:"ban_time"`
	RateLimit  int      `json:"rate_limit"`
	RateWindow string   `json:"rate_window"`
	MaxEntries int      `json:"max_entries"`
	Ignore     []string `json:"ignore"`
	Bans       []Ban    `json:"bans"`
}

type fileConfig struct {
	Enabled    *bool     `yaml:"enabled"`
	FindTime   *string   `yaml:"find_time"`
	MaxRetry   *int      `yaml:"max_retry"`
	BanTime    *string   `yaml:"ban_time"`
	RateLimit  *int      `yaml:"rate_limit"`
	RateWindow *string   `yaml:"rate_window"`
	MaxEntries *int      `yaml:"max_entries"`
	Ignore     *[]string `yaml:"ignore"`
}

type config struct {
	enabled    bool
	findTime   time.Duration
	maxRetry   int
	banTime    time.Duration
	rateLimit  int
	rateWindow time.Duration
	maxEntries int
	ignore     []*net.IPNet
	ignoreText []string
}

type banRec struct {
	until  time.Time
	reason string
}

type peerState struct {
	strikes []time.Time
	rates   []time.Time
}

type stateMeta struct {
	saw   bool
	mtime time.Time
	size  int64
}

type service struct {
	mu         sync.Mutex
	cfg        config
	configPath string
	statePath  string
	forceOff   bool
	forceOn    bool
	tripped    error
	sawState   bool
	stateMtime time.Time
	stateSize  int64
	bans       map[string]banRec
	peers      map[string]*peerState
}

type stateFile struct {
	V    int        `json:"v"`
	Bans []stateBan `json:"bans"`
}

type stateBan struct {
	Addr   string    `json:"addr"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

var (
	pkgMu    sync.Mutex
	svc      *service
	recorder func(Event)
	now      = func() time.Time { return time.Now() }
)

// SetRecorder installs the audit callback. The callback runs without the
// jail lock held.
func SetRecorder(fn func(Event)) {
	pkgMu.Lock()
	recorder = fn
	pkgMu.Unlock()
}

// ResetForTest drops the process jail and the recorder. It leaves the clock
// function alone so a test can install a clock before startup.
func ResetForTest() {
	pkgMu.Lock()
	svc = nil
	recorder = nil
	pkgMu.Unlock()
}

// ParseSwitch reads ADSSH_GUARD. An empty value defers to the config file.
// off forces the jail off. on forces it on.
func ParseSwitch(raw string) (forceOff, forceOn bool, err error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return false, false, nil
	case "0", "false", "no", "off":
		return true, false, nil
	case "1", "true", "yes", "on":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("invalid ADSSH_GUARD value %q", raw)
	}
}

// ValidateSwitch reports whether ADSSH_GUARD is a known value.
func ValidateSwitch(raw string) error {
	_, _, err := ParseSwitch(raw)
	return err
}

// CheckConfig parses a config file without replacing the live jail. A
// missing file is valid because the built-in defaults apply.
func CheckConfig(path string) error {
	_, err := loadConfig(path)
	return err
}

// CheckState parses a ban file without replacing the live jail. A missing
// file returns os.ErrNotExist.
func CheckState(path string) error {
	if path == "" {
		return errors.New("guard state path is empty")
	}
	_, _, err := loadState(path)
	if os.IsNotExist(err) {
		return os.ErrNotExist
	}
	return err
}

// Configure loads the jail for this process. A bad switch, config, or state
// file installs a tripped jail and returns the error. ADSSH_GUARD=off skips
// both files.
func Configure(opt Options) error {
	forceOff, forceOn, err := ParseSwitch(opt.Switch)
	if err != nil {
		install(newService(opt, defaultConfig(), false, forceOn, err))
		return err
	}
	if forceOff {
		install(newService(opt, defaultConfig(), true, false, nil))
		return nil
	}
	if opt.StatePath == "" {
		err = errors.New("guard state path is empty")
		install(newService(opt, defaultConfig(), false, forceOn, err))
		return err
	}
	cfg, err := loadConfig(opt.ConfigPath)
	if err != nil {
		install(newService(opt, defaultConfig(), false, forceOn, err))
		return err
	}
	if forceOn {
		cfg.enabled = true
	}
	bans, meta, err := loadOptionalState(opt.StatePath)
	if err != nil {
		s := newService(opt, cfg, false, forceOn, err)
		install(s)
		return err
	}
	s := newService(opt, cfg, false, forceOn, nil)
	s.bans = bans
	s.sawState = meta.saw
	s.stateMtime = meta.mtime
	s.stateSize = meta.size
	install(s)
	return nil
}

// Ready reports whether the listener may accept connections. A jail that was
// never configured is ready. A tripped jail is not.
func Ready() error {
	s := current(false)
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forceOff {
		return nil
	}
	return s.tripped
}

// Status returns the effective config and the in-memory bans. It does not
// create a jail, and it does not read the ban file while the jail is tripped.
func Status() Snapshot {
	s := current(false)
	if s == nil {
		return snapshot(defaultConfig(), "", "", false, nil, nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tripped == nil && !s.forceOff {
		if err := s.refreshLocked(); err == nil {
			s.sweepLocked(now())
		}
	}
	return s.snapshotLocked()
}

// Admit decides whether a new TCP connection may start the SSH handshake.
func Admit(addr string) Decision {
	s := current(true)
	s.mu.Lock()
	d, evs := s.admitLocked(addr)
	s.mu.Unlock()
	emitAll(evs)
	return d
}

// NoteHandshake records the outcome of ssh.NewServerConn. A success is a
// no-op: it does not pardon strikes.
func NoteHandshake(addr string, ok bool) {
	if ok {
		return
	}
	s := current(true)
	s.mu.Lock()
	evs := s.noteHandshakeLocked(addr)
	s.mu.Unlock()
	emitAll(evs)
}

// Unban removes one ban and clears that address's strikes. The ban file is
// written before memory changes. The address may be an IP or host:port.
func Unban(addr string) (string, error) {
	key, _, err := parsePeer(addr)
	if err != nil {
		return "", ErrBadPeer
	}
	s := current(false)
	if s == nil {
		return "", ErrInactive
	}
	s.mu.Lock()
	evs, err := s.unbanLocked(key)
	s.mu.Unlock()
	emitAll(evs)
	if err != nil {
		return "", err
	}
	return key, nil
}

// Reload reads the config file and the ban file again. A bad config keeps
// the previous config. A bad ban file trips the jail. Reload trusts the
// files on disk, so a ban that never reached disk is gone after a successful
// reload.
func Reload() error {
	s := current(false)
	if s == nil {
		return errors.New("guard is not configured")
	}
	s.mu.Lock()
	evs, err := s.reloadLocked()
	s.mu.Unlock()
	emitAll(evs)
	return err
}

func newService(opt Options, cfg config, forceOff, forceOn bool, tripped error) *service {
	return &service{
		cfg:        cfg,
		configPath: opt.ConfigPath,
		statePath:  opt.StatePath,
		forceOff:   forceOff,
		forceOn:    forceOn,
		tripped:    tripped,
		stateSize:  -1,
		bans:       map[string]banRec{},
		peers:      map[string]*peerState{},
	}
}

func install(s *service) {
	pkgMu.Lock()
	svc = s
	pkgMu.Unlock()
}

func current(create bool) *service {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	if svc == nil && create {
		svc = &service{
			cfg:       defaultConfig(),
			stateSize: -1,
			bans:      map[string]banRec{},
			peers:     map[string]*peerState{},
		}
	}
	return svc
}

func (s *service) admitLocked(addr string) (Decision, []Event) {
	if s.forceOff || !s.cfg.enabled {
		return Decision{Allow: true, Addr: addr}, nil
	}
	key, ip, err := parsePeer(addr)
	if err != nil {
		return Decision{Allow: false, Reason: "bad_peer"}, nil
	}
	if ignored(s.cfg.ignore, ip) {
		return Decision{Allow: true, Addr: key}, nil
	}
	if s.tripped != nil {
		return Decision{Allow: false, Reason: "guard_unavailable", Addr: key}, nil
	}
	if err := s.refreshLocked(); err != nil {
		return Decision{Allow: false, Reason: "guard_unavailable", Addr: key}, nil
	}
	t := now()
	s.sweepLocked(t)
	if b, ok := s.bans[key]; ok && b.until.After(t) {
		return Decision{Allow: false, Reason: "banned", Addr: key}, nil
	}
	if len(s.bans) >= s.cfg.maxEntries {
		return Decision{Allow: false, Reason: "table_full", Addr: key}, nil
	}
	evs, banned := s.noteRateLocked(key, t)
	if banned {
		return Decision{Allow: false, Reason: "rate", Addr: key}, evs
	}
	return Decision{Allow: true, Addr: key}, nil
}

func (s *service) noteHandshakeLocked(addr string) []Event {
	if s.forceOff || !s.cfg.enabled || s.tripped != nil {
		return nil
	}
	if err := s.refreshLocked(); err != nil {
		return nil
	}
	key, ip, err := parsePeer(addr)
	if err != nil || ignored(s.cfg.ignore, ip) {
		return nil
	}
	t := now()
	s.sweepLocked(t)
	if b, ok := s.bans[key]; ok && b.until.After(t) {
		return nil
	}
	p := s.peerLocked(key)
	p.strikes = appendWindow(p.strikes, t, s.cfg.findTime, s.cfg.maxRetry)
	if len(p.strikes) < s.cfg.maxRetry {
		return nil
	}
	if _, exists := s.bans[key]; !exists && len(s.bans) >= s.cfg.maxEntries {
		return nil
	}
	return s.applyBanLocked(key, "handshake", t)
}

func (s *service) noteRateLocked(key string, t time.Time) ([]Event, bool) {
	p := s.peerLocked(key)
	p.rates = appendWindow(p.rates, t, s.cfg.rateWindow, s.cfg.rateLimit)
	if len(p.rates) < s.cfg.rateLimit {
		return nil, false
	}
	if _, exists := s.bans[key]; !exists && len(s.bans) >= s.cfg.maxEntries {
		return nil, false
	}
	return s.applyBanLocked(key, "rate", t), true
}

func (s *service) applyBanLocked(key, reason string, t time.Time) []Event {
	if s.bans == nil {
		s.bans = map[string]banRec{}
	}
	s.bans[key] = banRec{until: t.Add(s.cfg.banTime).UTC(), reason: reason}
	if err := s.persistLocked(); err != nil {
		s.tripped = fmt.Errorf("guard_unavailable: %w", err)
	}
	return []Event{
		{Action: "threshold", Addr: key, Reason: reason},
		{Action: "ban", Addr: key, Reason: reason},
	}
}

func (s *service) unbanLocked(key string) ([]Event, error) {
	if s.forceOff {
		return nil, ErrInactive
	}
	if s.tripped != nil {
		return nil, s.tripped
	}
	if err := s.refreshLocked(); err != nil {
		return nil, err
	}
	s.sweepLocked(now())
	if _, ok := s.bans[key]; !ok {
		return nil, ErrNotBanned
	}
	prev := s.bans
	next := make(map[string]banRec, len(prev)-1)
	for k, v := range prev {
		if k != key {
			next[k] = v
		}
	}
	s.bans = next
	if err := s.persistLocked(); err != nil {
		s.bans = prev
		return nil, err
	}
	delete(s.peers, key)
	return []Event{{Action: "unban", Addr: key, Reason: "operator"}}, nil
}

func (s *service) reloadLocked() ([]Event, error) {
	if s.forceOff {
		return nil, errors.New("guard is forced off")
	}
	cfg, err := loadConfig(s.configPath)
	if err != nil {
		return nil, err
	}
	if s.forceOn {
		cfg.enabled = true
	}
	s.cfg = cfg
	s.stateMtime = time.Time{}
	s.stateSize = -1
	if s.statePath == "" {
		s.tripped = errors.New("guard state path is empty")
		return nil, s.tripped
	}
	_, err = os.Lstat(s.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			if s.sawState {
				s.tripped = fmt.Errorf("guard_unavailable: state file disappeared")
				return nil, s.tripped
			}
			s.bans = map[string]banRec{}
			s.peers = map[string]*peerState{}
			s.tripped = nil
			return []Event{{Action: "reload", Reason: "config"}}, nil
		}
		s.tripped = fmt.Errorf("guard_unavailable: %w", err)
		return nil, s.tripped
	}
	bans, meta, err := loadState(s.statePath)
	if err != nil {
		s.tripped = fmt.Errorf("guard_unavailable: %w", err)
		return nil, s.tripped
	}
	for addr := range s.bans {
		if _, ok := bans[addr]; !ok {
			delete(s.peers, addr)
		}
	}
	s.bans = bans
	s.stateMtime = meta.mtime
	s.stateSize = meta.size
	s.sawState = true
	s.tripped = nil
	return []Event{{Action: "reload", Reason: "config"}}, nil
}

func (s *service) refreshLocked() error {
	if s.forceOff || s.statePath == "" {
		return nil
	}
	info, err := os.Lstat(s.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			if s.sawState {
				s.tripped = fmt.Errorf("guard_unavailable: state file disappeared")
				return s.tripped
			}
			return nil
		}
		s.tripped = fmt.Errorf("guard_unavailable: %w", err)
		return s.tripped
	}
	if s.sawState && info.ModTime().Equal(s.stateMtime) && info.Size() == s.stateSize {
		return nil
	}
	bans, meta, err := loadState(s.statePath)
	if err != nil {
		s.tripped = fmt.Errorf("guard_unavailable: %w", err)
		return s.tripped
	}
	for addr := range s.bans {
		if _, ok := bans[addr]; !ok {
			delete(s.peers, addr)
		}
	}
	s.bans = bans
	s.stateMtime = meta.mtime
	s.stateSize = meta.size
	s.sawState = true
	return nil
}

func (s *service) sweepLocked(t time.Time) {
	for addr, b := range s.bans {
		if !b.until.After(t) {
			delete(s.bans, addr)
		}
	}
}

func (s *service) peerLocked(key string) *peerState {
	if s.peers == nil {
		s.peers = map[string]*peerState{}
	}
	p := s.peers[key]
	if p == nil {
		p = &peerState{}
		s.peers[key] = p
	}
	return p
}

func (s *service) persistLocked() error {
	if s.statePath == "" {
		return errors.New("state path is empty")
	}
	dir := filepath.Dir(s.statePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	payload, err := s.marshalStateLocked()
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".guard-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.statePath); err != nil {
		return err
	}
	keep = true
	info, err := os.Lstat(s.statePath)
	if err != nil {
		return err
	}
	s.stateMtime = info.ModTime()
	s.stateSize = info.Size()
	s.sawState = true
	return nil
}

func (s *service) marshalStateLocked() ([]byte, error) {
	t := now()
	keys := make([]string, 0, len(s.bans))
	for addr, b := range s.bans {
		if b.until.After(t) {
			keys = append(keys, addr)
		}
	}
	sort.Strings(keys)
	doc := stateFile{V: stateVersion, Bans: make([]stateBan, 0, len(keys))}
	for _, addr := range keys {
		b := s.bans[addr]
		doc.Bans = append(doc.Bans, stateBan{
			Addr:   addr,
			Until:  b.until.UTC(),
			Reason: b.reason,
		})
	}
	return json.Marshal(doc)
}

func (s *service) snapshotLocked() Snapshot {
	return snapshot(s.cfg, s.configPath, s.statePath, s.forceOff, s.tripped, s.bans)
}

func snapshot(cfg config, configPath, statePath string, forceOff bool, tripped error, bans map[string]banRec) Snapshot {
	st := Snapshot{
		Enabled:    !forceOff && cfg.enabled,
		ForcedOff:  forceOff,
		ConfigPath: configPath,
		StatePath:  statePath,
		FindTime:   cfg.findTime.String(),
		MaxRetry:   cfg.maxRetry,
		BanTime:    cfg.banTime.String(),
		RateLimit:  cfg.rateLimit,
		RateWindow: cfg.rateWindow.String(),
		MaxEntries: cfg.maxEntries,
		Ignore:     append([]string{}, cfg.ignoreText...),
		Bans:       []Ban{},
	}
	if st.Ignore == nil {
		st.Ignore = []string{}
	}
	if tripped != nil {
		st.Tripped = tripped.Error()
	}
	t := now()
	for addr, b := range bans {
		if !b.until.After(t) {
			continue
		}
		st.Bans = append(st.Bans, Ban{Addr: addr, Until: b.until.UTC(), Reason: b.reason})
	}
	sort.Slice(st.Bans, func(i, j int) bool { return st.Bans[i].Addr < st.Bans[j].Addr })
	return st
}

func appendWindow(samples []time.Time, t time.Time, window time.Duration, capN int) []time.Time {
	cutoff := t.Add(-window)
	kept := make([]time.Time, 0, len(samples)+1)
	for _, ts := range samples {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, t)
	if capN > 0 && len(kept) > capN {
		kept = kept[len(kept)-capN:]
	}
	return kept
}

func defaultConfig() config {
	nets, text, err := parseIgnore([]string{"127.0.0.0/8", "::1/128"})
	if err != nil {
		panic(err)
	}
	return config{
		enabled:    true,
		findTime:   10 * time.Minute,
		maxRetry:   5,
		banTime:    time.Hour,
		rateLimit:  30,
		rateWindow: time.Minute,
		maxEntries: 10000,
		ignore:     nets,
		ignoreText: text,
	}
}

func loadConfig(path string) (config, error) {
	if path == "" {
		return defaultConfig(), nil
	}
	data, _, err := readRegular(path, maxConfigBytes, func(m os.FileMode) error {
		if m.Perm()&0o022 != 0 {
			return fmt.Errorf("%s is group or world writable", path)
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfig(), nil
		}
		return config{}, err
	}
	return parseConfigDocument(data)
}

func parseConfigDocument(data []byte) (config, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return config{}, errors.New("guard config is empty")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		if errors.Is(err, io.EOF) {
			return config{}, errors.New("guard config is empty")
		}
		return config{}, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return config{}, errors.New("guard config has multiple documents")
		}
		return config{}, err
	}
	explicitEmpty, err := ignoreExplicitEmpty(data)
	if err != nil {
		return config{}, err
	}
	return buildConfig(fc, explicitEmpty)
}

func ignoreExplicitEmpty(data []byte) (bool, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := dec.Decode(&node); err != nil {
		return false, err
	}
	doc := &node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return false, nil
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != "ignore" {
			continue
		}
		v := doc.Content[i+1]
		if v.Kind == yaml.SequenceNode && len(v.Content) == 0 {
			return true, nil
		}
		if v.Tag == "!!null" || (v.Kind == yaml.ScalarNode && (v.Value == "" || v.Value == "~" || v.Value == "null")) {
			return true, nil
		}
		return false, nil
	}
	return false, nil
}

func buildConfig(fc fileConfig, ignoreEmpty bool) (config, error) {
	cfg := defaultConfig()
	if fc.Enabled != nil {
		cfg.enabled = *fc.Enabled
	}
	var err error
	if cfg.findTime, err = parseDur("find_time", fc.FindTime, cfg.findTime, time.Second, 24*time.Hour); err != nil {
		return config{}, err
	}
	if cfg.banTime, err = parseDur("ban_time", fc.BanTime, cfg.banTime, time.Second, 8760*time.Hour); err != nil {
		return config{}, err
	}
	if cfg.rateWindow, err = parseDur("rate_window", fc.RateWindow, cfg.rateWindow, time.Second, time.Hour); err != nil {
		return config{}, err
	}
	if fc.MaxRetry != nil {
		if *fc.MaxRetry < 1 || *fc.MaxRetry > 100 {
			return config{}, fmt.Errorf("max_retry %d is outside 1..100", *fc.MaxRetry)
		}
		cfg.maxRetry = *fc.MaxRetry
	}
	if fc.RateLimit != nil {
		if *fc.RateLimit < 1 || *fc.RateLimit > 10000 {
			return config{}, fmt.Errorf("rate_limit %d is outside 1..10000", *fc.RateLimit)
		}
		cfg.rateLimit = *fc.RateLimit
	}
	if fc.MaxEntries != nil {
		if *fc.MaxEntries < 1 || *fc.MaxEntries > 100000 {
			return config{}, fmt.Errorf("max_entries %d is outside 1..100000", *fc.MaxEntries)
		}
		cfg.maxEntries = *fc.MaxEntries
	}
	if ignoreEmpty {
		cfg.ignore = nil
		cfg.ignoreText = []string{}
		return cfg, nil
	}
	if fc.Ignore != nil {
		nets, text, err := parseIgnore(*fc.Ignore)
		if err != nil {
			return config{}, err
		}
		cfg.ignore = nets
		cfg.ignoreText = text
	}
	if cfg.ignoreText == nil {
		cfg.ignoreText = []string{}
	}
	return cfg, nil
}

func parseDur(name string, raw *string, def, min, max time.Duration) (time.Duration, error) {
	if raw == nil {
		return def, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(*raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if d < min || d > max {
		return 0, fmt.Errorf("%s %s is outside %s..%s", name, d, min, max)
	}
	return d, nil
}

func parseIgnore(list []string) ([]*net.IPNet, []string, error) {
	nets := make([]*net.IPNet, 0, len(list))
	text := make([]string, 0, len(list))
	for _, raw := range list {
		item := strings.TrimSpace(raw)
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, nil, fmt.Errorf("ignore %q: %w", item, err)
		}
		ones, _ := n.Mask.Size()
		if ones == 0 {
			return nil, nil, fmt.Errorf("ignore %q: mask size 0 is rejected", item)
		}
		nets = append(nets, n)
		text = append(text, item)
	}
	return nets, text, nil
}

func ignored(nets []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		for _, cand := range ipCandidates(ip) {
			if n.Contains(cand) {
				return true
			}
		}
	}
	return false
}

func ipCandidates(ip net.IP) []net.IP {
	if v4 := ip.To4(); v4 != nil {
		mapped := make(net.IP, net.IPv6len)
		copy(mapped[12:], v4)
		mapped[10] = 0xff
		mapped[11] = 0xff
		return []net.IP{append(net.IP(nil), v4...), mapped}
	}
	if v16 := ip.To16(); v16 != nil {
		return []net.IP{v16}
	}
	return []net.IP{ip}
}

func loadOptionalState(path string) (map[string]banRec, stateMeta, error) {
	bans, meta, err := loadState(path)
	if os.IsNotExist(err) {
		return map[string]banRec{}, stateMeta{size: -1}, nil
	}
	return bans, meta, err
}

func loadState(path string) (map[string]banRec, stateMeta, error) {
	data, info, err := readRegular(path, maxStateBytes, func(m os.FileMode) error {
		if m.Perm() != 0o600 {
			return fmt.Errorf("%s mode is %o", path, m.Perm())
		}
		return nil
	})
	if err != nil {
		return nil, stateMeta{}, err
	}
	bans, err := parseState(data)
	if err != nil {
		return nil, stateMeta{}, err
	}
	return bans, stateMeta{saw: true, mtime: info.ModTime(), size: info.Size()}, nil
}

func parseState(data []byte) (map[string]banRec, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc stateFile
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("guard state: %w", err)
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("guard state has trailing data")
		}
		return nil, fmt.Errorf("guard state: %w", err)
	}
	if doc.V != stateVersion {
		return nil, fmt.Errorf("guard state version %d", doc.V)
	}
	out := map[string]banRec{}
	t := now()
	horizon := t.Add(maxBanHorizon)
	for _, b := range doc.Bans {
		ip := net.ParseIP(strings.TrimSpace(b.Addr))
		if ip == nil {
			return nil, fmt.Errorf("guard state addr %q", b.Addr)
		}
		key := canonicalIP(ip)
		if _, ok := out[key]; ok {
			return nil, fmt.Errorf("guard state duplicate addr %s", key)
		}
		if b.Reason != "handshake" && b.Reason != "rate" {
			return nil, fmt.Errorf("guard state reason %q", b.Reason)
		}
		if b.Until.IsZero() {
			return nil, errors.New("guard state until is zero")
		}
		if b.Until.After(horizon) {
			return nil, errors.New("guard state until is too far ahead")
		}
		if !b.Until.After(t) {
			continue
		}
		out[key] = banRec{until: b.Until.UTC(), reason: b.Reason}
	}
	return out, nil
}

func readRegular(path string, max int64, modeCheck func(os.FileMode) error) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, info, fmt.Errorf("%s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, info, fmt.Errorf("%s is not a regular file", path)
	}
	if err := modeCheck(info.Mode()); err != nil {
		return nil, info, err
	}
	if info.Size() > max {
		return nil, info, fmt.Errorf("%s is too large", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, info, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, info, err
	}
	if int64(len(data)) > max {
		return nil, info, fmt.Errorf("%s is too large", path)
	}
	return data, info, nil
}

func parsePeer(addr string) (string, net.IP, error) {
	host := strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return "", nil, ErrBadPeer
	}
	return canonicalIP(ip), ip, nil
}

func canonicalIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v16 := ip.To16(); v16 != nil {
		return v16.String()
	}
	return ip.String()
}

func emitAll(evs []Event) {
	if len(evs) == 0 {
		return
	}
	pkgMu.Lock()
	fn := recorder
	pkgMu.Unlock()
	if fn == nil {
		return
	}
	for _, ev := range evs {
		ev.Action = stripControls(ev.Action)
		ev.Addr = stripControls(ev.Addr)
		ev.Reason = stripControls(ev.Reason)
		if !allowedAction(ev.Action) || !allowedReason(ev.Reason) {
			continue
		}
		fn(ev)
	}
}

func stripControls(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func allowedAction(action string) bool {
	switch action {
	case "ban", "unban", "reload", "threshold":
		return true
	default:
		return false
	}
}

func allowedReason(reason string) bool {
	switch reason {
	case "handshake", "rate", "operator", "config":
		return true
	default:
		return false
	}
}
