package security

// Threats:
//   Several processes on one host (two REPL windows, adssh plus adssh-mcp) share
//   one ledger and one key. Without a cross-process lock each process appends
//   from its own idea of the tail, the chain forks into duplicate seqs, and
//   VerifyChain fails for good, which hides a real tamper behind the fork. These
//   tests prove that appends from two engines and from two OS processes stay one
//   contiguous chain, that a lock held past the bound fails closed instead of
//   hanging, and that a tail whose HMAC does not verify blocks the next append.

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const chainHelperEnv = "ADSSH_CHAIN_HELPER"

// TestChainHelperProcess is not a test. The tests below run the test binary
// again with chainHelperEnv set, so that a second OS process touches the ledger.
func TestChainHelperProcess(t *testing.T) {
	mode := os.Getenv(chainHelperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	ledger := os.Getenv("ADSSH_CHAIN_LEDGER")
	switch mode {
	case "append":
		n, err := strconv.Atoi(os.Getenv("ADSSH_CHAIN_N"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad N:", err)
			os.Exit(2)
		}
		eng, err := NewEngine(EngineConfig{ChainPath: ledger, ChainKeyPath: os.Getenv("ADSSH_CHAIN_KEY"), SessionID: "helper"})
		if err != nil {
			fmt.Fprintln(os.Stderr, "NewEngine:", err)
			os.Exit(2)
		}
		for i := 0; i < n; i++ {
			if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("pid%d-%d", os.Getpid(), i)}); err != nil {
				fmt.Fprintln(os.Stderr, "AppendChain:", err)
				os.Exit(1)
			}
		}
		os.Exit(0)
	case "hold":
		f, err := os.OpenFile(ledger, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			os.Exit(2)
		}
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
			fmt.Fprintln(os.Stderr, "flock:", err)
			os.Exit(2)
		}
		fmt.Println("locked")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "key":
		key, err := loadOrCreateChainKey(os.Getenv("ADSSH_CHAIN_KEY"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "loadOrCreateChainKey:", err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(key))
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func chainHelperCmd(t *testing.T, mode, ledger, key string, n int) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChainHelperProcess$")
	cmd.Env = append(os.Environ(),
		chainHelperEnv+"="+mode,
		"ADSSH_CHAIN_LEDGER="+ledger,
		"ADSSH_CHAIN_KEY="+key,
		"ADSSH_CHAIN_N="+strconv.Itoa(n),
	)
	return cmd
}

// assertContiguousChain checks the ledger verifies and holds seqs 0..want-1,
// each exactly once, in file order.
func assertContiguousChain(t *testing.T, eng *Engine, ledger string, want int) {
	t.Helper()
	ok, badSeq, err := eng.VerifyChain(ledger)
	if err != nil || !ok {
		t.Fatalf("VerifyChain: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
	lines := readChainLines(t, ledger)
	if len(lines) != want {
		t.Fatalf("expected %d lines, got %d", want, len(lines))
	}
	seen := map[int64]bool{}
	for i, l := range lines {
		e := unmarshalEntry(t, l)
		if e.Seq != int64(i) {
			t.Fatalf("line %d: seq %d, want %d", i, e.Seq, i)
		}
		if seen[e.Seq] {
			t.Fatalf("duplicate seq %d", e.Seq)
		}
		seen[e.Seq] = true
	}
}

func newSharedEngine(t *testing.T, ledger, key, session string) *Engine {
	t.Helper()
	eng, err := NewEngine(EngineConfig{ChainPath: ledger, ChainKeyPath: key, SessionID: session})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func TestChainShared_TwoEnginesInterleave(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.log.chain")
	key := filepath.Join(dir, "audit.key")
	a := newSharedEngine(t, ledger, key, "a")
	b := newSharedEngine(t, ledger, key, "b")

	const per = 50
	var wg sync.WaitGroup
	errs := make(chan error, 2*per)
	for _, eng := range []*Engine{a, b} {
		wg.Add(1)
		go func(eng *Engine) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: fmt.Sprintf("c%d", i)}); err != nil {
					errs <- err
				}
			}
		}(eng)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("AppendChain: %v", err)
	}
	assertContiguousChain(t, a, ledger, 2*per)
}

func TestChainShared_TwoProcesses(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.log.chain")
	key := filepath.Join(dir, "audit.key")
	// Create the key first so both helpers load the same one.
	eng := newSharedEngine(t, ledger, key, "parent")

	const per = 50
	cmds := []*exec.Cmd{
		chainHelperCmd(t, "append", ledger, key, per),
		chainHelperCmd(t, "append", ledger, key, per),
	}
	outs := make([]strings.Builder, len(cmds))
	for i, c := range cmds {
		c.Stderr = &outs[i]
		if err := c.Start(); err != nil {
			t.Fatalf("start helper: %v", err)
		}
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("helper %d: %v: %s", i, err, outs[i].String())
		}
	}
	assertContiguousChain(t, eng, ledger, 2*per)
}

func TestChainShared_LockHeldTooLongFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.log.chain")
	key := filepath.Join(dir, "audit.key")
	eng := newSharedEngine(t, ledger, key, "parent")
	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "before"}); err != nil {
		t.Fatalf("AppendChain: %v", err)
	}

	holder := chainHelperCmd(t, "hold", ledger, key, 0)
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatalf("start holder: %v", err)
	}
	t.Cleanup(func() {
		_ = holder.Process.Kill()
		_ = holder.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		t.Fatalf("holder did not take the lock: %q %v", line, err)
	}

	start := time.Now()
	err = eng.AppendChain(ChainEntry{Type: "cmd", Command: "blocked"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected AppendChain to fail closed while another process holds the lock")
	}
	if elapsed > 7*time.Second {
		t.Fatalf("AppendChain took %v; the lock wait must be bounded", elapsed)
	}
	if elapsed < chainLockTimeout/2 {
		t.Fatalf("AppendChain gave up after %v; expected it to wait for the bound", elapsed)
	}
	if n := len(readChainLines(t, ledger)); n != 1 {
		t.Fatalf("failed append wrote to the ledger: %d lines", n)
	}

	// Once the holder exits, appends work again and the chain is intact.
	_ = holder.Process.Kill()
	_ = holder.Wait()
	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "after"}); err != nil {
		t.Fatalf("AppendChain after release: %v", err)
	}
	assertContiguousChain(t, eng, ledger, 2)
}

func TestChainShared_CorruptTailFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.log.chain")
	key := filepath.Join(dir, "audit.key")
	eng := buildNegChain(t, ledger, key, 3) // tail cache is warm

	lines := readChainLines(t, ledger)
	tail := unmarshalEntry(t, lines[2])
	tail.Command = "rm -rf /evidence"
	lines[2] = marshalEntry(t, tail)
	writeChainLines(t, ledger, lines)
	before, _ := os.ReadFile(ledger)

	err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "next"})
	if err == nil {
		t.Fatal("expected AppendChain to refuse a tail whose HMAC does not verify")
	}
	after, _ := os.ReadFile(ledger)
	if string(before) != string(after) {
		t.Fatal("failed append changed the ledger")
	}

	// A fresh engine with the same key refuses too.
	other := newSharedEngine(t, ledger, key, "other")
	if err := other.AppendChain(ChainEntry{Type: "cmd", Command: "next"}); err == nil {
		t.Fatal("expected a fresh engine to refuse the corrupt tail")
	}
}

func TestChainShared_PartialTailFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "audit.log.chain")
	key := filepath.Join(dir, "audit.key")
	eng := buildNegChain(t, ledger, key, 2)

	f, err := os.OpenFile(ledger, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"seq":2,"ts":"x"`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := eng.AppendChain(ChainEntry{Type: "cmd", Command: "next"}); err == nil {
		t.Fatal("expected AppendChain to refuse a partial tail line")
	}
}
