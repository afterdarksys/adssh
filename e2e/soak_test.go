//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestConcurrencySoak launches N parallel `adssh -c` invocations and then
// asserts every audit chain verifies intact.
//
// Sharing model (documented deliberately): security.AppendChain has NO
// cross-process file locking — it does readLastChainLine() followed by an
// O_APPEND write. Two processes appending to a single shared ledger would race
// on the previous hash/seq and corrupt the chain. The concurrency model the
// binary actually supports safely is therefore ONE LEDGER PER PROCESS sharing a
// common directory and a common HMAC key. We pre-seed the shared key so the
// 20 workers do not race to generate (and clobber) it, give each worker its own
// ADSSH_AUDIT_LOG under the shared dir, run them in parallel, then verify each
// ledger via the `audit verify` CLI (which reads the shared key).
func TestConcurrencySoak(t *testing.T) {
	const n = 20

	sb := newSandbox(t)
	sb.seedChainKey() // shared HMAC key, pre-created to avoid a generation race

	ledgerFor := func(i int) string {
		return filepath.Join(sb.dir, fmt.Sprintf("audit-%02d.log", i))
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all goroutines together for real contention
			res := run(t, adsshBin, sb.env(ledgerFor(i)), "",
				"-c", fmt.Sprintf("echo soak-worker-%02d", i))
			if res.exitCode != 0 {
				errs[i] = fmt.Errorf("worker %d exit=%d stderr=%q", i, res.exitCode, res.stderr)
				return
			}
			if !strings.Contains(res.stdout, fmt.Sprintf("soak-worker-%02d", i)) {
				errs[i] = fmt.Errorf("worker %d missing output: %q", i, res.stdout)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	for _, e := range errs {
		if e != nil {
			t.Fatalf("soak worker failed: %v", e)
		}
	}

	// Every per-process ledger must exist and verify intact, both via the CLI
	// and structurally.
	for i := 0; i < n; i++ {
		ledger := ledgerFor(i)
		chain := ledger + ".chain"

		verify := run(t, adsshBin, sb.env(ledger), "", "-c", "audit verify")
		if verify.exitCode != 0 {
			t.Fatalf("audit verify (ledger %d) exit=%d stderr=%q", i, verify.exitCode, verify.stderr)
		}
		if !strings.Contains(verify.stdout, "PASS") {
			t.Fatalf("audit verify (ledger %d) did not report PASS: stdout=%q stderr=%q",
				i, verify.stdout, verify.stderr)
		}
		assertChainStructurallyIntact(t, chain)
	}
}
