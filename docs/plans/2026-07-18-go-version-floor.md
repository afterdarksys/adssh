# Finding — go.mod requires go 1.26.0 (adoption barrier for embedders)

**Logged:** 2026-07-18. **Status:** decision needed before/at v0.9.0 freeze.

## What
`go.mod` has `go 1.26.0` (a hard floor — no `toolchain` fallback line). Native build on the
dev/CI toolchain (go 1.24.6) FAILS; builds have silently been auto-fetching go 1.26 via
GOTOOLCHAIN=auto this whole time. The floor is NOT spurious — it's pinned by:
  k8s.io/api v0.36.0, k8s.io/apimachinery v0.36.0, k8s.io/client-go v0.36.0
all of which `require go >= 1.26.0` (k8s 1.36 client line).

## Why it matters
1. **Embeddable-library goal:** a library requiring go 1.26.0 is a real adoption barrier — the
   commercial platform must run a bleeding-edge toolchain just to import adssh. For an embedded
   dependency the go floor should be conservative (as low as the code actually needs).
2. **Blocking lint impossible:** golangci-lint has no release built against go 1.26, so it refuses
   to load a 1.26-targeted module ("Go version used to build golangci-lint is lower than the
   targeted Go version"). This failed CI's lint twice and is why the lint job is currently
   ADVISORY (continue-on-error) despite the errcheck/misspell backlog being fully cleaned.

## Options
- **A. Keep go 1.26 + latest k8s.** Consumers need go 1.26; lint stays advisory until golangci-lint
  ships a 1.26 build. Lowest effort, worst adoption posture. Document the consumer requirement.
- **B. Downgrade k8s.io/* to a go-1.24 line (e.g. v0.31.x) and lower go.mod to `go 1.24`
  (RECOMMENDED for the library goal).** Makes adssh consumable on mainstream Go AND lets lint
  become a hard gate immediately. Cost: k8s client-go API differences between v0.36 and v0.31 may
  require changes in starlarkext/k8s.go — must build + test the k8s namespace after. Bounded but
  non-trivial; risk of a cascade if the k8s API surface adssh uses moved.
- **C. Keep 1.26 now, revisit post-freeze.** Ship v0.9.0 documenting the go-1.26 requirement; do the
  k8s downgrade as a v0.9.1 dependency-hygiene pass.

## DECISION (2026-07-18, Ryan): Option C — keep go 1.26, move forward.
The dev machine and the deployment targets differ; the real deploy environments (RHEL and
others) ship the right Go version, so go 1.26 is not a barrier in practice for this product's
context. Ship v0.9.0 on go 1.26; lint stays advisory (continue-on-error) until golangci-lint
ships a 1.26 build. The k8s downgrade (Option B) is NOT pursued — revisit only if a consumer
actually hits the floor. No further action for the freeze.
