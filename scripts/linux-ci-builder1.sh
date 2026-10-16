#!/usr/bin/env bash
# Run adssh's Linux test binaries on builder1 without Go, a network fetch, or
# any delete on the host.
#
# The host has no Go and its egress firewall blocks go.dev, so the tests are
# cross-built here, bundled with the repo files they read, pushed through the
# fleet door, and run there as an unprivileged user (nobody, uid 65534).
#
#   scripts/linux-ci-builder1.sh build
#       On the Mac. Cross-builds the test binaries into dist-linux/<run-id>/,
#       tars them (refused at 256 MB or more) and prints the operator steps.
#   scripts/linux-ci-builder1.sh body <run-id> <tgz-sha256> <tgz-name>
#       Prints the one-argument host command the operator passes to vpsexec.
#       It does not contact the host.
#
# The operator types each vpsexec step: a plan, then the same line with
# --run --approve=<plan-hash>. Nothing here pushes, approves, or runs.
#
# Host layout. Each run gets a fresh root, /srv/adssh-ci/<run-id>, which the
# body refuses to reuse. HOME=<root>/home and TMPDIR=<root>/tmp are siblings,
# not nested, and neither is under a world-writable directory. The script
# never deletes anything on the host. The paths it creates are printed at the
# end; cleanup is a committed runbook in vpscfgfarm policies/ that the
# operator approves.
set -euo pipefail

host=builder1
scratch=/srv/adssh-ci
push_dir=/var/tmp/vpscfg-push
max_bytes=$((256 * 1024 * 1024))
# Packages built and run, in order. "." is the root package.
packages=(. ./engine ./security ./internal/sys ./internal/repl ./internal/guard ./internal/starlarkext ./internal/safefile ./internal/grid)
# Repo files the tests read by relative path, copied next to the packages.
repo_files=(policy docs/openapi)

die() { echo "linux-ci: $*" >&2; exit 1; }

valid_run_id() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; }
valid_sha() { [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
valid_name() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tgz$ ]]; }

# body prints the host command. Every substituted value is validated first,
# so nothing the caller passes is interpreted by the remote shell.
body() {
	local run_id=$1 sha=$2 name=$3
	valid_run_id "$run_id" || die "bad run id: $run_id"
	valid_sha "$sha" || die "bad sha256: $sha"
	valid_name "$name" || die "bad bundle name: $name"
	cat <<EOF
set -eu
umask 022
run=$scratch/$run_id
tgz=$push_dir/$sha/$name
echo "$sha  \$tgz" | sha256sum -c -
mkdir -p $scratch
chmod 0755 $scratch
mkdir -m 0700 "\$run"
mkdir -m 0700 "\$run/home" "\$run/tmp" "\$run/repo"
tar -xzf "\$tgz" -C "\$run/repo" --no-same-owner
chown -R 65534:65534 "\$run"
cd "\$run/repo"
nohup setsid setpriv --reuid=65534 --regid=65534 --clear-groups env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 HOME="\$run/home" TMPDIR="\$run/tmp" sh ./run-tests.sh > "\$run/run.log" 2>&1 < /dev/null &
echo "launched pid \$! as uid 65534"
echo "log: \$run/run.log"
echo "created on $host (not deleted by this run): \$run and $push_dir/$sha"
EOF
}

# run_tests_sh is the runner placed in the bundle. It runs as uid 65534 from
# the bundle root, and each test binary runs from its package directory, as
# go test would.
run_tests_sh() {
	cat <<'EOF'
#!/bin/sh
set -u
root=$(pwd)
echo "bundle: $(cat BUNDLE)"
echo "host: $(uname -srm)"
echo "id: $(id)"
echo "umask: $(umask)"
echo "HOME=$HOME TMPDIR=$TMPDIR"
fail=0
while read -r dir bin; do
	start=$(date +%s)
	(cd "$root/$dir" && "$root/$bin" -test.count=1 -test.timeout=15m)
	code=$?
	echo "PKG $dir EXIT=$code SECONDS=$(( $(date +%s) - start ))"
	[ "$code" -eq 0 ] || fail=$((fail + 1))
done < PACKAGES
echo "DONE failed_packages=$fail"
EOF
}

build() {
	local top rev stamp run_id out stage name tgz sha bytes dir bin pkg
	top=$(git rev-parse --show-toplevel)
	cd "$top"
	rev=$(git describe --always --dirty --abbrev=12)
	stamp=$(date -u +%Y%m%dT%H%M%SZ)
	run_id="$rev-$stamp"
	valid_run_id "$run_id" || die "bad run id: $run_id"
	out="dist-linux/$run_id"
	stage="$out/stage"
	[ ! -e "$out" ] || die "$out exists"
	mkdir -p "$stage/bin"

	: > "$stage/PACKAGES"
	for pkg in "${packages[@]}"; do
		dir=${pkg#./}
		if [ "$dir" = "." ]; then
			bin=bin/root.test
		else
			bin="bin/$(printf '%s' "$dir" | tr '/' '_').test"
		fi
		echo "building $pkg"
		GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -ldflags='-s -w' -o "$stage/$bin" "$pkg"
		mkdir -p "$stage/$dir"
		if [ -d "$dir/testdata" ]; then
			cp -R "$dir/testdata" "$stage/$dir/"
		fi
		echo "$dir $bin" >> "$stage/PACKAGES"
	done
	for f in "${repo_files[@]}"; do
		mkdir -p "$stage/$(dirname "$f")"
		cp -R "$f" "$stage/$(dirname "$f")/"
	done
	run_tests_sh > "$stage/run-tests.sh"
	chmod 0755 "$stage/run-tests.sh"
	echo "$run_id" > "$stage/BUNDLE"

	name="adssh-tests-$run_id.tgz"
	tgz="$out/$name"
	COPYFILE_DISABLE=1 tar -czf "$tgz" -C "$stage" .
	bytes=$(wc -c < "$tgz" | tr -d ' ')
	[ "$bytes" -lt "$max_bytes" ] || die "$tgz is $bytes bytes, limit $max_bytes"
	sha=$(shasum -a 256 "$tgz" | cut -d' ' -f1)

	cat <<EOF

Bundle: $tgz ($bytes bytes)
sha256: $sha
run id: $run_id

Operator steps. Type each line, read the plan, then repeat it with
--run --approve=<plan-hash>.

1. Push the bundle:
   ~/bin/vpsexec $host push $tgz --sha256 $sha --reason "adssh Linux tests $run_id"

2. Start the run (as uid 65534, under $scratch/$run_id):
   ~/bin/vpsexec $host "\$(scripts/linux-ci-builder1.sh body $run_id $sha $name)" --reason "adssh Linux tests $run_id"

3. Read the log (a read, no approval):
   ~/bin/vpsexec $host 'tail -n 120 $scratch/$run_id/run.log'
   The run is finished when the log ends with DONE.

Paths this run creates on $host (not deleted by this script):
   $scratch/$run_id
   $push_dir/$sha
Cleanup is a committed runbook in vpscfgfarm policies/, approved by the operator.

Local files (on this Mac): $out
EOF
}

case "${1:-}" in
build)
	[ $# -eq 1 ] || die "usage: $0 build"
	build
	;;
body)
	[ $# -eq 4 ] || die "usage: $0 body <run-id> <tgz-sha256> <tgz-name>"
	body "$2" "$3" "$4"
	;;
*)
	die "usage: $0 build | body <run-id> <tgz-sha256> <tgz-name>"
	;;
esac
