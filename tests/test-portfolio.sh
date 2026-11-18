#!/usr/bin/env bash
# tests/test-portfolio.sh — §73 portfolio-similarity (4.3(a) near-identical apps).
# Opt-in: without --portfolio (or config `.portfolio`) the rule prints nothing and is
# not a coverage gap, so default output is unchanged. With it, a near-duplicate
# sibling repo is a WARN (never FAIL — merging apps is a product decision).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=tests/_assert.sh
source "$HERE/_assert.sh"
SCAN="$ROOT/skills/appstore-precheck/scripts/scan.sh"

base="$(mktemp -d)"
cp -R "$HERE/fixtures/clean-app/." "$base/app/" 2>/dev/null || { mkdir -p "$base/app"; cp -R "$HERE/fixtures/clean-app/." "$base/app/"; }
cp -R "$base/app/." "$base/twin/"
mkdir -p "$base/other/ios/Other"
printf 'import SwiftUI\nstruct LedgerView: View { var body: some View { Text("Reconcile the quarterly ledger") } }\n' > "$base/other/ios/Other/Ledger.swift"

scan() { ( cd "$base/app" && APPSTORE_PRECHECK_CONFIG="${CFG:-/nonexistent}" bash "$SCAN" "$@" 2>&1 ); }

section "off by default: no line, no coverage gap"
out="$(scan)"
assert_absent "$out" "portfolio-similarity" "default scan never mentions the opt-in rule"

section "near-identical sibling is a WARN naming the sibling"
out="$(scan --portfolio "$base/twin")"
assert_contains "$out" "WARN: 4.3 portfolio-similarity" "a copied app trips §73"
assert_contains "$out" "twin overall 1.00" "the sibling and its score are named"
assert_absent   "$out" "FAIL: 4.3 portfolio-similarity" "never a FAIL"

section "a different app passes with its score shown"
out="$(scan --portfolio="$base/other")"
assert_contains "$out" "PASS: 4.3 portfolio-similarity" "an unrelated app passes"
assert_contains "$out" "below the 0.60 near-duplicate threshold" "and says why"

section "config .portfolio is honored when no flag is given"
printf '{"portfolio": ["%s"]}\n' "$base/twin" > "$base/cfg.json"
out="$(CFG="$base/cfg.json" scan)"
assert_contains "$out" "WARN: 4.3 portfolio-similarity" "config path list drives the rule"

section "the finding is labelled and catalogued"
j="$(scan --portfolio "$base/twin" --format json 2>/dev/null | sed -n '/^{/,$p')"
f="$(jq -c '[.findings[]|select(.rule_id=="portfolio-similarity")][0]' <<<"$j")"
assert_eq "WARN"          "$(jq -r .severity <<<"$f")"   "advisory severity"
assert_eq "4.3"           "$(jq -r .guideline <<<"$f")"  "guideline 4.3"
assert_eq "source"        "$(jq -r .evidence <<<"$f")"   "concluded from source"
assert_eq "judgment-call" "$(jq -r .confidence <<<"$f")" "a human decides"

rm -rf "$base"
exit "$fails"
