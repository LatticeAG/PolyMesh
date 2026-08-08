#!/bin/bash
# PolyMesh v6 continuous build loop: M3 -> verify -> M4 -> verify -> M5 -> verify
# Each milestone: cursor-agent build (default settings: --yolo cursor-grok-4.5-high)
# Then independent verification (npm test + pytest). On failure: one fix pass, re-verify.
set -u
cd /home/ubuntu/polymesh || exit 1
LOG=v6-build-loop.log
exec > >(tee -a "$LOG") 2>&1

say() { echo; echo "==================== $(date '+%H:%M:%S') $* ===================="; }

verify() {
  say "VERIFY: npm rebuild + test + pytest"
  npm rebuild better-sqlite3 >/dev/null 2>&1
  npm test > /tmp/pm-npm-test.log 2>&1
  TS=$?
  uv run pytest > /tmp/pm-pytest.log 2>&1
  PY=$?
  TS_COUNT=$(grep -E "^\s+Tests" /tmp/pm-npm-test.log | tail -1 | tr -s ' ')
  PY_COUNT=$(tail -1 /tmp/pm-pytest.log)
  say "TS exit=$TS ($TS_COUNT) | PY exit=$PY ($PY_COUNT)"
  return $((TS || PY))
}

fix_pass() {
  local milestone="$1"
  say "FIX PASS for $milestone (tests failed)"
  cat > /tmp/pm-fix-prompt.md <<EOF
You are fixing failing tests in the PolyMesh v6 $milestone build at /home/ubuntu/polymesh/.
READ /tmp/pm-npm-test.log and /tmp/pm-pytest.log (full test output - failures are there).
Also read the relevant spec sections in /home/ubuntu/polymesh/PM-V6-SPEC.md (Part A for adapter, Part B for router).
Your job: make all tests pass WITHOUT changing test expectations unless a test contradicts the normative spec (then fix the test to match the spec and note it).
Run: npm rebuild better-sqlite3, npm test, uv run pytest. Iterate until both suites are fully green.
Then: git add -A && git commit -m "fix: $milestone test failures" && git push origin main
Report: what was broken, what you changed, final suite counts.
EOF
  cat /tmp/pm-fix-prompt.md /tmp/pm-npm-test.log /tmp/pm-pytest.log | cursor-agent --yolo --model cursor-grok-4.5-high
}

build_milestone() {
  local milestone="$1" prompt="$2"
  say "BUILD $milestone"
  cat "$prompt" | cursor-agent --yolo --model cursor-grok-4.5-high
}

# --- M3: A2A adapter inbound ---
build_milestone "M3 (A2A adapter inbound)" v6-m3-build-prompt.md
if ! verify; then fix_pass "M3"; verify || say "M3 STILL FAILING after fix pass - continuing to M4 anyway (flagged)"; fi

# --- M4: docs + positioning + demo ---
build_milestone "M4 (docs/positioning/demo)" v6-m4-build-prompt.md
if ! verify; then fix_pass "M4"; verify || say "M4 STILL FAILING after fix pass - continuing to M5 anyway (flagged)"; fi

# --- M5: release gates ---
build_milestone "M5 (release)" v6-m5-build-prompt.md
verify || fix_pass "M5"
verify || say "M5 STILL FAILING after fix pass (flagged)"

say "LOOP COMPLETE. Final state:"
git log --oneline -8
say "Suite totals:"
tail -2 /tmp/pm-npm-test.log
tail -1 /tmp/pm-pytest.log
say "Ship readiness: see /home/ubuntu/polymesh/RELEASE.md (M5 gate results)"
echo "DONE"
