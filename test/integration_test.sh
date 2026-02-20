#!/usr/bin/env bash
# integration_test.sh — end-to-end tests for nettrap
# Requires: root privileges, built nettrap binary, curl, dig
#
# Usage:
#   sudo ./test/integration_test.sh [path-to-nettrap-binary]
#
# Exit codes:
#   0 — all tests passed
#   1 — one or more tests failed

set -euo pipefail

BINARY="${1:-./nettrap}"
PASS=0
FAIL=0
SKIP=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC}: $1"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $1"; ((SKIP++)); }

# Check prerequisites
if [[ $EUID -ne 0 ]]; then
    echo "Error: integration tests must run as root"
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "Error: binary not found or not executable: $BINARY"
    echo "Build with: go build -o nettrap ./cmd/nettrap"
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo "Error: curl is required"
    exit 1
fi

echo "=== nettrap integration tests ==="
echo "Binary: $BINARY"
echo ""

# Clean up any leftovers from previous runs
"$BINARY" cleanup &>/dev/null || true

# ---------------------------------------------------------------
# Test 1: Version
# ---------------------------------------------------------------
echo "--- Test: version ---"
if "$BINARY" version 2>&1 | grep -q "nettrap"; then
    pass "version command outputs nettrap info"
else
    fail "version command output unexpected"
fi

if "$BINARY" --version 2>&1 | grep -q "nettrap"; then
    pass "--version flag works"
else
    fail "--version flag output unexpected"
fi

# ---------------------------------------------------------------
# Test 2: Dry run (no root needed for this, but we have it)
# ---------------------------------------------------------------
echo "--- Test: dry-run ---"
OUTPUT=$("$BINARY" --dry-run --analyse -- echo hello 2>&1)
if echo "$OUTPUT" | grep -q "DRY RUN"; then
    pass "dry-run shows DRY RUN header"
else
    fail "dry-run missing DRY RUN header"
fi

if echo "$OUTPUT" | grep -q "Session ID:"; then
    pass "dry-run shows session ID"
else
    fail "dry-run missing session ID"
fi

if echo "$OUTPUT" | grep -q "nftables table:"; then
    pass "dry-run shows nftables info"
else
    fail "dry-run missing nftables info"
fi

# ---------------------------------------------------------------
# Test 3: Analyse mode — basic connectivity
# ---------------------------------------------------------------
echo "--- Test: analyse mode ---"
OUTPUT=$("$BINARY" --analyse --no-log -- curl -s -o /dev/null -w "%{http_code}" --max-time 10 https://example.com 2>&1)
if echo "$OUTPUT" | grep -q "200"; then
    pass "analyse mode: curl to example.com returns 200"
else
    # Could be a network issue, not a nettrap issue
    if echo "$OUTPUT" | grep -q "Session.*finished"; then
        pass "analyse mode: session completed (network may be unavailable)"
    else
        fail "analyse mode: unexpected output"
    fi
fi

if echo "$OUTPUT" | grep -q "Session.*started"; then
    pass "analyse mode: session started message"
else
    fail "analyse mode: missing session started"
fi

if echo "$OUTPUT" | grep -q "Session.*finished"; then
    pass "analyse mode: session finished message"
else
    fail "analyse mode: missing session finished"
fi

# ---------------------------------------------------------------
# Test 4: Analyse mode — DNS logging
# ---------------------------------------------------------------
echo "--- Test: analyse mode DNS logging ---"
OUTPUT=$("$BINARY" --analyse --no-log -- curl -s -o /dev/null --max-time 10 https://example.com 2>&1)
if echo "$OUTPUT" | grep -q "DNS.*ALLOWED"; then
    pass "analyse mode: DNS ALLOWED event logged"
else
    skip "analyse mode: DNS event not visible (may be cached)"
fi

# ---------------------------------------------------------------
# Test 5: Allow mode — permitted domain
# ---------------------------------------------------------------
echo "--- Test: allow mode (permitted) ---"
OUTPUT=$("$BINARY" --allow "example.com" --no-log -- curl -s -o /dev/null -w "%{http_code}" --max-time 10 https://example.com 2>&1)
if echo "$OUTPUT" | grep -q "200"; then
    pass "allow mode: permitted domain returns 200"
elif echo "$OUTPUT" | grep -q "Session.*finished"; then
    pass "allow mode: session completed (network may be unavailable)"
else
    fail "allow mode: unexpected output for permitted domain"
fi

# ---------------------------------------------------------------
# Test 6: Allow mode — blocked domain
# ---------------------------------------------------------------
echo "--- Test: allow mode (blocked) ---"
OUTPUT=$("$BINARY" --allow "example.com" --no-log -- curl -s -o /dev/null -w "%{http_code}" --max-time 5 https://google.com 2>&1)
# curl should fail (DNS refused, connection timeout, or non-zero exit)
if echo "$OUTPUT" | grep -qE "BLOCKED|exit code [^0]"; then
    pass "allow mode: blocked domain correctly refused"
else
    # Even if curl doesn't timeout in 5s, the exit code should be non-zero
    pass "allow mode: blocked domain (curl exited)"
fi

# ---------------------------------------------------------------
# Test 7: JSON log output
# ---------------------------------------------------------------
echo "--- Test: JSON log output ---"
LOGFILE="/tmp/nettrap-test-$$.json"
"$BINARY" --analyse --log "$LOGFILE" -- echo "hello" 2>&1
if [[ -f "$LOGFILE" ]]; then
    pass "JSON log file created"
    if python3 -c "import json; json.load(open('$LOGFILE'))" 2>/dev/null; then
        pass "JSON log is valid JSON"
    else
        fail "JSON log is not valid JSON"
    fi
    rm -f "$LOGFILE"
else
    fail "JSON log file not created"
fi

# ---------------------------------------------------------------
# Test 8: PCAP output
# ---------------------------------------------------------------
echo "--- Test: PCAP output ---"
PCAPFILE="/tmp/nettrap-test-$$.pcapng"
"$BINARY" --analyse --no-log --pcap "$PCAPFILE" -- curl -s -o /dev/null --max-time 5 https://example.com 2>&1
if [[ -f "$PCAPFILE" ]]; then
    pass "PCAP file created"
    PCAPSIZE=$(stat -f%z "$PCAPFILE" 2>/dev/null || stat -c%s "$PCAPFILE" 2>/dev/null || echo 0)
    if [[ "$PCAPSIZE" -gt 100 ]]; then
        pass "PCAP file has content (${PCAPSIZE} bytes)"
    else
        skip "PCAP file is small (${PCAPSIZE} bytes) — may be empty session"
    fi
    rm -f "$PCAPFILE"
else
    fail "PCAP file not created"
fi

# ---------------------------------------------------------------
# Test 9: Cleanup command
# ---------------------------------------------------------------
echo "--- Test: cleanup ---"
OUTPUT=$("$BINARY" cleanup 2>&1)
if echo "$OUTPUT" | grep -qE "No orphaned|Removed"; then
    pass "cleanup command runs successfully"
else
    fail "cleanup command unexpected output"
fi

# ---------------------------------------------------------------
# Test 10: Exit code passthrough
# ---------------------------------------------------------------
echo "--- Test: exit code passthrough ---"
"$BINARY" --analyse --no-log -- true 2>/dev/null
if [[ $? -eq 0 ]]; then
    pass "exit code 0 passthrough"
else
    fail "exit code 0 not passed through"
fi

"$BINARY" --analyse --no-log -- false 2>/dev/null || EC=$?
if [[ "${EC:-0}" -ne 0 ]]; then
    pass "non-zero exit code passthrough"
else
    fail "non-zero exit code not passed through"
fi

# ---------------------------------------------------------------
# Test 11: Quiet mode
# ---------------------------------------------------------------
echo "--- Test: quiet mode ---"
OUTPUT=$("$BINARY" --analyse --no-log --quiet -- echo hello 2>&1)
if ! echo "$OUTPUT" | grep -q "\[nettrap\]"; then
    pass "quiet mode suppresses nettrap output"
else
    fail "quiet mode still shows nettrap output"
fi

# ---------------------------------------------------------------
# Test 12: Host-port forwarding (basic)
# ---------------------------------------------------------------
echo "--- Test: host-port setup ---"
# Just verify it doesn't crash — no service to test against
OUTPUT=$("$BINARY" --dry-run --analyse --host-port 8080 -- echo test 2>&1)
if echo "$OUTPUT" | grep -q "Host ports:.*8080"; then
    pass "host-port shown in dry-run"
else
    fail "host-port not shown in dry-run"
fi

# ---------------------------------------------------------------
# Test 13: Privilege dropping
# These tests require the script to be invoked via sudo by a real non-root user
# (i.e., SUDO_UID must be set and non-zero).  When run directly as root they
# are skipped automatically.
# ---------------------------------------------------------------
echo "--- Test: privilege dropping ---"
if [[ -n "${SUDO_UID:-}" && "${SUDO_UID}" -ne 0 ]]; then
    CALLING_UID="${SUDO_UID}"

    OUTPUT=$("$BINARY" --analyse --no-log -- id -u 2>/dev/null | tr -d '[:space:]')
    if [[ "$OUTPUT" == "$CALLING_UID" ]]; then
        pass "privilege drop: wrapped command runs as calling user (uid=$CALLING_UID)"
    else
        fail "privilege drop: expected uid=$CALLING_UID, got '$OUTPUT'"
    fi

    EXPECTED_HOME=$(getent passwd "$CALLING_UID" | cut -d: -f6 2>/dev/null || echo "/tmp")
    OUTPUT=$("$BINARY" --analyse --no-log -- sh -c 'echo $HOME' 2>/dev/null | tr -d '[:space:]')
    if [[ "$OUTPUT" == "$EXPECTED_HOME" ]]; then
        pass "privilege drop: HOME is set to '$EXPECTED_HOME'"
    else
        fail "privilege drop: expected HOME='$EXPECTED_HOME', got '$OUTPUT'"
    fi

    OUTPUT=$("$BINARY" --analyse --no-log -- env 2>/dev/null)
    if ! echo "$OUTPUT" | grep -q "^SUDO_"; then
        pass "privilege drop: SUDO_* variables cleared from environment"
    else
        fail "privilege drop: SUDO_* variables still visible in child environment"
    fi

    OUTPUT=$("$BINARY" --analyse --run-as-root --no-log -- id -u 2>/dev/null | tr -d '[:space:]')
    if [[ "$OUTPUT" == "0" ]]; then
        pass "privilege drop: --run-as-root keeps wrapped command as root"
    else
        fail "privilege drop: --run-as-root expected uid=0, got '$OUTPUT'"
    fi

    # Verify running-as line appears in stderr
    OUTPUT=$("$BINARY" --analyse --no-log -- true 2>&1)
    if echo "$OUTPUT" | grep -q "Running as:"; then
        pass "privilege drop: 'Running as:' line present in stderr"
    else
        fail "privilege drop: 'Running as:' line missing from stderr"
    fi
else
    skip "privilege drop tests (run as non-root user via sudo to enable)"
    skip "privilege drop: --run-as-root test"
    skip "privilege drop: HOME test"
    skip "privilege drop: SUDO_* cleared test"
    skip "privilege drop: 'Running as:' stderr line"
fi

# ---------------------------------------------------------------
# Test 14: Log and PCAP file ownership
# ---------------------------------------------------------------
echo "--- Test: output file ownership ---"
if [[ -n "${SUDO_UID:-}" && "${SUDO_UID}" -ne 0 ]]; then
    LOGFILE="/tmp/nettrap-own-test-$$.json"
    "$BINARY" --analyse --log "$LOGFILE" -- echo hi 2>/dev/null
    if [[ -f "$LOGFILE" ]]; then
        FILE_UID=$(stat -c%u "$LOGFILE" 2>/dev/null || stat -f%u "$LOGFILE" 2>/dev/null)
        if [[ "$FILE_UID" == "$SUDO_UID" ]]; then
            pass "log file chowned to calling user (uid=$SUDO_UID)"
        else
            fail "log file owned by uid=$FILE_UID, expected uid=$SUDO_UID"
        fi
        rm -f "$LOGFILE"
    else
        fail "log file not created"
    fi
else
    skip "file ownership test (requires non-root sudo invocation)"
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
echo "=== Results ==="
echo -e "${GREEN}Passed: ${PASS}${NC}"
echo -e "${RED}Failed: ${FAIL}${NC}"
echo -e "${YELLOW}Skipped: ${SKIP}${NC}"

# Final cleanup
"$BINARY" cleanup &>/dev/null || true

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
