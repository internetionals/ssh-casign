#!/bin/sh
# Stand-in browser for the authorization code flow against the test Dex: logs in
# with curl and follows the redirect back to the client's loopback listener.
#   usage: BROWSER=tests/e2e/fixtures/dex-browser.sh ssh-casign-client --sign-in browser cert ...
#   env:   DEX_LOGIN (default user1@example.com), DEX_PASSWORD (default password),
#          DEX_BROWSER_LOG (default /dev/null)
set -eu
URL="$1"
LOG="${DEX_BROWSER_LOG:-/dev/null}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# The sign-in page redirects to the login form; its URL carries the state.
LOGIN_URL="$(curl -sf -c "$JAR" -b "$JAR" -L -o /dev/null -w '%{url_effective}' "$URL")"
echo "login form: $LOGIN_URL" >> "$LOG"

# Logging in redirects to the client's loopback listener, which curl follows.
DONE_URL="$(curl -s -c "$JAR" -b "$JAR" -L -o /dev/null -w '%{url_effective}' \
  --data-urlencode "login=${DEX_LOGIN:-user1@example.com}" \
  --data-urlencode "password=${DEX_PASSWORD:-password}" "$LOGIN_URL")"
echo "final page: $DONE_URL" >> "$LOG"
