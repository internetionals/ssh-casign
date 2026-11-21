#!/bin/sh
# Plays the user's part of the device flow against the test Dex, without a
# browser: enter the user code, log in as the test user, approve.
#   usage: approve.sh USER_CODE [LOGIN] [PASSWORD]
set -eu
USER_CODE="$1"
LOGIN="${2:-user1@example.com}"
PASSWORD="${3:-password}"
DEX="${DEX_URL:-http://dex:5556}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# Entering the code redirects to the login form; its URL carries the state.
LOGIN_URL="$(curl -sf -c "$JAR" -b "$JAR" -L -o /dev/null -w '%{url_effective}' \
  --data-urlencode "user_code=$USER_CODE" "$DEX/dex/device/auth/verify_code")"
case "$LOGIN_URL" in
  */auth/local/login*) ;;
  *) echo "unexpected page after entering the code: $LOGIN_URL" >&2; exit 1 ;;
esac

# Logging in ends on the device callback page (approval screen is skipped).
DONE_URL="$(curl -sf -c "$JAR" -b "$JAR" -L -o /dev/null -w '%{url_effective}' \
  --data-urlencode "login=$LOGIN" --data-urlencode "password=$PASSWORD" "$LOGIN_URL")"
case "$DONE_URL" in
  */device/callback*) echo "approved $USER_CODE as $LOGIN" ;;
  *) echo "unexpected page after logging in: $DONE_URL" >&2; exit 1 ;;
esac
