#!/bin/sh
#
# Insert a audit identifier to suppress in verification proccess.
#
# Suppressions are objects added to the auditSuppresions element of package.json
# and are of the form:
#
# "auditSuppressions": {
#   "<numeric-vulnerability-id>": {
#     "until": <numeric-expiry-in-seconds-since-epoch>,
#     "untilISO": "<expiry-time-in-ISO8601-format>",
#     "reason": "<string-text-for-recording-reason-for-suppression>"
#   }
# }
#

usage() {
  echo 1>&2 "Usage: $cmd [-d <days-to-suppress>] audit-id reasonwords as remaining args"
  echo 1>&2
  echo 1>&2 "       -d Number of days to suppress vulnerability for. Default: 30."
  echo 1>&2
  echo 1>&2 "       Example:"
  echo 1>&2 "          suppress-audit.sh 12345 suppressing for a while"
  echo 1>&2
  echo 1>&2 "          Suppresses vulnerability 12345 for default 30 days recording"
  echo 1>&2 "          'suppressing for a while' as the reason."
  echo 1>&2
}

DAYS_TO_SUPPRESS=30

cmd=$(basename "$0")
# shellcheck disable=SC2048,SC2086
if ! args=$(getopt d: $*); then
  usage
  exit 1
fi

# shellcheck disable=SC2086
set -- $args

while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
  case "$1" in
    -d) if ! expr "$2" : '[0-9][0-9]*$' >/dev/null || [ "$(($2 > 0))" -eq 0 ]; then
          echo 1>&2 "ERROR: suppression days must be positive integer"
          echo 1>&2
          usage
          exit 1
        fi
        DAYS_TO_SUPPRESS=$2
        shift
        shift
        ;;
  esac
done
if [ "$1" = "--" ]; then
  shift
fi
auditid="$1"
shift
reason="${*}"

if [ -z "$auditid" ]; then
  echo 1>&2 "ERROR: No audit-id specified"
  echo 1>&2
  usage
  exit 1
fi

if [ -z "$reason" ]; then
  echo 1>&2 "ERROR: No suppression reason specified"
  echo 1>&2
  usage
  exit 1
fi

SECONDS_TO_SUPPRESS=$((DAYS_TO_SUPPRESS * 3600 * 24))
PACKAGE_JSON="package.json"

set -e
cp $PACKAGE_JSON $PACKAGE_JSON.old
cat $PACKAGE_JSON | jq '(now | floor | . + '$SECONDS_TO_SUPPRESS') as $expiry | .auditSuppressions."'"$auditid"'" = {"until": $expiry,"untilISO":($expiry | strftime("%FT%TZ") ),"reason":"'"${reason}"'"}' > $PACKAGE_JSON.staging
mv $PACKAGE_JSON.staging $PACKAGE_JSON
set +e
