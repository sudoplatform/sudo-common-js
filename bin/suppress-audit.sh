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

auditid=$1
shift
reason="${*}"
PACKAGE_JSON="package.json"

if [ -z "$auditid" ] || [ -z "$reason" ]; then
  echo "Usage: yarn suppress-audit <audit id> <reason>"
  exit 1
fi

cp $PACKAGE_JSON $PACKAGE_JSON.old
cat $PACKAGE_JSON | jq '(now | floor | . + 1209600) as $expiry | .auditSuppressions."'"$auditid"'" = {"until": $expiry,"untilISO":($expiry | strftime("%FT%TZ") ),"reason":"'"${reason}"'"}' > $PACKAGE_JSON.staging
mv $PACKAGE_JSON.staging $PACKAGE_JSON
