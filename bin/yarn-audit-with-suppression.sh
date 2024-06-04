#!/bin/sh

# Run yarn audit reading any suppressions from the auditSuppressions element
# of package.json.
#
# Suppressions are added by yarn suppress-audit and are of the form:
#
# "auditSuppressions": {
#   "<numeric-vulnerability-id>": {
#     "until": <numeric-expiry-in-seconds-since-epoch>,
#     "untilISO": "<expiry-time-in-ISO8601-format>",
#     "reason": "<string-text-for-recording-reason-for-suppression>"
#   }
# }
#
# Previously, the value of the audit suppression was jsut the expiry timestamp
# this old format is still recognized by this script.
#
yarn audit --json --groups "dependencies devDependencies" | \
  jq -M -s -c 'map(select(.type == "auditAdvisory").data.advisory) | unique_by(.id) | .[] | {id, title, module_name, vulnerable_versions, patched_versions, severity, findings}' | \
  (new=""; while read -r advisory ; do
  id=$(echo "${advisory}" | jq '.id')
  suppression=$(jq ".auditSuppressions[\"$id\"] | select (. != null)" package.json)
  if [ -z "$suppression" ]; then
    echo "New advisory ${id}:"
    echo "${advisory}" | jq .
    new=1
  else
    if expr "$suppression" : '^[0-9][0-9]*$' >/dev/null ; then
      # Old style suppression that was just the expiry timestamp
      expiry="$suppression"
    else
      # New style suppression is a JSON object
      expiry=$(echo "$suppression" | jq -M -c ".until // 0")
    fi
    if [ "$(date '+%s')" -gt "$expiry" ]; then
      echo "Suppression for advisory ${id} has expired. Please revisit:"
      echo "${advisory}" | jq .
      new=1
    fi
  fi
done
if [ -n "${new}" ]; then
  exit 1
fi
)
