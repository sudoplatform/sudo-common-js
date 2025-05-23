#!/usr/bin/env bash

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
# Previously, the value of the audit suppression was just the expiry timestamp
# this old format is still recognized by this script for Yarn v1 projects, but
# ignored for Yarn 4+ projects.

YARNVER=$(yarn -v)
if [[ "${YARNVER}" == 1* ]]; then
  yarn npm audit --json --groups "dependencies devDependencies" | \
    jq -M -s -c 'map(select(.type == "auditAdvisory").data.advisory) | unique_by(.id) | .[] | {id, title, module_name, vulnerable_versions, patched_versions, severity, findings}' | \
    (new=""; while read -r advisory ; do
      id=$(echo "${advisory}" | jq '.id')
      suppression=$(jq ".auditSuppressions[\"$id\"] | select (. != null)" package.json)
      if [ -z "$suppression" ]; then
        echo "New advisory ${id}:"
        echo "${advisory}" | jq .
        new=1
      else
        if expr "$suppression" : '[0-9][0-9]*$' >/dev/null ; then
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
else
  now=$(date '+%s')

  echo "Checking for npm audit advisories"
  echo
  ignores=$(
    # shellcheck disable=SC2002
    cat package.json | \
      jq -j -r ".auditSuppressions | select(. != null) | to_entries[] | select(.value.untilISO | fromdate > $now) | (\" --ignore \" + .key)"
  )
  # shellcheck disable=SC2086
  yarn npm audit --all --environment all --recursive --no-deprecations $ignores
  foundaudits=$?
  
  echo
  echo "Checking for expired audit suppressions"
  # shellcheck disable=SC2002
  cat package.json | \
    jq -e ".auditSuppressions | select(. != null) | to_entries[] | select(.value.untilISO | fromdate <= $now)"
  # "jq -e" returns 4 if no valid result was found - so 4 means success, 0 (or anything else) is failure
  # so determine status by testing result for 4
  [ $? == 4 ]
  foundexpired=$?

  echo
  echo "done"

  [ $foundaudits != 0 ] && exit 1
  [ $foundexpired != 0 ] && exit 1

  # No audit failures or expired suppressions that need examination. Success
  exit 0
fi
