#!/bin/sh

yarn outdated --json | jq -s -c 'map(select(.type == "table").data.body) | .[] | unique_by(.[0]) | .[] | .[0]' | (new=""; while read package_name ; do
  suppression=$(jq ".outdatedSuppressions[$package_name] | select (. != null)" package.json)
  if [ -z "$suppression" ]; then
    echo "New outdated_package ${package_name}:"
    echo "${package_name}" | jq .
    new=1
  elif [ $(date '+%s') -gt "$suppression" ]; then
    echo "Suppression for outdated_package ${package_name} has expired. Please revisit:"
    echo "${package_name}" | jq .
    new=1
  else
    echo "outdated_package ${package_name} is suppressed"
  fi
done
if [ -n "${new}" ]; then
  exit 1
fi
)
