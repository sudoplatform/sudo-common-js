#!/bin/sh

function version_diff_type() {
  v1="$1"
  v2="$2"
  v1_major=$(echo $v1 | sed -E -e 's/^([^.]+)\..*/\1/')
  v2_major=$(echo $v2 | sed -E -e 's/^([^.]+)\..*/\1/')
  v1_minor=$(echo $v1 | sed -E -e 's/^([^.]+)\.([^.]+)\..*/\2/')
  v2_minor=$(echo $v2 | sed -E -e 's/^([^.]+)\.([^.]+)\..*/\2/')
  if [ "${v1_major}" != "${v2_major}" ]; then echo 'major'; return 0; fi
  if [ "${v1_minor}" != "${v2_minor}" ]; then echo 'minor'; return 0; fi
  if [ "${v1}" != "${v2}" ]; then echo 'patch'; return 0; fi
  echo 'equal'
  return 0
}

function suppression_from_diff_type() {
  diff_type="$1"
  majorSuppression="$2"
  minorSuppression="$3"
  patchSuppression="$4"

  case "${diff_type}" in
    major)
      if [ -n "${majorSuppression}" ]; then
        echo "major ${majorSuppression}"
      elif [ -n "${minorSuppression}" ]; then
        echo "minor ${minorSuppression}"
      elif [ -n "${patchSuppression}" ]; then
        echo "patch ${patchSuppression}"
      fi
      ;;
    minor)
      if [ -n "${minorSuppression}" ]; then
        echo "minor ${minorSuppression}"
      elif [ -n "${patchSuppression}" ]; then
        echo "patch ${patchSuppression}"
      fi
      ;;
    patch)
      if [ -n "${patchSuppression}" ]; then
        echo "patch ${patchSuppression}"
      fi
      ;;
  esac
}

yarn outdated --json | jq -r -s -c 'map(select(.type == "table").data.body) | .[] | unique_by(.[0]) | .[] | .[0] + " " + .[1] + " " + .[2] + " " + .[3]' | (new=""; while read package_name current wanted latest; do
  majorSuppression=$(jq ".outdatedSuppressions.major[\"${package_name}\"] | select (. != null)" package.json)
  minorSuppression=$(jq ".outdatedSuppressions.minor[\"${package_name}\"] | select (. != null)" package.json)
  patchSuppression=$(jq ".outdatedSuppressions[\"${package_name}\"] | select (. != null)" package.json)
  latest_diff_type=$(version_diff_type "${current}" "${latest}")
  wanted_diff_type=$(version_diff_type "${current}" "${wanted}")

  set -- $(suppression_from_diff_type "${latest_diff_type}" "${majorSuppression}" "${minorSuppression}" "${patchSuppression}")
  latest_suppression_type="$1"
  latest_suppression="$2"

  set -- $(suppression_from_diff_type "${wanted_diff_type}" "${majorSuppression}" "${minorSuppression}" "${patchSuppression}")
  wanted_suppression_type="$1"
  wanted_suppression="$2"

  # If package has major update but isn't suppre
  suppression=""
  suppression_type=""
  outdated_diff_type="${latest_diff_type}"
  if [ -n "${latest_suppression_type}" ]; then
    if [ "${wanted_diff_type}" != "equal" ]; then
      outdated_diff_type="${wanted_diff_type}"
      if [ -n "${wanted_suppression_type}" ]; then
        suppression_type="${wanted_suppression_type}"
        suppression="${wanted_suppression}"
      else
        # Only suppressed at major level and we have minor or patch
        # updates available - do not suppress
        :
      fi
    else
      suppression_type="${latest_suppression_type}"
      suppression="${latest_suppression}"
    fi
  fi

  if [ -z "${suppression}" ]; then
    echo "${package_name}: current: ${current} wanted: ${wanted} latest: ${latest} [${outdated_diff_type} outdated]"
    new=1
  elif [ $(date '+%s') -gt "${suppression}" ]; then
    echo "${package_name}: current: ${current} wanted: ${wanted} latest: ${latest} [${outdated_diff_type} suppression expired]"
    new=1
  else
    echo "${package_name}: current: ${current} wanted: ${wanted} latest: ${latest} [${outdated_diff_type} suppressed]"
  fi
done
if [ -n "${new}" ]; then
  exit 1
fi
)
