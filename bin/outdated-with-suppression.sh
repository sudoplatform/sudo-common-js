#!/bin/sh

###
# This script is duplicated in platform-common. Any updates to this script here should also be adjusted in the platform-common repository.
###

set -e
d="$(dirname "$0")"

version_diff_type() {
  v1="$1"
  v2="$2"
  v1_major=$(echo "$v1" | sed -E -e 's/^([^.]+)\..*/\1/')
  v2_major=$(echo "$v2" | sed -E -e 's/^([^.]+)\..*/\1/')
  v1_minor=$(echo "$v1" | sed -E -e 's/^([^.]+)\.([^.]+)\..*/\2/')
  v2_minor=$(echo "$v2" | sed -E -e 's/^([^.]+)\.([^.]+)\..*/\2/')
  if [ "${v1_major}" != "${v2_major}" ]; then echo 'major'; return 0; fi
  if [ "${v1_minor}" != "${v2_minor}" ]; then echo 'minor'; return 0; fi
  if [ "${v1}" != "${v2}" ]; then echo 'patch'; return 0; fi
  echo 'equal'
  return 0
}

suppression_from_diff_type() {
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

#
# This function will determine whether a new outdated dependency will cause the script to fail.
# It compares the publish date of the wanted version and only populates 'new' when the publish date is outside 'stability_days'.
#
classify_outdated_dependency() {
  dependency_name=$1
  wanted_version=$2
  # Get the publish date of the version that matches 'wanted', returning YYYY-MM-DD
  publish_date=$(yarn info "$dependency_name" time --json | jq -r '.data | to_entries[] | select(.key == "'"$wanted_version"'") | .value | split("T") | .[0]')

  # Convert the 'publish_date' variable to epoch
  if [ -z "$CI" ]; then
    # CI_COMMIT_BRANCH is undefined, running locally, use mac environment
    publish_date_epoch=$(date -j -f '%Y-%m-%d' "$publish_date" '+%s')
  else
    # CI_COMMIT_BRANCH is defined, running in CI context, use busybox environment
    publish_date_epoch=$(date -d "$publish_date" +%s)
  fi

  # Calculate the difference in days
  diff_days=$(((current_epoch - publish_date_epoch) / 86400))

  # Check if the difference in days is greater than or equal to 3, and set a new outdated dependency if it was not published in the last 3 days
  if [ $diff_days -ge $stability_days ]; then
    # The date is more than 3 days away from the current date, populate 'new' to return fail later
    new=1
  fi
}

# Number of days to suppress if accepting or refreshing and cadence to run if --last specified
cadence=30

# If set, accept any outdated packages. Has the effect of refreshing existing suppressions
# as well.
accept=""

# If set, refresh any existing suppressions
refresh=""

# If set, records/references last success in the specified directory.
# Only run the dependency check every cadence days if a last success
# timestamp is found
last=""

# Define the number of days an outdated dependency exists for before it returns a fail. For example, if this is set to 3, it includes today, yesterday, and the day before.
stability_days=3

# Get the current date in epoch, this is used with stability_days and each outdated dependency's publish date to determine when the script should fail.
current_epoch=$(date +%s)

while [ -n "${1}" ]; do
  case "${1}" in
    --cadence)
      if [ -z "$2" ]; then
        echo "ERROR: --cadence requires number of days argument" 1>&2
        exit 1
      fi
      shift
      cadence="$1"
      ;;
    --accept) accept="1" ;;
    --refresh) refresh="1" ;;
    --last)
      if [ -z "$2" ]; then
        echo "ERROR: --last requires directory argument in which last successful run timestamp is to be store" 1>&2
        exit 1
      fi
      shift
      last="$1"
      ;;
    *)
      echo "ERROR: Unrecognized argument '${1}'" 1>&2
      exit 1
  esac
  shift
done

dateFromSeconds() {
  s="$1"
  case $(uname) in
    Darwin)
      date -Iseconds -r"${s}"
      ;;
    *)
      date -Iseconds "-d@${s}"
      ;;
  esac
}

within_cadence=""
if [ -r "${last}/last_success" ]; then
  cadence_seconds=$((cadence * 24 * 3600))
  now="$(date +%s)"
  last_run="$(cat "${last}/last_success")"
  due="$((last_run + cadence_seconds))"
  if [ "$((due > now))" = "1" ]; then
    echo "Last success: $(dateFromSeconds "${last_run}")"
    echo "Now:          $(date -Iseconds)"
    echo "Due from:     $(dateFromSeconds "${due}")"
    within_cadence="1"
  else
    echo "Last success: $(dateFromSeconds "${last_run}")"
    echo "Now:          $(date -Iseconds)"
    echo "Due since:    $(dateFromSeconds "${due}")"
  fi
fi


yarn outdated --json | jq -r -s -c 'map(select(.type == "table").data.body) | .[] | unique_by(.[0]) | .[] | .[0] + " " + .[1] + " " + .[2] + " " + .[3]' | (new=""; while read -r package_name current wanted latest; do
  majorSuppression=$(jq ".outdatedSuppressions.major[\"${package_name}\"] | select (. != null)" package.json)
  minorSuppression=$(jq ".outdatedSuppressions.minor[\"${package_name}\"] | select (. != null)" package.json)
  patchSuppression=$(jq ".outdatedSuppressions[\"${package_name}\"] | select (. != null)" package.json)
  latest_diff_type=$(version_diff_type "${current}" "${latest}")
  wanted_diff_type=$(version_diff_type "${current}" "${wanted}")

  # shellcheck disable=SC2046
  set -- $(suppression_from_diff_type "${latest_diff_type}" "${majorSuppression}" "${minorSuppression}" "${patchSuppression}")
  latest_suppression_type="$1"
  latest_suppression="$2"

  # shellcheck disable=SC2046
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

  suppress_outdated=""
  if [ -e "${d}/suppress-outdated" ]; then
    suppress_outdated="${d}/suppress-outdated"
  elif [ -e "${d}/suppress-outdated.sh" ]; then
    suppress_outdated="${d}/suppress-outdated.sh"
  fi
  if [ -z "${suppress_outdated}" ]; then
    echo "ERROR: Unable to find suppress-outdated" 1>&2
    exit 1
  fi
  if [ -z "${suppression}" ]; then
    if [ -n "${accept}" ]; then
      echo "${package_name}: current: ${current} wanted: ${wanted} latest: ${latest} [${latest_diff_type} accepted]"
      "${suppress_outdated}" --suppression "${cadence}" --"${latest_diff_type}" "${package_name}"
    else
      echo "${package_name}: current: ${current} wanted: ${wanted} latest: ${latest} [${outdated_diff_type} outdated]"
      classify_outdated_dependency "$package_name" "$wanted"

    fi
  elif [ -n "${accept}${refresh}" ]; then
    echo "${package_name}: current: ${current} wanted: ${wanted} latest: ${latest} [${suppression_type} suppression refreshed]"
    "${suppress_outdated}" --suppression "${cadence}" --"${suppression_type}" "${package_name}"
  elif [ "$(date '+%s')" -gt "${suppression}" ]; then
    echo "${package_name}: current: ${current} wanted: ${wanted} latest: ${latest} [${outdated_diff_type} suppression expired]"
    new=1
  else
    echo "${package_name}: current: ${current} wanted: ${wanted} latest: ${latest} [${outdated_diff_type} suppressed until $(dateFromSeconds "${suppression}")]"
  fi
done

# If we're not within cadence and there are new outdated dependencies
# then fail
if [ -z "${within_cadence}" ] && [ -n "${new}" ]; then
  exit 1
fi

# If there a no outdated dependencies and we're tracking last success then
# refresh the last success timestamp.
if [ -z "${new}" ] && [ -n "${last}" ]; then
  mkdir -p "${last}"
  date +%s > "${last}/last_success"
fi
)
