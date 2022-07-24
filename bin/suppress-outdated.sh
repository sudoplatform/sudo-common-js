#!/bin/sh
#
# Insert a package name to suppress in outdated checks.
#

set -e

usage() {
  echo "Usage: suppress-outdated.sh [--suppression <number-of-days>] {--major|--minor|--patch} <package name> ..."
}

suppression=30
if [ "$1" = "--suppression" ]; then
  if [ -z "$2" ]; then
    echo "ERROR: --suppression argument must specify a number of days argument" 1>&2
    usage 1>&2
    exit 1
  fi
  shift
  suppression="$1"
  shift
fi

case "$1" in
  --major)
    root=".outdatedSuppressions.major"
    ;;
  --minor)
    root=".outdatedSuppressions.minor"
    ;;
  --patch)
    root=".outdatedSuppressions"
    ;;
  *)
    echo "suppress-outdated.sh: Unrecognized option: '$1'" 1>&2
    usage 1>&2
    exit 1
    ;;
esac
shift

if [ -z "$1" ]; then
  echo "suppress-outdated.sh: No package names specified" 1>&2
  usage 1>&2
  exit 1
fi

suppression_seconds=$((suppression * 24 * 3600))

PACKAGE_JSON="package.json"
cp "$PACKAGE_JSON" "$PACKAGE_JSON.old"

while [ -n "$1" ]; do
  package_name="$1"

  jq < "$PACKAGE_JSON" "${root}.\"${package_name}\" = (now | floor | . + ${suppression_seconds})" > "$PACKAGE_JSON.staging"
  mv "$PACKAGE_JSON.staging" "$PACKAGE_JSON"

  shift
done
