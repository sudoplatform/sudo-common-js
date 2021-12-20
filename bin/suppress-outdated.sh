#!/bin/sh
#
# Insert a package name to suppress in outdated checks.
#

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
    echo "Usage: suppress-outdated.sh {--major|--minor|--patch} <package name>" 1>&2
    exit 1
    ;;
esac

package_name="$2"
PACKAGE_JSON="package.json"

if [ -z "$package_name" ]; then
  echo "Usage: yarn suppress-outdated {--major|--minor|--patch} <package name>"
  exit 1
fi

cp $PACKAGE_JSON $PACKAGE_JSON.old
cat $PACKAGE_JSON | jq "${root}.\"${package_name}\" = (now | floor | . + 1209600)" > $PACKAGE_JSON.staging
mv $PACKAGE_JSON.staging $PACKAGE_JSON
