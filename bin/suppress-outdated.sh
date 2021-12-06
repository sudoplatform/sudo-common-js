#!/bin/sh
#
# Insert a package name to suppress in outdated checks.
#

package_name=$1
PACKAGE_JSON="package.json"

if [ -z "$package_name" ]; then
  echo "Usage: yarn suppress-outdated <package name>"
  exit 1
fi
cp $PACKAGE_JSON $PACKAGE_JSON.old
cat $PACKAGE_JSON | jq ".outdatedSuppressions.\"$package_name\" = (now | floor | . + 1209600)" > $PACKAGE_JSON.staging
mv $PACKAGE_JSON.staging $PACKAGE_JSON
