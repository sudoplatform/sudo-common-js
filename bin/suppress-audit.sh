#!/bin/sh
#
# Insert a audit identifier to suppress in verification proccess.
#

auditid=$1
PACKAGE_JSON="package.json"

if [ -z $auditid ]; then
  echo "Usage: yarn suppress-audit <audit id>"
  exit 1
fi
cp $PACKAGE_JSON $PACKAGE_JSON.old
cat $PACKAGE_JSON | jq ".auditSuppressions.\"$auditid\" = (now | floor | . + 1209600)" > $PACKAGE_JSON.staging
mv $PACKAGE_JSON.staging $PACKAGE_JSON
