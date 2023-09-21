#!/bin/bash

set -e
set -o pipefail

# the approach here is to hash services individually using md5sum so we
# only build and push what's required.
# lambda images are tagged with their md5sum and lambda zips are uploaded
# to s3 under a prefix that is their respective md5sum - as are app assets.
#
# the following pattern:
# touch ".artifacts/public/${GIT_REV}/uploads/${rev}";
# just allows the md5sum to be traced back to an actual git sha in
# s3 (sha => md5sum per service), should the need arise.

site=app;

rm -rf .artifacts
mkdir -p ".artifacts/web/${site}"


rev=$(find ./web/${site}/ -type f -exec md5sum {} + | sort -k 2 | md5sum | awk '{print $1}')
mkdir ".artifacts/web/${site}/${rev}"

if aws s3 ls "s3://${GATED_BUCKET}/${rev}" >/dev/null 2>&1; then
  echo "Tag ${rev} already exists in S3. Skipping build."
else
  cd web/${site} && make build && cd ../..
  for file in web/${site}/dist/*.js web/${site}/dist/*.html web/${site}/dist/*.webmanifest web/${site}/dist/*.json; do
    sed -i.bak "s/__rev__/${rev}/g" "$file"
  done
  cp web/${site}/dist/* ".artifacts/web/${site}/${rev}"
  cp web/${site}/dist/index.html ".artifacts/web/${site}/"
  rm .artifacts/web/${site}/${rev}/*.bak
fi
