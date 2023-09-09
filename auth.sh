#!/bin/bash

set -e
set -o pipefail

for func in test-auth-token; do
  rev=$(find ./lambda/${func}/ -type f -exec md5sum {} + | sort -k 2 | md5sum | awk '{print $1}');
  mkdir -p ".artifacts/functions/${rev}/${func}"
  sed -i.bak "s/__rev__\/${func}/${rev}\/${func}/g" ${TEMPLATE}
  mkdir -p ".artifacts/functions/${GIT_REV}/${func}/"
  touch ".artifacts/functions/${GIT_REV}/${func}/${rev}"
  if aws s3 ls "s3://${ARTIFACTS_BUCKET}/${rev}/${func}" >/dev/null 2>&1; then
    echo "Tag ${rev} already exists in S3. Skipping build."
  else
    cd "./lambda/${func}";
    if [[ "$func" == "test-auth-token" ]]; then
      sed -i.bak "s/region: ''/region: '${AWS_REGION}'/g" auth.js
      sed -i.bak "s/userPoolId: ''/userPoolId: '${USER_POOL_ID}'/g" auth.js
      sed -i.bak "s/userPoolAppId: ''/userPoolAppId: '${USER_POOL_APP_ID}'/g" auth.js
      sed -i.bak "s/userPoolAppSecret: ''/userPoolAppSecret: '${USER_POOL_APP_SECRET}'/g" auth.js
      sed -i.bak "s/userPoolDomain: ''/userPoolDomain: '${USER_POOL_DOMAIN}'/g" auth.js
      sed -i.bak "s/apiVersion: ''/apiVersion: '${rev}'/g" auth.js
    fi
    REV=${rev} make build;
    cd ${CODEBUILD_SRC_DIR}
    mv "./lambda/${func}/build/function.zip" ".artifacts/functions/${rev}/${func}/";
  fi
done


