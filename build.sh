#!/bin/bash

# the approach here is to hash services individually using md5sum so we
# only build and push what's required.
# lambda images are tagged with their md5sum and lambda zips are uploaded
# to s3 under a prefix that is their respective md5sum - as are web assets.
#
# the following pattern:
# touch ".artifacts/public/${GIT_REV}/uploads/${rev}";
# just allows the md5sum to be traced back to an actual git sha in
# s3 (sha => md5sum per service), should the need arise.

ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
ECR_REPO=${ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com
CODEBUILD_SRC_DIR=${CODEBUILD_SRC_DIR:=$(pwd)}
GIT_REV=${CODEBUILD_RESOLVED_SOURCE_VERSION:=$(git rev-parse HEAD)}
AWS_REGION=${AWS_REGION:=us-east-1}

aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com

rm -rf .artifacts
mkdir -p .artifacts/app .artifacts/templates
cp template.cfn.yml .artifacts/templates/template.yml

TEMPLATE=${CODEBUILD_SRC_DIR}/.artifacts/templates/template.yml

for site in app; do
  bkt="APP_BUCKET"

  rev=$(find ./web/${site}/ -type f -exec md5sum {} + | sort -k 2 | md5sum | awk '{print $1}')
  mkdir -p ".artifacts/${site}/${GIT_REV}"
  touch ".artifacts/${site}/${GIT_REV}/${rev}"
  mkdir ".artifacts/${site}/${rev}"

  if aws s3 ls "s3://${bkt}/${rev}" >/dev/null 2>&1; then
    echo "Tag ${rev} already exists in S3. Skipping build."
  else
    cd web/${site} && make build && cd "${CODEBUILD_SRC_DIR}"
    sed -i.bak "s/index.js/\/${rev}\/index.js/g" web/${site}/build/index.html
    sed -i.bak "s/index.css/\/${rev}\/index.css/g" web/${site}/build/index.html
    sed -i.bak "s/manifest.json/\/${rev}\/manifest.json/g" web/${site}/build/index.html
    mv web/${site}/build/* ".artifacts/${site}/"
    mv ".artifacts/${site}/index.js" ".artifacts/${site}/${rev}/"
    mv ".artifacts/${site}/index.css" ".artifacts/${site}/${rev}/"
    mv ".artifacts/${site}/manifest.json" ".artifacts/${site}/${rev}/"
  fi
done



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

sed -i.bak "s/__ArtifactsBucket__/${ARTIFACTS_BUCKET}/g" ${TEMPLATE}
