#!/bin/bash

rev=$(find ./lambda/test-auth-token/build/ -type f -exec md5sum {} + | sort -k 2 | md5sum | awk '{print $1}')
cp edgeauth.cfn.yml /tmp/edgeauth.cfn.yml

sed -i.bak "s/__rev__/${rev}/g" /tmp/edgeauth.cfn.yml

cd ./lambda/test-auth-token && \
  aws s3 cp build/function.zip "s3://${DEPLOY_BUCKET}/${rev}/test-auth-token/"

# Get the new value from CloudFormation stack
new_value=$(aws cloudformation describe-stacks --region=us-east-1 \
  --stack-name "live-${STACK_NAME}-edgeauth" \
  --query "Stacks[0].Outputs[?OutputKey==\`FunctionVersion\`].OutputValue" \
  --output text)

# Get the current value from SSM Parameter Store
current_value=$(aws ssm get-parameter --region us-east-1 \
  --name "live-${STACK_NAME}-edgeauth-FunctionVersion" \
  --query 'Parameter.Value' \
  --output text)

# Compare the new value with the current value and update if different
if [ "$new_value" != "$current_value" ]; then
  aws ssm put-parameter --region us-east-1 \
    --name "live-${STACK_NAME}-edgeauth-FunctionVersion" \
    --value "$new_value" \
    --type 'String' \
    --overwrite
fi

