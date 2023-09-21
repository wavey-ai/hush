#!/bin/bash

user_pool_id=$(aws cognito-idp list-user-pools --max-results 10 \
   --query "UserPools[?Name==\`live-$STACK_NAME-auth\`].Id | [0]" \
  --output text)

if [ "$user_pool_id" == "None" ]; then
  echo "User Pool 'live-$STACK_NAME-auth' not found."
  exit 1
fi

app_clients=$(aws cognito-idp list-user-pool-clients --user-pool-id $user_pool_id \
  --query 'UserPoolClients[].{ClientId:ClientId, ClientName:ClientName}' \
  --output json)
client_id=$(echo $app_clients | jq -r '.[0].ClientId')
client_secret=$(aws cognito-idp describe-user-pool-client --user-pool-id $user_pool_id --client-id $client_id \
  --query 'UserPoolClient.ClientSecret' --output text)

domain=$(aws cloudformation describe-stacks --stack-name live-$STACK_NAME-auth --query "Stacks[0].Outputs[?OutputKey=='UserPoolDomain'].OutputValue" --output text)
sed -i.bak "s/region: \"\"/region: 'us-east-1'/g" main.js
sed -i.bak "s/userPoolId: \"\"/userPoolId: '$user_pool_id'/g" main.js
sed -i.bak "s/userPoolAppId: \"\"/userPoolAppId: '$client_id'/g" main.js
sed -i.bak "s/userPoolAppSecret: \"\"/userPoolAppSecret: '$client_secret'/g" main.js
sed -i.bak "s/userPoolDomain: \"\"/userPoolDomain: '$domain'/g" main.js
sed -i.bak "s/apiVersion: \"\"/apiVersion: 'your_api_version_here'/g" main.js

