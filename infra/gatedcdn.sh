#!/bin/bash

ParameterVersion=$(aws ssm get-parameter-history --region us-east-1 --name "${ENV}-edgeauth-FunctionVersion" --query 'Parameters | sort_by(@, &Version)[-1].Version' --output text)

./merge_yml_files.sh cdn.cfn.yml gatedcdn.yml /tmp/gatedcdn.yml
sed -i.bak "s/__version__/$ParameterVersion/g" /tmp/gatedcdn.yml
