#!/bin/bash

rev=$(find ./lambda/get-status/build/ -type f -exec md5sum {} + | sort -k 2 | md5sum | awk '{print $1}')
cp api.cfn.yml /tmp/api.cfn.yml

sed -i.bak "s/__rev__/${rev}/g" /tmp/api.cfn.yml
	cd ./lambda/get-status && \
		aws s3 cp build/function.zip s3://$DEPLOY_BUCKET/$rev/get-status/
