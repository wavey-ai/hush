.PHONY: ecr
ecr:
	aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $(AWS_ACCOUNT).dkr.ecr.us-east-1.amazonaws.com

.PHONY: touch
touch:
	openssl rand -base64 12 > lambda/test-auth-token/.touch

.PHONY: cp_zips
cp_zips:
	cd ./lambda/test-auth-token && \
		aws s3 cp build/function.zip s3://$(DEPLOY_BUCKET)/latest/test-auth-token/

.PHONY: build_zips
build_zips:
	cd ./lambda/test-auth-token && make build

.PHONY: roles
roles:
	aws cloudformation deploy \
		--region us-east-1 \
		--stack-name $(ENV)-roles \
		--template-file roles.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides \
			CodeStarConnectionArn=$(CODESTAR_CONNECTION_ARN)


.PHONY: shared
shared:
	aws cloudformation deploy \
		--region $(REGION) \
		--stack-name $(ENV)-shared \
		--template-file shared.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides \
			CodeStarConnectionArn=$(CODESTAR_CONNECTION_ARN)

.PHONY: vpc
vpc:
	aws cloudformation deploy \
		--region $(REGION) \
		--stack-name $(ENV)-$(STACK_NAME)-vpc \
		--template-file vpc.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM

.PHONY: edgeauth
edgeauth:
	cd ./lambda/test-auth-token && make build
	./edgeauth.sh
	aws cloudformation deploy \
		--region us-east-1 \
		--stack-name $(ENV)-edgeauth \
		--template-file /tmp/edgeauth.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM

.PHONY: auth
auth:
	aws cloudformation deploy \
		--region $(REGION) \
		--stack-name $(ENV)-auth \
		--template-file auth.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides \
			Certificate=$(CERTIFICATE_ARN) \
			DomainName=$(DOMAIN_NAME) \
			HostedZoneId=$(HOSTED_ZONE_ID) \
			StageName=$(ENV)

.PHONY: opencdn
opencdn:
	aws cloudformation deploy \
		--region us-east-1 \
		--stack-name $(ENV)-opencdn \
		--template-file cdn.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides \
			Certificate=$(CERTIFICATE_ARN) \
			DomainName=$(DOMAIN_NAME) \
			HostedZoneId=$(HOSTED_ZONE_ID) \
			Subdomain=opencdn \
			StageName=$(ENV)
	aws s3 cp index.html s3://live-opencdn-opendistributionbucket-bcwqovshicgu/

.PHONY: gatedcdn
gatedcdn:
	./edgeauth.sh
	./gatedcdn.sh
	aws cloudformation deploy \
		--region us-east-1 \
		--stack-name $(ENV)-gatedcdn \
		--template-file /tmp/gatedcdn.yml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides \
			Certificate=$(CERTIFICATE_ARN) \
			DomainName=$(DOMAIN_NAME) \
			HostedZoneId=$(HOSTED_ZONE_ID) \
			StageName=$(ENV) \
			Subdomain=app

.PHONY: api
api:
	cd ./lambda/get-status && make build &&  \
		aws s3 cp build/function.zip s3://$(DEPLOY_BUCKET)/latest/get-status/
	./api.sh
	aws cloudformation deploy \
		--region $(REGION) \
		--stack-name $(ENV)-api \
		--template-file /tmp/api.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides \
			Certificate=$(CERTIFICATE_ARN_REGIONAL) \
			DomainName=$(DOMAIN_NAME) \
			HostedZoneId=$(HOSTED_ZONE_ID) \
			AppSubdomain=app \
			ApiSubdomain=api \
			StageName=$(ENV)


