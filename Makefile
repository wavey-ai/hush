.PHONY: ecr
ecr:
	aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $(AWS_ACCOUNT).dkr.ecr.us-east-1.amazonaws.com

.PHONY: touch
touch:
	openssl rand -base64 12 > lambda/test-auth-token/.touch

.PHONY: vpc
vpc:
	aws cloudformation deploy \
		--region $(REGION) \
		--stack-name $(ENV)-$(STACK_NAME)-vpc \
		--template-file vpc.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM

.PHONY: app
app:
	cfn-lint app.cfn.yml
	aws cloudformation deploy \
	 --region $(REGION) \
	 --stack-name $(ENV)-${STACK_NAME} \
		--template-file ec2.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides \
			PipelineOnly=yes \
			RepositoryId=wavey-ai/hush \
			CertificateArn=$(CERTIFICATE_ARN) \
			DomainName=$(DOMAIN_NAME) \
			HostedZoneId=$(HOSTED_ZONE_ID) \
			StageName=$(ENV) \
			CodeStarConnectionArn=$(CODESTAR_CONNECTION_ARN) \
			BranchName=$(BRANCH_NAME)
			AmiId=$(AMI_ID) \
			InstancePort=1337

.PHONY: cp_zips
cp_zips:
	cd ./lambda/test-auth-token && \
		aws s3 cp build/function.zip s3://$(BOOTSTRAP_BUCKET)/latest/test-auth-token/

.PHONY: build_zips
build_zips:
	cd ./lambda/test-auth-token && \
		npm install --omit=dev && \
		rm -rf build && mkdir build && \
		esbuild auth.js --bundle --outfile=main.js --platform=node  --external:'aws-sdk' && \
		zip -r build/function.zip main.js && rm main.js
