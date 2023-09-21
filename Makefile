.PHONY: ecr
ecr:
	aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $(AWS_ACCOUNT).dkr.ecr.us-east-1.amazonaws.com

.PHONY: touch
touch:
	openssl rand -base64 12 > lambda/test-auth-token/.touch
	openssl rand -base64 12 > web/app/.touch

.PHONY: vpc
vpc:
	aws cloudformation deploy \
		--region $(REGION) \
		--stack-name $(ENV)-$(STACK_NAME)-vpc \
		--template-file vpc.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM

.PHONY: app
app:
	cd web/app && make build
	./app.sh
	aws s3 sync .artifacts/web/app s3://$(GATED_BUCKET)

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
