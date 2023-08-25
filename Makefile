.PHONY: ecr
ecr:
	aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $(AWS_ACCOUNT).dkr.ecr.us-east-1.amazonaws.com

.PHONY: vpc
vpc:
	aws cloudformation deploy \
		--region $(REGION) \
		--stack-name $(ENV)-$(STACK_NAME)-vpc \
		--template-file vpc.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM
