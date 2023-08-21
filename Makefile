
.PHONY: vpc
vpc:
	aws cloudformation deploy \
		--region $(REGION) \
		--stack-name $(ENV)-$(STACK_NAME)-vpc \
		--template-file vpc.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM

.PHONY: deploy
deploy:
	cfn-lint ec2.cfn.yml
	aws cloudformation deploy \
	 --region $(REGION) \
	 --stack-name $(ENV)-${STACK_NAME} \
		--template-file ec2.cfn.yml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides \
			CertificateArn=$(CERTIFICATE_ARN) \
			DomainName=$(DOMAIN_NAME) \
			HostedZoneId=$(HOSTED_ZONE_ID) \
			AmiId=$(AMI_ID) \
			InstancePort=1337
