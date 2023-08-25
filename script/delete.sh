#!/bin/bash

keyword1="wavey"
keyword2="hush"

# Get a list of bucket names
bucket_names=$(aws s3api list-buckets --query "Buckets[].Name" --output text)

# Loop through the bucket names
for bucket_name in $bucket_names; do
    if [[ $bucket_name == *$keyword1* || $bucket_name == *$keyword2* ]]; then
        echo "Emptying and deleting bucket: $bucket_name"

        # Empty the bucket
        aws s3 rm s3://$bucket_name --recursive

        # Delete the bucket
        aws s3api delete-bucket --bucket $bucket_name
    fi
done

