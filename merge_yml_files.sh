#!/bin/bash

# Check if the right number of arguments are passed
if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <file1.yaml> <file2.yaml> <output.yaml>"
    exit 1
fi

# Check if yq is installed
if ! command -v yq &> /dev/null; then
    echo "yq is not installed. Please install it first."
    exit 1
fi

# Input files
file1="$1"
file2="$2"

# Output file
output="$3"

# Perform deep merge using yq
yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' "$file1" "$file2" > "$output"

# Verify and output the result
if [[ $? -eq 0 ]]; then
    echo "Successfully merged $file1 and $file2 into $output."
else
    echo "Failed to merge files."
    exit 1
fi

