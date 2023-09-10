.PHONY: build
build:
	GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -o bootstrap \
		&& rm -rf build && mkdir build && zip build/function.zip bootstrap
