.PHONY: build
build:
	GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o bootstrap \
		&& rm -rf build && mkdir build && zip build/function.zip bootstrap
