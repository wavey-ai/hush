.PHONY: build
build:
		npm i -g esbuild
		npm i --omit=dev
		rm -rf build && mkdir build
		esbuild auth.js --bundle --outfile=main.js --platform=node  --external:'aws-sdk'
		./build.sh
		zip -r build/function.zip main.js
