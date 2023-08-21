.PHONY: build
build:
		npm i -g esbuild &&\
		npm i --omit=dev && \
		rm -rf build && mkdir build && \
		esbuild auth.js --bundle --outfile=main.js --platform=node  --external:'aws-sdk' && \
		zip -r build/function.zip main.js && rm main.js
