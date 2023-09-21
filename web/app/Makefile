
.PHONY: co
co:
	git clone https://github.com/wavey-ai/mel-spec.git
	git clone https://github.com/timothygebhard/js-colormaps.git

clean:
	rm -rf mel-spec
	rm -rf js-colormaps

.PHONY: build
build:
	npm i && npm run build
	cd ./mel-spec/mel_spec_pipeline && wasm-pack build --target no-modules --no-typescript --out-dir ../../build --debug
	cd ./mel-spec/mel_spec_audio && wasm-pack build --target no-modules --no-typescript --out-dir ../../build --debug
	sed -i.bak "s/wasm_bindgen/wasm_bindgen_wav/g" build/mel_spec_audio.js
	sed -i.bak "s/wasm_bindgen/wasm_bindgen_mel/g" build/mel_spec_pipeline.js
	cp src/*.js build
	cat src/ringbuffer.js src/worklet.js > build/worklet.js
	cp js-colormaps/js-colormaps.js build
