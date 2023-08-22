
clean:
	rm -rf mel-spec
	rm -rf js-colormaps

.PHONY: build
build: clean
	npm i && npm run build
	git clone git@github.com:wavey-ai/mel-spec.git
	cd ./mel-spec/mel_spec_pipeline && wasm-pack build --target no-modules --no-typescript --out-dir ../../build --debug
	cd ./mel-spec/mel_spec_audio && wasm-pack build --target no-modules --no-typescript --out-dir ../../build --debug
	sed -i.bak "s/wasm_bindgen/wasm_bindgen_wav/g" build/mel_spec_audio.js
	cat src/ringbuffer.js src/worklet.js > build/worklet.js
	cp src/wav_worker.js build
	cp src/worker.js build
	git clone https://github.com/timothygebhard/js-colormaps.git
	cp js-colormaps/js-colormaps.js build
