SHELL := /bin/bash

OUT_DIR := dist/code/hush
WASM_DIR := $(OUT_DIR)/dist
DEPS_DIR := .deps
MEL_SPEC_LOCAL := ../../../mel-spec
MEL_SPEC_DIR ?= $(shell if [ -d "$(MEL_SPEC_LOCAL)" ]; then printf "$(MEL_SPEC_LOCAL)"; else printf "$(DEPS_DIR)/mel-spec"; fi)

.PHONY: clean deps build

clean:
	rm -rf dist
	mkdir -p "$(WASM_DIR)"

deps:
	@if [ ! -d "$(MEL_SPEC_DIR)" ]; then \
		rm -rf "$(DEPS_DIR)/mel-spec"; \
		mkdir -p "$(DEPS_DIR)"; \
		git clone --depth 1 https://github.com/wavey-ai/mel-spec.git "$(DEPS_DIR)/mel-spec"; \
	fi

build: clean deps
	cp public/* "$(OUT_DIR)/"
	cp src/app.js src/ringbuffer.js src/worker.js "$(OUT_DIR)/"
	cat src/ringbuffer.js src/worklet.js > "$(WASM_DIR)/worklet.js"
	cd "$(MEL_SPEC_DIR)" && wasm-pack build --features=wasm --target no-modules --no-typescript --out-dir "$(abspath $(WASM_DIR))" --release
	rm -f "$(WASM_DIR)"/*.bak "$(WASM_DIR)/.gitignore" "$(WASM_DIR)/LICENSE-MIT" "$(WASM_DIR)/README.md" "$(WASM_DIR)/package.json"
