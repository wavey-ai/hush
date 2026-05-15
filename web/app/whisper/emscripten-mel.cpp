#include "whisper.h"

#include <emscripten/bind.h>

#include <algorithm>
#include <string>
#include <thread>
#include <vector>

std::vector<struct whisper_context *> g_contexts(1, nullptr);

static int thread_count(int requested) {
    const int hardware = std::max(1, (int) std::thread::hardware_concurrency());
    return std::max(1, std::min(requested, std::min(8, hardware)));
}

EMSCRIPTEN_BINDINGS(hush_whisper) {
    emscripten::function("init", emscripten::optional_override([](const std::string & path_model) {
        if (g_contexts[0] == nullptr) {
            g_contexts[0] = whisper_init_from_file_with_params(
                path_model.c_str(),
                whisper_context_default_params()
            );
        }

        return g_contexts[0] == nullptr ? 0 : 1;
    }));

    emscripten::function("free", emscripten::optional_override([](size_t index) {
        if (index == 0 || index > g_contexts.size()) {
            return;
        }

        --index;
        if (g_contexts[index]) {
            whisper_free(g_contexts[index]);
            g_contexts[index] = nullptr;
        }
    }));

    emscripten::function("full_default_mel", emscripten::optional_override([](
        size_t index,
        const emscripten::val & mel,
        int n_mels,
        const std::string & lang,
        int nthreads,
        bool translate
    ) {
        if (index == 0 || index > g_contexts.size()) {
            return std::string("ERROR: invalid instance");
        }

        --index;
        whisper_context * ctx = g_contexts[index];
        if (ctx == nullptr) {
            return std::string("ERROR: whisper is not initialized");
        }

        const int n = mel["length"].as<int>();
        if (n_mels <= 0 || n % n_mels != 0) {
            return std::string("ERROR: invalid mel shape");
        }

        std::vector<float> mel_data(n);
        emscripten::val heap = emscripten::val::module_property("HEAPU8");
        emscripten::val memory = heap["buffer"];
        emscripten::val memory_view = mel["constructor"].new_(
            memory,
            reinterpret_cast<uintptr_t>(mel_data.data()),
            n
        );
        memory_view.call<void>("set", mel);

        const int n_len = n / n_mels;
        if (whisper_set_mel(ctx, mel_data.data(), n_len, n_mels) != 0) {
            return std::string("ERROR: whisper_set_mel failed");
        }

        whisper_full_params params = whisper_full_default_params(WHISPER_SAMPLING_GREEDY);
        const bool multilingual = whisper_is_multilingual(ctx);

        params.print_realtime = false;
        params.print_progress = false;
        params.print_timestamps = false;
        params.print_special = false;
        params.translate = translate;
        params.language = multilingual ? lang.c_str() : "en";
        params.n_threads = thread_count(nthreads);
        params.offset_ms = 0;
        params.no_context = true;
        params.no_timestamps = true;
        params.single_segment = true;

        whisper_reset_timings(ctx);
        const int ret = whisper_full(ctx, params, nullptr, 0);
        if (ret != 0) {
            return std::string("ERROR: whisper_full failed: ") + std::to_string(ret);
        }

        std::string text;
        const int n_segments = whisper_full_n_segments(ctx);
        for (int i = 0; i < n_segments; ++i) {
            const char * segment = whisper_full_get_segment_text(ctx, i);
            if (segment) {
                text += segment;
            }
        }

        return text;
    }));
}
