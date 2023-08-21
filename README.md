### 🤫 *hush*

#### Silent whipser inference for privacy and performance.

Current speech-to-text wrappers tend to require audio input, even though all models use mel spectrograms, not audio, interally.

This has drawbacks, as audio needs to be sent from the user's device to the server and if that is not possible the implementation is restriced to run locally.

_**hush**_ uses 8-bit grayscale images, not audio.

As well as helping to prevent leakage of identifiable information, this approach simplifies voice activity detection, caching, storage/retrival and bandwidth considerations by removing audio signal procesing and large audio payploads from the pipeline.

For more background on how mel spectrograms are generated and used, see [wavey-ai/mel-spec](https://github.com/wavey-ai/mel-spec.git) 
