### 🤫 *hush*

#### Silent Whipser inference for privacy and performance.

Current speech-to-text wrappers tend to require audio input, even though all models use mel spectrograms, not audio, interally.

This has drawbacks, as audio needs to be sent from the user's device to the server and if that is not possible the implementation is restriced to run locally.

_**hush**_ uses 8-bit grayscale images, not audio.

As well as helping to prevent leakage of identifiable information, this approach simplifies voice activity detection, caching, storage/retrival and bandwidth considerations by removing audio signal procesing and large audio payploads from the pipeline.

For more background on how mel spectrograms are generated and used, see [wavey-ai/mel-spec](https://github.com/wavey-ai/mel-spec.git) 

To run inference, _**hush**_ uses a fork of the brilliant [whisper-burn](https://github.com/wavey-ai/whisper-burn.git) which uses Rust's [burn-rs](https://github.com/burn-rs/burn) Deep Learning framework and [tch-rs](https://github.com/LaurentMazare/tch-rs) (Rust bindings for the C++ api of PyTorch). The fork provides a mel API and exposes whisper-burn as a service, and configures a CUDA backend.

#### deployment

The included `ami.sh` creates an image with GPU support for running NVIDIA T4 Tensor Core instances. _A public ami will be provided soon._

The cloudformation template creates an Auto Scaling Group that requests a `g4dn.xlarge` spot instance and exposes the demo api on [https://hush.wavey.ai](https://hush.wavey.ai).

#### TODO

* Authentication
* Support Web GPU (AWS G4ad instance w/AMD Radeon Pro V520 GPU)
