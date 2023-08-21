# $${\color{pink}🤫hush}$$
### Silent Whisper inference for privacy and performance.

Current speech-to-text wrappers tend to require audio input, even though all 
models use mel spectrograms, not audio, internally.

This has drawbacks, as audio needs to be sent from the user's device to the 
server and if that is not possible the implementation is restricted to run 
locally.

_**hush**_ uses 8-bit grayscale images, not audio.

As well as helping to prevent leakage of identifiable information, this approach
simplifies voice activity detection, caching, storage / retrieval and bandwidth 
considerations by removing audio signal processing and large audio payloads from
the pipeline.

For more background on how mel spectrograms are generated and used, see 
[wavey-ai/mel-spec](https://github.com/wavey-ai/mel-spec.git) 

To run inference, _**hush**_ uses a fork of the brilliant [whisper-burn](https://github.com/wavey-ai/whisper-burn.git) 
that uses Rust's [burn-rs](https://github.com/burn-rs/burn) Deep Learning framework
and [tch-rs](https://github.com/LaurentMazare/tch-rs) (Rust bindings for the C++ api of PyTorch). 
The fork provides a mel API and exposes whisper-burn as a service, and configures a CUDA backend.


#### demo

The demo UI has the following components:

* non-blocking WASM workers that convert audio (from file or microphone) into
  mel spectrograms on a stream
* voice activity detection that looks at the relative complexity of the 
  spectrogram 
* a client that POSTs audio segments as images to the AWS service running 
  Whisper on GPU, receiving a text translation back

#### deployment

The included `ami.sh` creates an image with GPU support for running NVIDIA T4 
Tensor Core instances. _A public ami will be provided soon._

The cloudformation template creates an Auto Scaling Group that requests a 
`g4dn.xlarge` spot instance and exposes the demo api on [https://hush.wavey.ai](https://hush.wavey.ai).

The same template creates the demo UI, Github auth and a self-updating AWS 
CodePipeline project that applies infrastructure changes via the template
alongside any code changes in the repo. (The approach of using a self-updating 
Pipeline has been well tested in our other projects with high velocity teams 
and is a robust one.)

The initial deployment should be done from local via the `make app` task, this
will create the CodePipeline pipeline.

Full instructions: TODO.

#### TODO

This is very much a POC and a WIP.

* Support Web GPU (AWS G4ad instance w/AMD Radeon Pro V520 GPU)
* Admin UI 
