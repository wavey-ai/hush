#! /bin/sh

sudo yum install openssl-devel git gcc make
sudo yum install -y gcc kernel-devel-$(uname -r)
aws s3 cp --recursive s3://ec2-linux-nvidia-drivers/latest/ .
chmod +x NVIDIA-Linux-x86_64*.run
sudo /bin/sh ./NVIDIA-Linux-x86_64*.run
nvidia-smi -q | head
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default nightly
wget https://developer.download.nvidia.com/compute/cuda/11.8.0/local_installers/cuda_11.8.0_520.61.05_linux.run
sudo sh cuda_11.8.0_520.61.05_linux.run --silent --override --toolkit --samples --toolkitpath=/usr/local/cuda-version --samplespath=/usr/local/cuda --no-opengl-libs
wget https://download.pytorch.org/libtorch/cu118/libtorch-cxx11-abi-shared-with-deps-2.0.1%2Bcu118.zip
unzip libtorch-cxx11-abi-shared-with-deps-2.0.1+cu118.zip
sudo ln -s /usr/local/cuda-11.8 /usr/local/cuda

wget -P hush/hush https://huggingface.co/Gadersd/whisper-burn/resolve/main/medium_en/medium_en.cfg
wget -P hush/hush https://huggingface.co/Gadersd/whisper-burn/resolve/main/medium_en/medium_en.mpk.gz

echo "export LIBTORCH=/home/ec2-user/libtorch" >> ~/.bashrc
echo "export LD_LIBRARY_PATH=/home/ec2-user/libtorch/lib:" >> ~/.bashrc

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.4/install.sh | bash
nvm i node
npm i -g pm2

pm2 startup
