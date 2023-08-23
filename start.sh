#! /bin/sh

git pull --rebase origin main && cd hush && cargo build
cargo run --release
