#! /bin/sh

git pull --rebase origin main && cd hush && cargo build
./target/debug/hush -m tiny_en
