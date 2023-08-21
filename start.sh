#! /bin/sh

cd hush && git pull --rebase origin master && cd hush && cargo build
./target/debug/hush -m medium_en
