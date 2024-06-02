#! /bin/bash
git clone https://github.com/paradigmxyz/reth
cd reth
cargo install --locked --path bin/reth --bin reth
