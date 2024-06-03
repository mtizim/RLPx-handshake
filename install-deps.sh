#! /bin/bash
rm -f ./reth
wget https://github.com/paradigmxyz/reth/releases/download/v0.2.0-beta.6/reth-v0.2.0-beta.6-x86_64-unknown-linux-gnu.tar.gz
tar -xvzf reth-v0.2.0-beta.6-x86_64-unknown-linux-gnu.tar.gz
rm -f reth-v0.2.0-beta.6-x86_64-unknown-linux-gnu.tar.gz
# Let's have a hardcoded private key (so a public key as well) for the node
mkdir -p ~/.local/share/reth/dev
echo -n "3369544a527fda55948730b467d47ecfd98bbe99ce1bb795d8bc0dd5c0ca85b0" > ~/.local/share/reth/dev/discovery-secret