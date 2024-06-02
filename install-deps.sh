#! /bin/bash
rm -rf reth
git clone https://github.com/paradigmxyz/reth
# Let's have a hardcoded private key (so a public key as well) for the node
cd /workspaces/assignment/reth
cargo install --locked --path bin/reth --bin reth
echo -n "3369544a527fda55948730b467d47ecfd98bbe99ce1bb795d8bc0dd5c0ca85b0" > /home/vscode/.local/share/reth/dev/discovery-secret