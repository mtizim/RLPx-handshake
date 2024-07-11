## What's this?

This is a Rust implementation of a RLPx handshake, as described in the [RLPx spec](https://github.com/ethereum/devp2p/blob/76cf0a141e8aa8616e3305738d51101945387d3c/rlpx.md)
A RLPx handshake is the p2p handshake used between Ethereum nodes

The implementation is bi-directional (it can either initiate or receive a handshake).
Firstly, it initiates a handshake with a [ethereum reth node](https://github.com/paradigmxyz/reth).
After confirming that initiating a handshake is done correctly, the code confirms that receival is correct by doing a network handshake with itself.

## Instructions

### Running

If you are using vscode:
- Open repository
- Reopen in container (a popup in the bottom right, or pick it from the command palette (CTRL+P))
- Wait for automatic setup to finish
- run `./run`

If you're not (but it's easier if you do):
- recreate devcontainer from `devcontainer.json` using the `image` field
- mount workspace in the recreated container
- run the line of code from `devcontainer.json/postCreateCommand`
- run `./run`

### Verifying handshake conclusion

The handshake process is described as such:
1. initiator connects to recipient and sends its `auth` message
2. recipient accepts, decrypts and verifies `auth` (checks that recovery of signature ==
   `keccak256(ephemeral-pubk)`)
3. recipient generates `auth-ack` message from `remote-ephemeral-pubk` and `nonce`
4. recipient derives secrets and sends the first encrypted frame containing the [Hello] message
5. initiator receives `auth-ack` and derives secrets
6. initiator sends its first encrypted frame containing initiator [Hello] message
7. recipient receives and authenticates first encrypted frame
8. initiator receives and authenticates first encrypted frame
9. cryptographic handshake is complete if MAC of first encrypted frame is valid on both sides

Which means that both parties receiving and verifying the hello message constitutes a successful handshake.
There's enough `print`s in the code to see when that happens.
If you need to doublecheck, `./run` also prints out a relevant part of the log from `reth`, where you can see that the message has been validated, and that reth now treats us as a peer


