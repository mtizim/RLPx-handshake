use initiator::initiate;
use p2p::PersistentKeys;
use secp256k1::{SecretKey, SECP256K1};
use thiserror::Error;

mod basic;
mod ecies;
mod initiator;
mod macstate;
mod p2p;
mod recipient;

#[tokio::main]
async fn main() {
    let reth_privkey = "3369544a527fda55948730b467d47ecfd98bbe99ce1bb795d8bc0dd5c0ca85b0"
        .parse::<SecretKey>()
        .expect("known good value");
    let reth_pubkey = secp256k1::PublicKey::from_secret_key(SECP256K1, &reth_privkey);

    println!("##################");
    println!("Initiating handshake with peer");
    println!("(we're the initiator, reth (known good implementation) is the peer)");
    println!("##################");

    initiate("0.0.0.0:30303", reth_pubkey)
        .await
        .expect("Handshake should have gone correctly");

    println!("\nPer spec, handshake ends when both parties have received and verified their hello messages");
    println!("If our hello was bad, the tcp connection should have been closed, and we'd have seen an error");
    println!("So we know our hello was good, we confirmed their hello was good");
    println!("So the handshake has finished successfully");
    println!("(if you want to doublecheck, look for 'sending eth status to peer' in reth.log, this confirms that the reth node now regards us as a peer");

    println!("\n\n##################");
    println!("Receiving handshake from peer");
    println!("(now that we know that we can initiate a handshake correctly, it's this code handshaking itself)");
    println!("##################");

    let receiver_identity = PersistentKeys::new();

    recipient::receive("0.0.0.0:33339", &receiver_identity)
        .await
        .expect("Handshake receival should have gone correctly");

    initiate("0.0.0.0:33339", receiver_identity.public)
        .await
        .expect("Handshake should have gone correctly");

    println!("\n");
    println!(
        "Both sides verified their hello messages - \n  the handshake has finished successfully!\n\n"
    );
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("concat kdf error")]
    KdfError(#[from] concat_kdf::Error),
    #[error("secp256k1 error")]
    Secp256k1Error(#[from] libsecp256k1_core::Error),
    #[error("Numeric conversion failed")]
    TryFromIntError(#[from] std::num::TryFromIntError),
    #[error("Not enough data received")]
    NotEnoughData(),
    #[error("RLP error - incoming data malformed")]
    RlpError(#[from] alloy_rlp::Error),
    #[error("TagMismatch")]
    TagMismatch(),
    #[error("ECIES parsing error")]
    EciesParsingError(),
    #[error("Invalid tag")]
    InvalidTag(),
    #[error("IO")]
    IOError(#[from] std::io::Error),
    #[error("Out of assignment scope")]
    OutOfScope,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Message timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, Error>;
