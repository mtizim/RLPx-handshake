use initiator::initiate;
use secp256k1::{SecretKey, SECP256K1};
use thiserror::Error;

mod basic;
mod ecies;
mod initiator;
mod macstate;

#[tokio::main]
async fn main() {
    let privkey = "3369544a527fda55948730b467d47ecfd98bbe99ce1bb795d8bc0dd5c0ca85b0"
        .parse::<SecretKey>()
        .unwrap();
    let recipient_pubkey = secp256k1::PublicKey::from_secret_key(SECP256K1, &privkey);

    initiate(recipient_pubkey).await.unwrap();
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
    #[error("IO")]
    IOError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
