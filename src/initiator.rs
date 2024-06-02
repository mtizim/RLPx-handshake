use crate::basic::keccak256;
use crate::ecies::ecies_decrypt_message;
use crate::p2p::receive_hello;
use crate::p2p::send_hello;
use crate::p2p::AckBody;
use crate::p2p::AuthAckBody;
use crate::p2p::AuthSecrets;
use crate::p2p::P2PState;
use crate::p2p::PersistentKeys;
use crate::p2p::AUTH_PADDING;
use crate::p2p::AUTH_VSN;
use crate::p2p::MAX_MESSAGE_SIZE;
use crate::p2p::SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
use alloy_rlp::Decodable;
use alloy_rlp::Encodable;
use ethereum_types::H256;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs;

use crate::basic::xor;
use crate::ecies::ecdh;
use crate::ecies::ecies_encrypt_message;
use crate::Error;
use crate::Result;

pub async fn initiate(address: impl ToSocketAddrs, recipient_pubkey: PublicKey) -> Result<()> {
    let mut stream = TcpStream::connect(address).await?;

    // (should be) Persistent identity
    // Ofc we're not really a peer so we don't persist it anywhere
    let identity = PersistentKeys::new();

    // Ephemeral keyset
    let ephemeral_privkey = SecretKey::new(&mut secp256k1::rand::thread_rng());

    // Initial ephemeral key exchange
    let initiator_nonce = H256::random();
    let auth_bytes = send_auth_message(
        recipient_pubkey,
        identity.secret,
        ephemeral_privkey,
        identity.public,
        initiator_nonce,
        &mut stream,
    )
    .await?;
    println!("Initiator: Sent auth message");

    let (secrets, ack_body, ack_bytes) = receive_auth_ack(
        &mut stream,
        &identity,
        ephemeral_privkey,
        recipient_pubkey,
        initiator_nonce,
    )
    .await?;
    println!("Initiator: Received auth ack");

    let mut state = P2PState::new(
        recipient_pubkey,
        secrets,
        initiator_nonce,
        H256::from_slice(&ack_body.recipient_nonce),
        &auth_bytes,
        &ack_bytes,
    );

    send_hello(&identity, &mut state, &mut stream).await?;
    println!("Initiator: Sent hello");

    receive_hello(&mut state, &mut stream).await?;
    println!("Initiator: Received and verified hello");

    Ok(())
}

async fn receive_auth_ack(
    stream: &mut TcpStream,
    identity: &PersistentKeys,
    ephemeral_privkey: SecretKey,
    recipient_pubkey: PublicKey,
    initiator_nonce: H256,
) -> Result<(AuthSecrets, AuthAckBody, Vec<u8>)> {
    let buf = &mut [0u8; 512];
    let bytes_read = stream.take(MAX_MESSAGE_SIZE).read(buf).await?;
    let mut ack_bytes = vec![];
    ack_bytes.extend_from_slice(&buf[..bytes_read]);
    let decrypted = ecies_decrypt_message(&identity.secret, &ack_bytes)?;
    // Decode rlp data

    let body = AuthAckBody::decode(&mut decrypted.as_slice())?;
    let mut pubk_bytes = vec![SECP256K1_TAG_PUBKEY_UNCOMPRESSED];
    pubk_bytes.extend_from_slice(&body.recipient_ephemeral_pubk);
    let recipient_ephemeral_pubk =
        PublicKey::from_slice(&pubk_bytes).map_err(|_| Error::EciesParsingError())?;
    // Generated secrets:
    let static_shared_secret = ecdh(&identity.secret, &recipient_pubkey);
    let ephemeral_key = ecdh(&ephemeral_privkey, &recipient_ephemeral_pubk);
    let shared_secret = H256::from_slice(&keccak256(
        [
            ephemeral_key.as_bytes(),
            &keccak256([&body.recipient_nonce, initiator_nonce.as_bytes()].concat()),
        ]
        .concat(),
    ));

    let aes_secret = H256::from_slice(&keccak256(
        [ephemeral_key.as_bytes(), shared_secret.as_bytes()].concat(),
    ));
    let mac_secret = H256::from_slice(&keccak256(
        [ephemeral_key.as_bytes(), aes_secret.as_bytes()].concat(),
    ));
    let secrets = AuthSecrets {
        ephemeral_key,
        mac_secret,
        shared_secret,
        static_shared_secret,
        aes_secret,
    };
    Ok((secrets, body, ack_bytes))
}

async fn send_auth_message(
    recipient_pubkey: PublicKey,
    initiator_privkey: SecretKey,
    ephemeral_privkey: SecretKey,
    initiator_pubkey: PublicKey,
    initiator_nonce: H256,
    stream: &mut TcpStream,
) -> Result<Vec<u8>> {
    let ecdh = ecdh(&initiator_privkey, &recipient_pubkey);
    let msg: [u8; 32] = xor(initiator_nonce.as_bytes(), ecdh.as_bytes())
        .try_into()
        .expect("32 bits");
    let (rec_id, sig) = Secp256k1::new()
        .sign_ecdsa_recoverable(&secp256k1::Message::from_digest(msg), &ephemeral_privkey)
        .serialize_compact();

    let mut sig_bytes = [0_u8; 65];
    sig_bytes[..64].copy_from_slice(&sig);
    sig_bytes[64] = rec_id.to_i32() as u8;
    // auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]

    let mut auth_body = Vec::with_capacity(65 + 64 + 32 + 1 + 8);
    AckBody {
        sig: sig_bytes,
        initiator_pubk: initiator_pubkey.serialize_uncompressed()[1..]
            .try_into()
            .expect("65 - 1 == 64"),
        initiator_nonce: *initiator_nonce.as_fixed_bytes(),
        auth_vsn: AUTH_VSN,
    }
    .encode(&mut auth_body);
    let message = [auth_body.as_slice(), AUTH_PADDING.as_bytes()].concat();
    let auth_message = ecies_encrypt_message(&recipient_pubkey, message)?;
    stream.write_all(&auth_message).await?;
    stream.flush().await?;
    Ok(auth_message)
}
