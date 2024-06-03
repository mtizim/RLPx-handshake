use std::time::Duration;

use ethereum_types::H256;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::ecdsa::RecoveryId;
use secp256k1::SECP256K1;
use tokio::net::TcpListener;
use tokio::task;
use tokio::time::sleep;

use crate::basic::keccak256;
use crate::ecies::ecies_decrypt_message;
use crate::p2p::receive_hello;
use crate::p2p::send_hello;
use crate::p2p::AuthAckBody;
use crate::p2p::AuthBody;
use crate::p2p::AuthSecrets;
use crate::p2p::P2PState;
use crate::p2p::PersistentKeys;
use crate::p2p::AUTH_PADDING;
use crate::p2p::AUTH_VSN;
use crate::p2p::MAX_MESSAGE_SIZE;
use crate::p2p::SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
use alloy_rlp::Decodable;
use alloy_rlp::Encodable;
use secp256k1::PublicKey;
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

pub async fn receive(address: impl ToSocketAddrs, own_identity: &PersistentKeys) -> Result<()> {
    let listener = TcpListener::bind(address).await?;
    let own_identity = own_identity.clone();
    // This is not an actual node, we just listen to one single handshake request
    task::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                receive_stream(stream, &own_identity)
                    .await
                    .expect("Handshake receival should have gone correctly");
            }
        }
    });

    Ok(())
}

async fn receive_stream(mut stream: TcpStream, own_identity: &PersistentKeys) -> Result<()> {
    let ephemeral_privkey = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let receiver_nonce = H256::random();
    let (auth_secrets, initiator_identity_pubkey, initiator_nonce, auth_bytes) =
        receive_auth_message(
            &mut stream,
            own_identity,
            &ephemeral_privkey,
            &receiver_nonce,
        )
        .await?;
    println!("Recipient: Got auth message");
    let ack_bytes = send_auth_ack(
        &mut stream,
        &ephemeral_privkey,
        &initiator_identity_pubkey,
        &receiver_nonce,
    )
    .await?;
    println!("Recipient: Sent auth ack");
    let mut state = P2PState::new(
        initiator_identity_pubkey,
        auth_secrets,
        receiver_nonce,
        initiator_nonce,
        &ack_bytes,
        &auth_bytes,
    );

    // We're sending two things after each other, and this being on the same OS thread doesn't give the listener a chance to be ready in time
    // This wouldn't be a problem if the TcpStream were separated into a Sink and a Stream and buffered,
    // But we can't all be perfect, and I already spent too much time implementing all this for a take home assignment
    //
    // So the hack is to pass control to the initiator here
    sleep(Duration::from_millis(0)).await;
    send_hello(own_identity, &mut state, &mut stream).await?;
    println!("Recipient: Sent hello");
    receive_hello(&mut state, &mut stream).await?;
    println!("Recipient: Received and verified hello");

    // Let the initiator do it's thing before closing the connection with the end of scope here
    sleep(Duration::from_millis(1000)).await;
    Ok(())
}

async fn send_auth_ack(
    stream: &mut TcpStream,
    ephemeral_privkey: &SecretKey,
    initiator_pubkey: &PublicKey,
    recipient_nonce: &H256,
) -> Result<Vec<u8>> {
    // ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
    let mut auth_ack_body = Vec::with_capacity(64 + 31 + 1 + 8);
    AuthAckBody {
        recipient_ephemeral_pubk: ephemeral_privkey
            .public_key(SECP256K1)
            .serialize_uncompressed()[1..65]
            .try_into()
            .expect("65 - 1 == 64"),
        recipient_nonce: recipient_nonce
            .as_bytes()
            .to_owned()
            .try_into()
            .expect("32 == 32"),
        // Spec says 4 so it's 4
        ack_vsn: AUTH_VSN,
    }
    .encode(&mut auth_ack_body);
    // Let's use the same padding, as it's unimportant anyway
    let message = [auth_ack_body.as_slice(), AUTH_PADDING.as_bytes()].concat();
    let auth_message = ecies_encrypt_message(initiator_pubkey, message)?;
    stream.write_all(&auth_message).await?;
    stream.flush().await?;
    Ok(auth_message)
}

async fn receive_auth_message(
    stream: &mut TcpStream,
    identity: &PersistentKeys,
    ephemeral_privkey: &SecretKey,
    recipient_nonce: &H256,
) -> Result<(AuthSecrets, PublicKey, H256, Vec<u8>)> {
    let buf = &mut [0u8; 512];
    let bytes_read = stream.take(MAX_MESSAGE_SIZE).read(buf).await?;
    let mut auth_bytes = vec![];
    auth_bytes.extend_from_slice(&buf[..bytes_read]);
    let decrypted = ecies_decrypt_message(&identity.secret, &auth_bytes)?;

    // Decode rlp data
    let body = AuthBody::decode(&mut decrypted.as_slice())?;

    // Read from signature
    let signature = RecoverableSignature::from_compact(
        &body.sig[..64],
        RecoveryId::from_i32(body.sig[64] as i32).map_err(|_| Error::InvalidSignature)?,
    )
    .map_err(|_| Error::InvalidSignature)?;

    let mut pubk_bytes = vec![SECP256K1_TAG_PUBKEY_UNCOMPRESSED];
    pubk_bytes.extend_from_slice(&body.initiator_pubk);

    let initiator_identity_pubkey =
        PublicKey::from_slice(&pubk_bytes).map_err(|_| Error::EciesParsingError())?;
    // Generated secrets:

    let static_shared_secret = ecdh(&identity.secret, &initiator_identity_pubkey);
    let initiator_ephemeral_pubkey = SECP256K1
        .recover_ecdsa(
            &secp256k1::Message::from_digest(
                xor(static_shared_secret.as_bytes(), &body.initiator_nonce)
                    .try_into()
                    .expect("32 == 32"),
            ),
            &signature,
        )
        .map_err(|_| Error::InvalidSignature)?;

    let ephemeral_key = ecdh(ephemeral_privkey, &initiator_ephemeral_pubkey);
    let shared_secret = H256::from_slice(&keccak256(
        [
            ephemeral_key.as_bytes(),
            &keccak256([recipient_nonce.as_bytes(), &body.initiator_nonce].concat()),
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
    Ok((
        secrets,
        initiator_identity_pubkey,
        H256(body.initiator_nonce),
        auth_bytes,
    ))
}
