use crate::basic::keccak256;
use crate::ecies::ecies_decrypt_message;
use crate::macstate::MacState;
use aes::cipher::KeyInit;
use aes::Aes128;
use aes::Aes256;
use alloy_rlp::BytesMut;
use alloy_rlp::Decodable;
use alloy_rlp::Encodable;
use alloy_rlp::Rlp;
use alloy_rlp::RlpDecodable;
use alloy_rlp::RlpEncodable;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use cipher::KeyIvInit;
use cipher::StreamCipher;
use ctr::Ctr64BE;
use ethereum_types::H128;
use ethereum_types::H256;
use ethereum_types::H264;
use ethereum_types::H512;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::ecdsa::RecoveryId;
use secp256k1::ffi::SECP256K1_SER_UNCOMPRESSED;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use secp256k1::SECP256K1;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::basic::xor;
use crate::ecies::ecdh;
use crate::ecies::ecies_encrypt_message;
use crate::Error;
use crate::Result;

static AUTH_PADDING: &str = "arbitrary data";
static AUTH_VSN: u8 = 4;
const PROTOCOL_VERSION: usize = 5;

// header = frame-size || header-data || header-padding
// header-data = [capability-id, context-id]
// capability-id = integer, always zero
// context-id = integer, always zero
// header-padding = zero-fill header to 16-byte boundary
// => header = frame-size || constant-data
// A header just has frame size and constant RLP artifacts
const ZERO_HEADER: &[u8; 3] = &[194, 128, 128]; //
const SECP256K1_TAG_PUBKEY_UNCOMPRESSED: u8 = 4;

struct PersistentKeys {
    secret: SecretKey,
    public: PublicKey,
}

impl PersistentKeys {
    fn new() -> PersistentKeys {
        let privkey = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let pubkey = secp256k1::PublicKey::from_secret_key(SECP256K1, &privkey);
        PersistentKeys {
            secret: privkey,
            public: pubkey,
        }
    }
}

struct P2PState {
    secrets: AuthSecrets,

    egress_mac: MacState,
    egress_aes: Ctr64BE<Aes256>,

    ingress_mac: MacState,
    ingress_aes: Ctr64BE<Aes256>,
}

impl P2PState {
    fn new(
        secrets: AuthSecrets,
        our_nonce: H256,
        their_nonce: H256,
        our_sent: &[u8],
        their_sent: &[u8],
    ) -> P2PState {
        let mac_secret = secrets.mac_secret;

        let mut egress_mac_state = MacState::new(mac_secret);
        egress_mac_state.update(&xor(mac_secret.as_bytes(), their_nonce.as_bytes()));
        egress_mac_state.update(our_sent);

        let mut ingress_mac_state = MacState::new(mac_secret);
        ingress_mac_state.update(&xor(mac_secret.as_bytes(), our_nonce.as_bytes()));
        ingress_mac_state.update(their_sent);

        P2PState {
            egress_mac: egress_mac_state,
            ingress_mac: ingress_mac_state,
            ingress_aes: <ctr::Ctr64BE<Aes256> as KeyIvInit>::new(
                secrets.aes_secret.as_ref().into(),
                H128::default().as_bytes().into(),
            ),
            egress_aes: <ctr::Ctr64BE<Aes256> as KeyIvInit>::new(
                secrets.aes_secret.as_ref().into(),
                H128::default().as_bytes().into(),
            ),
            secrets,
        }
    }

    fn compute_frame(&mut self, frame_data: &[u8]) -> Vec<u8> {
        // frame size
        // we'd need an u24 for this, but let's just truncate a u64 instead
        let mut buf = [0; 8];
        let n_bytes = 3; // 3 * 8 = 24;
        BigEndian::write_uint(&mut buf, frame_data.len() as u64, n_bytes);
        // header = frame-size || constant-data
        let mut header = [0_u8; 16];
        header[..3].copy_from_slice(&buf[..3]);
        header[3..6].copy_from_slice(ZERO_HEADER);

        // encrypt header, update mac for header
        self.egress_aes.apply_keystream(&mut header);
        let mac = self.egress_mac.compute_header_mac(&header);
        // zero-fill to 16-byte boundary
        let mut len = frame_data.len();
        if len % 16 > 0 {
            len = (len / 16 + 1) * 16;
        }

        let mut frame = Vec::with_capacity(32 + len + 16);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(mac.as_bytes());

        // the header is 32b long, mac is 16
        frame.resize(32 + len + 16, 0);

        let frame_ciphertext_slice = &mut frame[32..32 + len];
        frame_ciphertext_slice[..frame_data.len()].copy_from_slice(frame_data);
        self.egress_aes.apply_keystream(frame_ciphertext_slice);
        let mac = self.egress_mac.compute_frame_mac(frame_ciphertext_slice);
        frame[32 + len..].copy_from_slice(mac.as_bytes());

        frame
    }
}

struct AuthSecrets {
    static_shared_secret: H256,
    ephemeral_key: H256,
    shared_secret: H256,
    mac_secret: H256,
    aes_secret: H256,
}

pub async fn initiate(recipient_pubkey: PublicKey) -> Result<()> {
    let mut stream = TcpStream::connect("0.0.0.0:30303").await?;

    // (should be) Persistent identity
    let identity = PersistentKeys::new();

    // Ephemeral keyset
    let ephemeral_privkey = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let ephemeral_pubkey = secp256k1::PublicKey::from_secret_key(SECP256K1, &ephemeral_privkey);
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

    let (secrets, ack_body, ack_bytes) = receive_auth_ack(
        &mut stream,
        &identity,
        ephemeral_privkey,
        recipient_pubkey,
        initiator_nonce,
    )
    .await?;

    let mut state = P2PState::new(
        secrets,
        initiator_nonce,
        H256::from_slice(&ack_body.recipient_nonce),
        &auth_bytes,
        &ack_bytes,
    );

    let mut hello_message_bytes = Vec::new();
    HelloMessage {
        protocol_version: 5,
        // human-readable client id
        client_id: "mtizim takehome assignment".to_owned(),
        // let's pretend to be capable of something
        // otherwise we can get instantly disconnected as an useless peer
        capabilities: vec![Capability {
            name: "eth".to_string(),
            version: 68,
        }],
        // legacy
        listen_port: 42,
        node_key: identity.public.serialize_uncompressed()[1..65]
            .try_into()
            .expect("65 - 1 == 64"),
    }
    .encode(&mut hello_message_bytes);
    let data = state.compute_frame(
        &[
            alloy_rlp::encode(0u8).as_slice(),
            hello_message_bytes.as_slice(),
        ]
        .concat(),
    );

    stream.write_all(&data).await?;
    stream.flush().await?;
    Ok(())
}
#[derive(RlpDecodable)]
struct AuthAckBody {
    recipient_ephemeral_pubk: [u8; 64],
    recipient_nonce: [u8; 32],
    #[allow(unused)]
    ack_vsn: u8,
}

#[derive(RlpEncodable, RlpDecodable)]
struct HelloMessage {
    protocol_version: u8,
    client_id: String,
    capabilities: Vec<Capability>,
    listen_port: u8,
    node_key: [u8; 64],
}

#[derive(RlpEncodable, RlpDecodable)]
struct Capability {
    name: String,
    version: usize,
}

async fn receive_auth_ack(
    stream: &mut TcpStream,
    identity: &PersistentKeys,
    ephemeral_privkey: SecretKey,
    recipient_pubkey: PublicKey,
    initiator_nonce: H256,
) -> Result<(AuthSecrets, AuthAckBody, Vec<u8>)> {
    let buf = &mut [0u8; 512];
    let bytes_read = stream.read(buf).await.unwrap();
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
    #[derive(RlpEncodable)]
    struct Body<'a> {
        sig: &'a [u8; 65],
        initiator_pubk: &'a [u8; 64],
        initiator_nonce: &'a [u8; 32],
        auth_vsn: u8,
    }
    let mut auth_body = Vec::with_capacity(65 + 64 + 32 + 1 + 8);
    Body {
        sig: &sig_bytes,
        initiator_pubk: &initiator_pubkey.serialize_uncompressed()[1..]
            .try_into()
            .expect("65 - 1 == 64"),
        initiator_nonce: initiator_nonce.as_fixed_bytes(),
        auth_vsn: AUTH_VSN,
    }
    .encode(&mut auth_body);
    let message = [auth_body.as_slice(), AUTH_PADDING.as_bytes()].concat();
    let auth_message = ecies_encrypt_message(&recipient_pubkey, message)?;
    stream.write_all(&auth_message).await?;
    stream.flush().await?;
    Ok(auth_message)
}
