use std::time::Duration;

use crate::macstate::MacState;
use aes::Aes256;
use alloy_rlp::Encodable;
use alloy_rlp::RlpDecodable;
use alloy_rlp::RlpEncodable;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use cipher::KeyIvInit;
use cipher::StreamCipher;
use ctr::Ctr64BE;
use ethereum_types::H128;
use ethereum_types::H256;
use secp256k1::PublicKey;
use secp256k1::SecretKey;
use secp256k1::SECP256K1;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;

use crate::basic::xor;
use crate::Error;
use crate::Result;

pub static AUTH_PADDING: &str = "arbitrary data";
pub static AUTH_VSN: u8 = 4;
pub const PROTOCOL_VERSION: u8 = 5;
pub const MAX_MESSAGE_SIZE: u64 = 16 * 1048576;

// header = frame-size || header-data || header-padding
// header-data = [capability-id, context-id]
// capability-id = integer, always zero
// context-id = integer, always zero
// header-padding = zero-fill header to 16-byte boundary
// => header = frame-size || constant-data
// A header just has frame size and constant RLP artifacts
pub const ZERO_HEADER: &[u8; 3] = &[194, 128, 128]; //
pub const SECP256K1_TAG_PUBKEY_UNCOMPRESSED: u8 = 4;

#[derive(Clone)]
pub struct PersistentKeys {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl PersistentKeys {
    pub fn new() -> PersistentKeys {
        let privkey = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let pubkey = secp256k1::PublicKey::from_secret_key(SECP256K1, &privkey);
        PersistentKeys {
            secret: privkey,
            public: pubkey,
        }
    }
}

pub struct P2PState {
    pub secrets: AuthSecrets,
    pub other_pubkey: PublicKey,

    pub egress_mac: MacState,
    pub egress_aes: Ctr64BE<Aes256>,

    pub ingress_mac: MacState,
    pub ingress_aes: Ctr64BE<Aes256>,
}

impl P2PState {
    pub fn new(
        other_pubkey: PublicKey,
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
            other_pubkey,
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

    pub fn decode_frame(&mut self, mut frame_data: Vec<u8>) -> Result<Vec<u8>> {
        let (header_and_mac, rest) = frame_data.split_at_mut(32);
        let (header, header_mac) = header_and_mac.split_at_mut(16);
        let (body, body_mac) = rest.split_at_mut(rest.len() - 16);

        let computed_header_mac = self.ingress_mac.compute_header_mac(header);

        if computed_header_mac.as_bytes() != header_mac {
            return Err(Error::TagMismatch());
        }

        self.ingress_aes.apply_keystream(header);
        let body_size = usize::try_from(BigEndian::read_uint(header, 3))?;

        let computed_body_mac = self.ingress_mac.compute_body_mac(body);
        if computed_body_mac.as_bytes() != body_mac {
            return Err(Error::TagMismatch());
        }

        self.ingress_aes.apply_keystream(body);
        Ok(body[..body_size].to_vec())
    }

    pub fn encode_frame(&mut self, data: &[u8]) -> Vec<u8> {
        // frame size
        // we'd need an u24 for this, but let's just truncate a u64 instead
        let mut buf = [0; 8];
        let n_bytes = 3; // 3 * 8 = 24;
        BigEndian::write_uint(&mut buf, data.len() as u64, n_bytes);
        // header = frame-size || constant-data
        let mut header = [0_u8; 16];
        header[..3].copy_from_slice(&buf[..3]);
        header[3..6].copy_from_slice(ZERO_HEADER);

        // encrypt header, update mac for header
        self.egress_aes.apply_keystream(&mut header);
        let mac = self.egress_mac.compute_header_mac(&header);
        // zero-fill to 16-byte boundary
        let mut len = data.len();
        if len % 16 > 0 {
            len = (len / 16 + 1) * 16;
        }

        let mut frame = Vec::with_capacity(32 + len + 16);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(mac.as_bytes());

        // the header is 32b long, mac is 16
        frame.resize(32 + len + 16, 0);

        let frame_ciphertext_slice = &mut frame[32..32 + len];
        frame_ciphertext_slice[..data.len()].copy_from_slice(data);
        self.egress_aes.apply_keystream(frame_ciphertext_slice);
        let mac = self.egress_mac.compute_body_mac(frame_ciphertext_slice);
        frame[32 + len..].copy_from_slice(mac.as_bytes());

        frame
    }
}

pub struct AuthSecrets {
    pub static_shared_secret: H256,
    pub ephemeral_key: H256,
    pub shared_secret: H256,
    pub mac_secret: H256,
    pub aes_secret: H256,
}

#[derive(RlpEncodable, RlpDecodable)]
pub struct HelloMessage {
    pub protocol_version: u8,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u8,
    pub node_key: [u8; 64],
}

#[derive(RlpEncodable, RlpDecodable)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}
#[derive(RlpDecodable, RlpEncodable)]
pub struct AuthAckBody {
    pub recipient_ephemeral_pubk: [u8; 64],
    pub recipient_nonce: [u8; 32],
    // Spec requires us to ignore it
    #[allow(unused)]
    pub ack_vsn: u8,
}

#[derive(RlpEncodable, RlpDecodable)]
pub struct AuthBody {
    pub sig: [u8; 65],
    pub initiator_pubk: [u8; 64],
    pub initiator_nonce: [u8; 32],
    pub auth_vsn: u8,
}

pub async fn send_hello(
    identity: &PersistentKeys,
    state: &mut P2PState,
    stream: &mut TcpStream,
) -> Result<()> {
    let mut hello_message_bytes = Vec::new();
    HelloMessage {
        protocol_version: PROTOCOL_VERSION,
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
    let data = state.encode_frame(
        &[
            // 0 signifies a hello message
            alloy_rlp::encode(0u8).as_slice(),
            hello_message_bytes.as_slice(),
        ]
        .concat(),
    );
    stream.write_all(&data).await?;
    Ok(())
}

pub async fn receive_hello(p2p_state: &mut P2PState, stream: &mut TcpStream) -> Result<()> {
    let mut frame = Vec::with_capacity(4096);
    let mut handle = stream.take(MAX_MESSAGE_SIZE);
    let mut buf = [0; 1024];
    let mut time = 0;
    loop {
        let bytes_read = handle.read(&mut buf).await?;

        if frame.is_empty() && bytes_read == 0 {
            sleep(Duration::from_millis(20)).await;
            time += 20;
            // Ballpark estimate, I know this it not precise
            // But it also doesn't need to be
            if time > 1000 {
                return Err(Error::Timeout);
            }
            continue;
        }
        frame.extend_from_slice(&buf[..bytes_read]);
        if bytes_read == 0 || bytes_read < 1024 {
            break;
        }
    }
    if frame.len() < 32 + 16 {
        dbg!(frame.len());
        // I'm only handling a happy path handshake here, invalid messages are out of scope
        return Err(Error::OutOfScope);
    }

    let data = p2p_state.decode_frame(frame)?;
    let msg_type = data[0];
    // rlp-encoded 0 coresponds to a hello message
    if msg_type != alloy_rlp::encode(0u8).as_slice()[0] {
        dbg!("or here");
        // I'm only handling a handshake here, other messages are out of scope (including disconnect)
        return Err(Error::OutOfScope);
    }

    Ok(())
}
