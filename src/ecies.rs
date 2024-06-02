use crate::basic::aes128;
use crate::{Error, Result};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use secp256k1::SECP256K1;
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

// The short names here follow the spec, for easier comparison
// Also prepends message size
pub fn ecies_encrypt_message(
    // Kb in spec
    pubkey: &secp256k1::PublicKey,
    // m in spec
    mut message: Vec<u8>,
) -> Result<Vec<u8>> {
    let r = SecretKey::new(&mut rand::thread_rng());
    // R in spec
    let rbig = &PublicKey::from_secret_key(SECP256K1, &r).serialize_uncompressed();
    let s = ecdh(&r, pubkey);
    let (ke, km) = kdf(&s)?;
    let mut iv = H128::zero();
    iv.randomize_using(&mut rand::thread_rng());
    let c = aes128(&ke, &iv, message.as_mut_slice());
    // R + iv + c + d
    let auth_size: u16 = (65 + 16 + c.len() + 32).try_into()?;
    let mut message_out: Vec<u8> = Vec::with_capacity(2 + auth_size as usize);
    let d = mac(&km, &iv, &c, auth_size);

    let privkey = "3369544a527fda55948730b467d47ecfd98bbe99ce1bb795d8bc0dd5c0ca85b0"
        .parse::<SecretKey>()
        .unwrap();

    let recipient_pubkey = secp256k1::PublicKey::from_secret_key(SECP256K1, &privkey);

    message_out.extend(&auth_size.to_be_bytes());
    message_out.extend(rbig);
    message_out.extend(iv.as_bytes());
    message_out.extend(c);
    message_out.extend(d.as_bytes());
    Ok(message_out)
}

pub fn ecies_decrypt_message(
    // kb in spec
    privkey: &secp256k1::SecretKey,
    // m in spec
    message: &[u8],
) -> Result<Vec<u8>> {
    if message.len() < 2 {
        return Err(Error::NotEnoughData());
    }
    let auth_size = u16::from_be_bytes([message[0], message[1]]);
    let message_body = &message[2..];
    #[allow(clippy::identity_op)]
    if (message_body.len() < auth_size.into()) || message_body.len() < (65 + 16 + 0 + 32) {
        return Err(Error::NotEnoughData());
    }

    let (rbig, rest) = message_body.split_at(65);
    let (iv, rest) = rest.split_at(16);
    let (c, d) = rest.split_at(auth_size as usize - (65 + 16 + 32));

    let rbig = PublicKey::from_slice(rbig).map_err(|_| Error::EciesParsingError())?;
    let iv = H128::from_slice(iv);
    let s = ecdh(privkey, &rbig);
    let (ke, km) = kdf(&s)?;

    // Verify authenticity
    let d = H256::from_slice(&d[..32]);
    let dprim = mac(&km, &iv, c, auth_size);
    if d != dprim {
        return Err(Error::TagMismatch());
    }

    let m = aes128(&ke, &iv, c);

    Ok(m)
}

pub fn ecdh(private_key: &SecretKey, public_key: &PublicKey) -> H256 {
    H256::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, private_key)[..32])
}

// The spec always uses KDF(_,32), so this is not parametrized
// NIST SP 800-56 Concatenation KDF
fn kdf(k: &H256) -> Result<(H128, H256)> {
    let mut key = [0_u8; 32];
    concat_kdf::derive_key_into::<sha2::Sha256>(k.as_bytes(), &[], &mut key)?;

    let ke = H128::from_slice(&key[..16]);
    let km = H256::from(sha2::Sha256::digest(&key[16..32]).as_ref());

    Ok((ke, km))
}

// spec has MAC(k,m), but m is always iv || c, so let's split them
// also authdata is not specified as a parameter, but is also used, and is always :=len(auth-size)
// k is always used with sha256
// so MAC(sha256(k),iv || c) becomes this
fn mac(k: &H256, iv: &H128, c: &[u8], auth_size: u16) -> H256 {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(k.as_ref()).expect("HMAC can take key of any size");
    hmac.update(iv.as_bytes());
    hmac.update(c);
    let authdata = auth_size.to_be_bytes();
    hmac.update(&authdata);

    H256::from_slice(&hmac.finalize().into_bytes())
}
