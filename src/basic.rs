// A bucket of things from https://github.com/ethereum/devp2p/blob/master/rlpx.md#Notation

use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128, Aes256, Aes256Enc,
};
use cipher::{block_padding::NoPadding, BlockEncrypt, KeyInit};
use ethereum_types::{H128, H256};
use sha2::Digest;

pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut x = x.to_vec();
    xor_in_place(&mut x, y);
    x
}

pub fn xor_in_place(x: &mut [u8], y: &[u8]) {
    for (&mut ref mut xb, yb) in x.iter_mut().zip(y) {
        *xb ^= yb;
    }
}

pub fn keccak256(data: Vec<u8>) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.into()
}

// Single block aes256
pub fn aes256_16(k: &H256, m: H128) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(m.as_bytes());
    let encryptor = Aes256Enc::new_from_slice(k.as_bytes()).expect("32 is valid length");
    encryptor
        .encrypt_padded::<NoPadding>(&mut data, 16)
        .expect("H128 is 16b");
    data.to_vec()
}

pub fn aes128(k: &H128, iv: &H128, m: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(m);
    // Aes128 in CTR mode
    let mut encryptor =
        <ctr::Ctr64BE<Aes128> as KeyIvInit>::new(k.as_ref().into(), iv.as_ref().into());
    encryptor.apply_keystream(&mut data);
    data.to_vec()
}
