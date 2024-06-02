use ethereum_types::{H128, H256};
use sha2::Digest;
use sha3::Keccak256;

use crate::basic::{aes256_16, xor};

#[derive(Debug)]
pub struct MacState {
    secret: H256,
    hasher: Keccak256,
}

impl MacState {
    pub fn new(secret: H256) -> Self {
        Self {
            secret,
            hasher: sha3::Keccak256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn digest(&self) -> H128 {
        H128::from_slice(&self.hasher.clone().finalize()[..16])
    }

    pub fn compute_header_mac(&mut self, header_ciphertext: &[u8]) -> H128 {
        let a = self.digest();
        let aes256 = aes256_16(&self.secret, a);
        let header_mac_seed = &xor(&aes256, header_ciphertext);

        self.update(header_mac_seed);
        self.digest()
    }

    pub fn compute_body_mac(&mut self, frame_ciphertext: &[u8]) -> H128 {
        self.update(frame_ciphertext);
        let dig_1 = self.digest();
        let frame_mac_seed = &xor(&aes256_16(&self.secret, self.digest()), dig_1.as_bytes());

        self.update(frame_mac_seed);
        self.digest()
    }
}
