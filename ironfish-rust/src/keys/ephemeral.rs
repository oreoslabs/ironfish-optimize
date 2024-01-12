/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
use ff::Field;
use ironfish_zkp::constants::PUBLIC_KEY_GENERATOR;
use jubjub::SubgroupPoint;
use rand::thread_rng;

/// Diffie Hellman key exchange pair as used in note encryption.
///
/// This can be used according to the protocol described in
/// [`crate::keys::shared_secret`]
#[derive(Default)]
pub struct EphemeralKeyPair {
    secret: jubjub::Fr,
    public: jubjub::SubgroupPoint,
}

impl EphemeralKeyPair {
    pub fn new() -> Self {
        let secret = jubjub::Fr::random(thread_rng());

        Self {
            secret,
            public: *PUBLIC_KEY_GENERATOR * secret,
        }
    }

    pub fn secret(&self) -> &jubjub::Fr {
        &self.secret
    }

    pub fn public(&self) -> &jubjub::SubgroupPoint {
        &self.public
    }

    pub fn to_bytes_le(&self) -> Vec<u8> {
        let mut res = vec![];
        res.extend(self.secret.to_bytes());
        res.extend(self.public.to_bytes_le());
        res
    }

    pub fn from_bytes_le(bytes: Vec<u8>) -> Self {
        let secret_bytes: &[u8; 32] = bytes[0..32].try_into().unwrap();
        let public_bytes: &[u8; 160] = bytes[32..192].try_into().unwrap();
        let secret = jubjub::Fr::from_bytes(secret_bytes).unwrap();
        let public = SubgroupPoint::from_bytes_le(public_bytes);
        Self { secret, public }
    }
}

#[cfg(test)]
mod test {
    use ironfish_zkp::constants::PUBLIC_KEY_GENERATOR;

    use super::EphemeralKeyPair;

    #[test]
    fn test_ephemeral_key_pair() {
        let key_pair = EphemeralKeyPair::new();

        assert_eq!(
            *key_pair.public(),
            *PUBLIC_KEY_GENERATOR * key_pair.secret()
        );

        assert_eq!(key_pair.public(), &key_pair.public);
        assert_eq!(key_pair.secret(), &key_pair.secret);
    }
}
