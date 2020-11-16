use std::convert::From;

use uuid::Uuid;
use ykpers_rs::{
    ChallengeResponse, ChallengeResponseParams, Error as YubikeyError, Yubikey, YubikeyDevice, SHA1_BLOCK_LENGTH,
    SHA1_RESPONSE_LENGTH,
};

use crate::db::{YubikeyEntryType, YubikeySlot};
use crate::input::{Error, InputName, KeyInput, Result, SecStr};

/// Parameters for Yubikey input
pub struct YubikeyPrompt {
    /// Entry type (vanilla challenge-response or hybrid)
    pub entry_type: YubikeyEntryType,
    /// Key input mechanism for the challenge passphrase (and 'other' passphrase if hybrid)
    pub passphrase_input: Box<dyn KeyInput>,
    /// Slot of Yubikey
    pub slot: YubikeySlot,
    /// UUID of the key entry (used as a salt for hybrid)
    pub uuid: Uuid,
}

impl KeyInput for YubikeyPrompt {
    fn get_key(&self, name: &InputName, is_new: bool) -> Result<SecStr> {
        let mut dev = get_yubikey_device()?;
        let suffix = if is_new {
            format!("new disk {}:", name.name)
        } else {
            format!("disk {} (uuid={}):", name.name, self.uuid)
        };
        let chal_name = InputName::with_override("challenge".to_string(), format!("Challenge for {}", suffix));
        let other_name =
            InputName::with_override("other_hybrid".to_string(), format!("Other passphrase for {}", suffix));

        let chal_key = self.passphrase_input.get_key(&chal_name, is_new)?;
        match self.entry_type {
            YubikeyEntryType::ChallengeResponse => read_challenge_response(&mut dev, self.slot, &chal_key),
            YubikeyEntryType::HybridChallengeResponse => {
                let other_key = self.passphrase_input.get_key(&other_name, is_new)?;
                read_hybrid_challenge_response(&mut dev, self.slot, &chal_key, &other_key, &self.uuid)
            }
        }
    }
}

impl From<YubikeyError> for Error {
    fn from(e: YubikeyError) -> Self {
        Error::YubikeyError(e)
    }
}

fn get_yubikey_device() -> Result<YubikeyDevice> {
    let dev = YubikeyDevice::new()?;
    Ok(dev)
}

fn read_challenge_response<Dev: ChallengeResponse>(
    dev: &mut Dev,
    slot: YubikeySlot,
    challenge: &SecStr,
) -> Result<SecStr> {
    let params = ChallengeResponseParams { slot, is_hmac: true };
    println!("Please interact with the Yubikey now...");
    let mut response = [0u8; SHA1_BLOCK_LENGTH];
    dev.challenge_response(params, challenge.unsecure(), &mut response)?;
    let key = SecStr::new(response[0..SHA1_RESPONSE_LENGTH].to_vec());
    for b in response.iter_mut() {
        *b = 0u8;
    }
    Ok(key)
}

#[cfg(not(feature = "yubikey_hybrid"))]
fn read_hybrid_challenge_response<Dev>(
    dev: &mut Dev,
    slot: YubikeySlot,
    challenge: &SecStr,
    other_passphrase: &SecStr,
    uuid: &Uuid,
) -> Result<SecStr> {
    Err(Error::FeatureNotAvailable)
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use expectest::prelude::*;
    use ykpers_rs::{ChallengeResponse, ChallengeResponseParams, Result, SHA1_BLOCK_LENGTH};

    use crate::db::YubikeySlot;

    pub struct MockChallengeResponse<'a> {
        responses: HashMap<(YubikeySlot, &'a [u8]), Result<&'a [u8; SHA1_BLOCK_LENGTH]>>,
    }

    impl<'a> ChallengeResponse for MockChallengeResponse<'a> {
        fn challenge_response(
            &mut self,
            params: ChallengeResponseParams,
            challenge: &[u8],
            response: &mut [u8; SHA1_BLOCK_LENGTH],
        ) -> Result<()> {
            assert!(params.is_hmac);
            self.responses
                .get(&(params.slot, challenge))
                .unwrap_or_else(|| panic!("Nothing found for slot: {:?}, challenge {:?}", params.slot, challenge))
                .map(|got_bytes| response.clone_from(got_bytes))
        }
    }

    impl<'a> MockChallengeResponse<'a> {
        pub fn new(
            slot: YubikeySlot,
            challenge: &'a [u8],
            response: &'a [u8; SHA1_BLOCK_LENGTH],
        ) -> MockChallengeResponse<'a> {
            let mut map = HashMap::new();
            map.insert((slot, challenge), Ok(response));
            MockChallengeResponse { responses: map }
        }
    }

    #[test]
    fn test_sanity() {
        let params = ChallengeResponseParams { is_hmac: true, slot: 1 };
        let challenge = b"hello world";
        let response = [42u8; SHA1_BLOCK_LENGTH];
        let mut got_response = [0u8; SHA1_BLOCK_LENGTH];
        let mut mock = MockChallengeResponse::new(1, &challenge[..], &response);
        mock.challenge_response(params, &challenge[..], &mut got_response)
            .unwrap();
        expect!(&got_response[..]).to(be_equal_to(&response[..]));
    }
}

#[cfg(feature = "yubikey_hybrid")]
mod hybrid {
    use sodiumoxide;
    use sodiumoxide::crypto::auth::hmacsha512;
    use sodiumoxide::crypto::hash::sha256;
    use sodiumoxide::crypto::pwhash::scryptsalsa208sha256;
    use uuid::Uuid;
    use ykpers_rs::{ChallengeResponse, SHA1_BLOCK_LENGTH};

    use super::read_challenge_response;
    use crate::db::YubikeySlot;

    use crate::input::{Error, Result};

    use super::SecStr;

    // taken from crypto_pwhash_scrypt208sha256
    const PWHASH_OPSLIMIT: usize = 33554432;
    const PWHASH_MEMLIMIT: usize = 1073741824;

    fn salt_from_uuid(uuid: &Uuid) -> scryptsalsa208sha256::Salt {
        let sha256::Digest(bytes) = sha256::hash(uuid.as_bytes());
        scryptsalsa208sha256::Salt(bytes)
    }

    fn derive_challenge_key(challenge: &SecStr, uuid: &Uuid) -> Result<SecStr> {
        let mut derived_key = vec![0u8; SHA1_BLOCK_LENGTH];
        let salt = salt_from_uuid(uuid);
        let _ = scryptsalsa208sha256::derive_key(
            &mut derived_key,
            challenge.unsecure(),
            &salt,
            scryptsalsa208sha256::OpsLimit(PWHASH_OPSLIMIT),
            scryptsalsa208sha256::MemLimit(PWHASH_MEMLIMIT),
        )
        .map_err(|_| Error::UnknownCryptoError)?;
        Ok(SecStr::new(derived_key))
    }

    fn hash_challenge_and_then_response<Dev: ChallengeResponse>(
        dev: &mut Dev,
        slot: YubikeySlot,
        chal: &SecStr,
        uuid: &Uuid,
    ) -> Result<SecStr> {
        let derived_key = derive_challenge_key(chal, uuid)?;
        let resp = read_challenge_response(dev, slot, &derived_key)?;
        Ok(resp)
    }

    pub fn read_hybrid_challenge_response<Dev: ChallengeResponse>(
        dev: &mut Dev,
        slot: YubikeySlot,
        chal: &SecStr,
        other_passphrase: &SecStr,
        uuid: &Uuid,
    ) -> Result<SecStr> {
        // TODO: explain in more detail the reasoning behind home-brewed crypto...
        sodiumoxide::init().expect("libsodium to be initialised");

        let response = hash_challenge_and_then_response(dev, slot, chal, uuid)?;
        let sha256::Digest(response_hash) = sha256::hash(&response.unsecure());
        let auth_key = hmacsha512::Key(response_hash);
        let hmacsha512::Tag(final_key) = hmacsha512::authenticate(other_passphrase.unsecure(), &auth_key);
        Ok(SecStr::new(final_key.to_vec()))
    }

    #[cfg(test)]
    mod tests {
        use expectest::prelude::*;
        use uuid::Uuid;

        use super::super::tests::MockChallengeResponse;
        use super::read_hybrid_challenge_response;
        use secstr::SecStr;

        #[test]
        fn test_hybrid_key_derivation() {
            // Yubikey HMAC-SHA1 secret key 0x505249202a20485454502f322e300d0a0d0a534d
            let challenge = b"egotistical giraffe";
            let other = b"happy dance";
            let uuid = Uuid::parse_str("c01f4eb5-71a0-4ad8-b054-d72d2b2e5389").unwrap();

            let yubi_challenge = [
                71, 30, 203, 181, 69, 116, 116, 197, 82, 54, 31, 101, 81, 166, 142, 96, 218, 198, 60, 200, 241, 8, 244,
                243, 157, 56, 215, 35, 198, 153, 179, 44, 19, 253, 135, 159, 180, 55, 87, 201, 67, 20, 119, 49, 203,
                158, 73, 186, 141, 25, 223, 232, 103, 90, 93, 4, 159, 156, 81, 6, 212, 26, 242, 78,
            ];
            let yubi_response = [
                220, 239, 146, 171, 222, 13, 140, 7, 244, 155, 110, 202, 199, 189, 151, 152, 114, 106, 233, 82, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ];

            let mut yubikey = MockChallengeResponse::new(2, &yubi_challenge[..], &yubi_response);
            let result = read_hybrid_challenge_response(
                &mut yubikey,
                2,
                &SecStr::new(challenge.to_vec()),
                &SecStr::new(other.to_vec()),
                &uuid,
            );

            let expected_key = [
                226, 239, 138, 225, 242, 69, 238, 111, 116, 184, 69, 119, 126, 11, 228, 13, 14, 64, 93, 208, 190, 68,
                3, 59, 37, 233, 10, 210, 4, 168, 51, 21, 88, 30, 22, 86, 74, 0, 55, 52, 36, 166, 75, 14, 156, 162, 47,
                140, 242, 163, 58, 211, 34, 12, 250, 23, 152, 94, 172, 124, 66, 58, 76, 249,
            ];
            expect!(result.as_ref().map(|k| k.unsecure())).to(be_ok().value(&expected_key[..]));
        }
    }
}

#[cfg(feature = "yubikey_hybrid")]
use self::hybrid::read_hybrid_challenge_response;
