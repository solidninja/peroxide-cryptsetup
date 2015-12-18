use ykpers_rs::{Yubikey, YubikeyDevice, ChallengeResponse, ChallengeResponseParams, SHA1_RESPONSE_LENGTH, SHA1_BLOCK_LENGTH};
use uuid::Uuid;

use model::{YubikeySlot, YubikeyEntryType};
use context::{MainContext, YubikeyInput, Error, Result, PasswordInput};
use io::KeyWrapper;
use io::yubikey;


pub trait AcquireYubikey where Self::Device: Yubikey + ChallengeResponse + Sized {
    type Device;

    fn acquire_device() -> Result<Self::Device>;
}

impl AcquireYubikey for MainContext {
    type Device = YubikeyDevice;
    fn acquire_device() -> Result<Self::Device> {
        YubikeyDevice::new().map_err(|err| Error::YubikeyError { message: format!("Failed to get Yubikey device: {:?}", err) })
    }
}


impl<T> YubikeyInput for T where T: PasswordInput + AcquireYubikey
{
    fn read_yubikey(&self, name: Option<&str>, uuid: &Uuid, slot: YubikeySlot, entry_type: YubikeyEntryType) -> Result<KeyWrapper> {
        let mut dev = try!(Self::acquire_device());
        let challenge = try!(self.read_password(&challenge_prompt(name)));
        match entry_type {
            YubikeyEntryType::ChallengeResponse => read_challenge_response(&mut dev, slot, challenge.as_slice()).map(|k| yubikey::wrap(&k)),
            YubikeyEntryType::HybridChallengeResponse => {
                let other_passphrase = try!(self.read_password("Please enter the other passphrase: "));
                read_hybrid_challenge_response(&mut dev,
                                               slot,
                                               challenge.as_slice(),
                                               other_passphrase.as_slice(),
                                               uuid)
            }
        }
    }
}

fn challenge_prompt(maybe_name: Option<&str>) -> String {
    if let Some(name) = maybe_name {
        format!("Please enter challenge passphrase for {}: ", name)
    } else {
        format!("Please enter new challenge passphrase: ")
    }
}

fn read_challenge_response<Dev: ChallengeResponse>(dev: &mut Dev,
                                                   slot: YubikeySlot,
                                                   challenge: &[u8])
                                                   -> Result<[u8; SHA1_RESPONSE_LENGTH]> {
    let params = ChallengeResponseParams {
        slot: slot,
        is_hmac: true,
    };
    println!("Please interact with the Yubikey now...");
    let mut response = [0u8; SHA1_BLOCK_LENGTH];
    dev.challenge_response(params, &challenge, &mut response)
       .map(|_| {
           // FIXME: wait until copy_memory or similar is stable
           let mut fix_response = [0u8; SHA1_RESPONSE_LENGTH];
           {
               for (i, b) in response.iter().take(SHA1_RESPONSE_LENGTH).enumerate() {
                   fix_response[i] = *b;
               }
           }
           fix_response
       })
       .map_err(|err| Error::YubikeyError { message: format!("Failed Yubikey challenge-response: {:?}", err) })
}

#[cfg(not(feature = "yubikey_hybrid"))]
fn read_hybrid_challenge_response<Dev>(dev: &mut Dev,
                                       slot: YubikeySlot,
                                       challenge: &[u8],
                                       other_passphrase: &[u8],
                                       uuid: &Uuid)
                                       -> Result<KeyWrapper> {
    Err(Error::FeatureNotAvailable)
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use ykpers_rs::{ChallengeResponse, ChallengeResponseParams, SHA1_BLOCK_LENGTH, Result};
    use expectest::prelude::*;

    use model::YubikeySlot;

    pub struct MockChallengeResponse<'a> {
        responses: HashMap<(YubikeySlot, &'a [u8]), Result<&'a [u8; SHA1_BLOCK_LENGTH]>>,
    }

    impl<'a> ChallengeResponse for MockChallengeResponse<'a> {
        fn challenge_response(&mut self,
                              params: ChallengeResponseParams,
                              challenge: &[u8],
                              response: &mut [u8; SHA1_BLOCK_LENGTH])
                              -> Result<()> {
            assert!(params.is_hmac);
            self.responses
                .get(&(params.slot, challenge))
                .unwrap_or_else(|| {
                    panic!("Nothing found for slot: {:?}, challenge {:?}",
                           params.slot,
                           challenge)
                })
                .map(|got_bytes| {
                    // oh my, clone_from() is only implemented for arrays up to size 32
                    for (i, b) in got_bytes.iter().enumerate() {
                        response[i] = *b;
                    }
                    ()
                })
        }
    }

    impl<'a> MockChallengeResponse<'a> {
        pub fn new(slot: YubikeySlot, challenge: &'a [u8], response: &'a [u8; SHA1_BLOCK_LENGTH]) -> MockChallengeResponse<'a> {
            let mut map = HashMap::new();
            map.insert((slot, challenge), Ok(response));
            MockChallengeResponse { responses: map }
        }
    }

    #[test]
    fn test_sanity() {
        let params = ChallengeResponseParams {
            is_hmac: true,
            slot: 1,
        };
        let challenge = b"hello world";
        let response = [42u8; SHA1_BLOCK_LENGTH];
        let mut got_response = [0u8; SHA1_BLOCK_LENGTH];
        let mut mock = MockChallengeResponse::new(1, &challenge[..], &response);
        mock.challenge_response(params, &challenge[..], &mut got_response).unwrap();
        expect!(&got_response[..]).to(be_equal_to(&response[..]));
    }

}

#[cfg(feature = "yubikey_hybrid")]
mod hybrid {
    use ykpers_rs::{ChallengeResponse, SHA1_RESPONSE_LENGTH, SHA1_BLOCK_LENGTH};
    use sodiumoxide;
    use sodiumoxide::crypto::auth::hmacsha512;
    use sodiumoxide::crypto::hash::sha256;
    use sodiumoxide::crypto::pwhash::scryptsalsa208sha256;
    use uuid::Uuid;

    use model::YubikeySlot;
    use context::{Error, Result};
    use io::KeyWrapper;
    use io::yubikey;
    use super::read_challenge_response;

    // taken from crypto_pwhash_scrypt208sha256
    const PWHASH_OPSLIMIT: usize = 33554432;
    const PWHASH_MEMLIMIT: usize = 1073741824;

    fn salt_from_uuid(uuid: &Uuid) -> scryptsalsa208sha256::Salt {
        let sha256::Digest(bytes) = sha256::hash(uuid.as_bytes());
        scryptsalsa208sha256::Salt(bytes)
    }

    fn derive_challenge_key(challenge: &[u8], uuid: &Uuid) -> Result<[u8; SHA1_BLOCK_LENGTH]> {
        let mut derived_key = [0u8; SHA1_BLOCK_LENGTH];
        let salt = salt_from_uuid(uuid);
        try!{
            scryptsalsa208sha256::derive_key(&mut derived_key,
                                             challenge,
                                             &salt,
                                             scryptsalsa208sha256::OpsLimit(PWHASH_OPSLIMIT),
                                             scryptsalsa208sha256::MemLimit(PWHASH_MEMLIMIT))
                .map_err(|_| Error::UnknownCryptoError)
                .map(|_| ())
        }
        Ok(derived_key)
    }

    fn hash_challenge_and_then_response<Dev: ChallengeResponse>(dev: &mut Dev,
                                                                slot: YubikeySlot,
                                                                challenge: &[u8],
                                                                uuid: &Uuid)
                                                                -> Result<[u8; SHA1_RESPONSE_LENGTH]> {
        let derived_key = try!(derive_challenge_key(challenge, uuid));
        read_challenge_response(dev, slot, &derived_key)
    }

    pub fn read_hybrid_challenge_response<Dev: ChallengeResponse>(dev: &mut Dev,
                                                                  slot: YubikeySlot,
                                                                  challenge: &[u8],
                                                                  other_passphrase: &[u8],
                                                                  uuid: &Uuid)
                                                                  -> Result<KeyWrapper> {
        // TODO: explain in more detail the reasoning behind home-brewed crypto...
        sodiumoxide::init();

        let response = try!(hash_challenge_and_then_response(dev, slot, challenge, uuid));
        let sha256::Digest(response_hash) = sha256::hash(&response);
        let auth_key = hmacsha512::Key(response_hash);
        let hmacsha512::Tag(final_key) = hmacsha512::authenticate(other_passphrase, &auth_key);
        Ok(yubikey::wrap(&final_key))
    }

    #[cfg(test)]
    mod tests {
        use uuid::Uuid;
        use expectest::prelude::*;

        use yubikey::tests::MockChallengeResponse;
        use super::read_hybrid_challenge_response;

        #[test]
        fn test_hybrid_key_derivation() {
            // Yubikey HMAC-SHA1 secret key 0x505249202a20485454502f322e300d0a0d0a534d
            let challenge = b"egotistical giraffe";
            let other = b"happy dance";
            let uuid = Uuid::parse_str("c01f4eb5-71a0-4ad8-b054-d72d2b2e5389").unwrap();

            let yubi_challenge = [71, 30, 203, 181, 69, 116, 116, 197, 82, 54, 31, 101, 81, 166, 142, 96, 218, 198, 60, 200, 241, 8, 244,
                                  243, 157, 56, 215, 35, 198, 153, 179, 44, 19, 253, 135, 159, 180, 55, 87, 201, 67, 20, 119, 49, 203,
                                  158, 73, 186, 141, 25, 223, 232, 103, 90, 93, 4, 159, 156, 81, 6, 212, 26, 242, 78];
            let yubi_response = [220, 239, 146, 171, 222, 13, 140, 7, 244, 155, 110, 202, 199, 189, 151, 152, 114, 106, 233, 82, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0];

            let mut yubikey = MockChallengeResponse::new(2, &yubi_challenge[..], &yubi_response);
            let result = read_hybrid_challenge_response(&mut yubikey, 2, challenge, other, &uuid);

            let expected_key = [226, 239, 138, 225, 242, 69, 238, 111, 116, 184, 69, 119, 126, 11, 228, 13, 14, 64, 93, 208, 190, 68, 3,
                                59, 37, 233, 10, 210, 4, 168, 51, 21, 88, 30, 22, 86, 74, 0, 55, 52, 36, 166, 75, 14, 156, 162, 47, 140,
                                242, 163, 58, 211, 34, 12, 250, 23, 152, 94, 172, 124, 66, 58, 76, 249];
            expect!(result.as_ref().map(|k| k.as_slice())).to(be_ok().value(&expected_key[..]));

        }
    }

}

#[cfg(feature = "yubikey_hybrid")]
use yubikey::hybrid::read_hybrid_challenge_response;
