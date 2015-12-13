use ykpers_rs::{YubikeyDevice, ChallengeResponseParams};

use model::{YubikeySlot, YubikeyEntryType};
use context::{MainContext, YubikeyInput, Error, Result, PasswordInput};
use io::KeyWrapper;
use io::yubikey;

impl YubikeyInput for MainContext {
    fn read_yubikey(&self, name: Option<&str>, slot: YubikeySlot, entry_type: YubikeyEntryType) -> Result<KeyWrapper> {
        let mut dev = try!(acquire_device());
        let challenge = try!(self.read_password(&challenge_prompt(name)));
        match entry_type {
            YubikeyEntryType::ChallengeResponse => read_challenge_response(&mut dev, slot, challenge),
            _ => unimplemented!(),
        }
    }
}

fn challenge_prompt(maybe_name: Option<&str>) -> String {
    if let Some(name) = maybe_name {
        format!("Please enter challenge passphrase for '{}':", name)
    } else {
        format!("Please enter new challenge passphrase:")
    }
}

fn acquire_device() -> Result<YubikeyDevice> {
    YubikeyDevice::new().map_err(|err| Error::YubikeyError { message: format!("Failed to get Yubikey device: {:?}", err) })
}

fn read_challenge_response(dev: &mut YubikeyDevice, slot: YubikeySlot, challenge: KeyWrapper) -> Result<KeyWrapper> {
    let params = ChallengeResponseParams {
        slot: slot,
        is_hmac: true,
    };
    yubikey::challenge_response(dev, params, &challenge)
        .map_err(|err| Error::YubikeyError { message: format!("Failed Yubikey challenge-response: {:?}", err) })
}
