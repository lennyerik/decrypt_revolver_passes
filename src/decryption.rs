use base64::prelude::*;

const KEY: &str = "2pAuzgX9Ns";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("base64 decode error")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("utf8 decode error")]
    UTF8Decode(#[from] std::string::FromUtf8Error),
}

pub fn eh_decrypt_data(data: &[u8], password: &[u8], offset: u8) -> Vec<u8> {
    let mut ret = data.to_owned();

    for pass_byte in password {
        for (j, data_byte) in ret.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let j = j as u8;

            let off = (!j).wrapping_sub(offset).wrapping_add(*data_byte);
            *data_byte = match j % 4 {
                0 => data_byte
                    .wrapping_sub(*pass_byte)
                    .wrapping_sub(offset.wrapping_add(j + 1)),
                1 => off.wrapping_add(*pass_byte),
                2 => off.wrapping_add(password[0]),
                3 => off.wrapping_add(*pass_byte).wrapping_add(0xfd),
                _ => unreachable!(),
            }
        }
    }

    ret
}

pub fn decrypt_password(passw_b64: &str) -> Result<String, Error> {
    let enc_passw = BASE64_STANDARD.decode(passw_b64)?;
    let passw = eh_decrypt_data(&enc_passw, KEY.as_bytes(), 0);
    Ok(String::from_utf8(passw)?)
}
