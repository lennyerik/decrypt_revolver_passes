use core::str;

use base64::prelude::*;

const KEY: &str = "2pAuzgX9Ns";

fn decrypt(data: &[u8], password: &[u8], offset: u64) -> Vec<u8> {
    let mut ret = vec![0; data.len()];

    for pass_byte in password {
        let mut j = 1;
        while j < data.len() {
            #[allow(clippy::cast_possible_truncation)]
            let j_byte = j as u8;

            #[allow(clippy::cast_possible_truncation)]
            let offset_byte = offset as u8;

            ret[j - 1] = data[j - 1].wrapping_sub(*pass_byte).wrapping_sub(offset_byte.wrapping_add(j_byte));

            if j < data.len() {
                let off = (!j_byte).wrapping_sub(offset_byte).wrapping_add(data[j]);
                ret[j] = off.wrapping_add(*pass_byte);
                j += 1;
            }

            if j < data.len() {
                let off = (!j_byte).wrapping_sub(offset_byte).wrapping_add(data[j]);
                ret[j] = off.wrapping_add(password[0]);
                j += 1;
            }

            if j < data.len() {
                let off = (!j_byte).wrapping_sub(offset_byte).wrapping_add(data[j]);
                ret[j] = off.wrapping_add(*pass_byte).wrapping_add(0xfd);
                j += 1;
            }

            j += 1;
        }
    }

    ret
}

fn main() {
    let bytes = BASE64_STANDARD.decode("Ce6cKCYfs08cEA==").unwrap();
    let dec = decrypt(bytes.as_slice(), KEY.as_bytes(), 0);
    let str = str::from_utf8(&dec).unwrap_or("???");
    println!("{dec:?} :: {str}");
}