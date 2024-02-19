/// Undefines a variable by shadowing it with unit.
/// It also asserts that the variable actually exists.
/// Does not drop the variable.
macro_rules! undefine_variable {
    ($name:ident) => {
        #[allow(unused_variables, unused_must_use)]
        let $name: () = {
            &$name;
        };
    };
}
use std::{fmt::{Debug, Display}, str::FromStr};

pub(crate) use undefine_variable;

#[derive(PartialEq, Eq)]
pub struct Fingerprint<const LEN_BYTES: usize>(pub [u8; LEN_BYTES]);

const HEX: [u8; 16] = *b"0123456789abcdef";

impl<const LEN_BYTES: usize> Default for Fingerprint<LEN_BYTES> {
    fn default() -> Self {
        Self([0; LEN_BYTES])
    }
}

impl<const LEN_BYTES: usize> FromStr for Fingerprint<LEN_BYTES> {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != (LEN_BYTES * 2) {
            return Err("invalid length");
        }
        if s.bytes().any(|b| !HEX.contains(&b)) {
            return Err("invalid digit");
        }

        let mut arr = [0; LEN_BYTES];
        s.as_bytes().chunks(2).enumerate().for_each(|(i, byte)| {
            arr[i] = (((HEX.iter().position(|b| *b == byte[0]).unwrap()) << 4)
                + (HEX.iter().position(|b| *b == byte[1]).unwrap())) as u8;
        });
        Ok(Self(arr))
    }
}

impl<const LEN_BYTES: usize> Display for Fingerprint<LEN_BYTES> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<const LEN_BYTES: usize> Debug for Fingerprint<LEN_BYTES> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}
