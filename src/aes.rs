use crate::types::AesMode;
use std::io;

use byteorder::{LittleEndian, ReadBytesExt};
use hmac::Hmac;
use sha1::Sha1;

/// The length of the password verifcation value in bytes
const PWD_VERIFY_LENGTH: u64 = 2;
/// The length of the authentication code in bytes
const AUTH_CODE_LENGTH: u64 = 10;
/// The number of iterations used with PBKDF2
const ITERATION_COUNT: u32 = 1000;
/// AES block size in bytes
const BLOCK_SIZE: usize = 16;

// an aes encrypted file starts with a salt, whose length depends on the used aes mode
// followed by a 2 byte password verification value
// then the variable length encrypted data
// and lastly a 10 byte authentication code
pub(crate) struct AesReader<R> {
    reader: R,
    aes_mode: AesMode,
    salt_length: usize,
    data_length: u64,
}

impl<R: io::Read> AesReader<R> {
    pub fn new(reader: R, aes_mode: AesMode, compressed_size: u64) -> AesReader<R> {
        let salt_length = aes_mode.salt_length();
        let data_length = compressed_size - (PWD_VERIFY_LENGTH + AUTH_CODE_LENGTH + salt_length);

        Self {
            reader,
            aes_mode,
            salt_length: salt_length as usize,
            data_length,
        }
    }

    pub fn validate(mut self, password: &[u8]) -> Result<Option<AesReaderValid<R>>, io::Error> {
        // the length of the salt depends on the used key size
        let mut salt = vec![0; self.salt_length as usize];
        self.reader.read_exact(&mut salt).unwrap();

        // next are 2 bytes used for password verification
        let mut pwd_verification_value = vec![0; PWD_VERIFY_LENGTH as usize];
        self.reader.read_exact(&mut pwd_verification_value).unwrap();

        // derive a key from the password and salt
        // the length depends on the aes key length
        let derived_key_len = (2 * self.aes_mode.key_length() + PWD_VERIFY_LENGTH) as usize;
        let mut derived_key: Vec<u8> = vec![0; derived_key_len];

        // use PBKDF2 with HMAC-Sha1 to derive the key
        pbkdf2::pbkdf2::<Hmac<Sha1>>(password, &salt, ITERATION_COUNT, &mut derived_key);

        // the last 2 bytes should equal the password verification value
        if pwd_verification_value != &derived_key[derived_key_len - 2..] {
            // wrong password
            return Ok(None);
        }

        // the first key_length bytes are used as decryption key
        let decrypt_key = &derived_key[0..self.aes_mode.key_length() as usize];

        panic!("Validating AesReader");
    }
}

pub(crate) struct AesReaderValid<R> {
    reader: AesReader<R>,
}

impl<R: io::Read> io::Read for AesReaderValid<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        panic!("Reading from AesReaderValid")
    }
}

impl<R: io::Read> AesReaderValid<R> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader.reader
    }
}
