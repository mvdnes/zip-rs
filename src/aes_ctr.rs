use aes::block_cipher::generic_array::GenericArray;
use aes::{BlockCipher, NewBlockCipher};
use byteorder::WriteBytesExt;
use std::{any, fmt};

/// Internal block size of an AES cipher.
const AES_BLOCK_SIZE: usize = 16;

/// AES-128.
#[derive(Debug)]
pub struct Aes128;
/// AES-192
#[derive(Debug)]
pub struct Aes192;
/// AES-256.
#[derive(Debug)]
pub struct Aes256;

/// An AES cipher kind.
pub trait AesKind {
    /// Key type.
    type Key: AsRef<[u8]>;
    /// Cipher used to decrypt.
    type Cipher;
}

impl AesKind for Aes256 {
    type Key = [u8; 32];
    type Cipher = aes::Aes256;
}

/// An AES-CTR key stream generator.
///
/// Implements the slightly non-standard AES-CTR variant used by WinZip AES encryption.
///
/// Typical AES-CTR implementations combine a nonce with a 64 bit counter. WinZIP AES instead uses
/// no nonce and also uses a different byte order (little endian) than NIST (big endian).
///
/// The stream implements the `Read` trait; encryption or decryption is performed by XOR-ing the
/// bytes from the key stream with the ciphertext/plaintext.
pub struct AesCtrZipKeyStream<C: AesKind> {
    /// Current AES counter.
    counter: u128,
    /// AES cipher instance.
    cipher: C::Cipher,
    /// Stores the currently available keystream bytes.
    buffer: [u8; AES_BLOCK_SIZE],
    /// Number of bytes already used up from `buffer`.
    pos: usize,
}

impl<C> fmt::Debug for AesCtrZipKeyStream<C>
where
    C: AesKind,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AesCtrZipKeyStream<{}>(counter: {})",
            any::type_name::<C>(),
            self.counter
        )
    }
}

impl<C> AesCtrZipKeyStream<C>
where
    C: AesKind,
    C::Cipher: NewBlockCipher,
{
    /// Creates a new zip variant AES-CTR key stream.
    pub fn new(key: &C::Key) -> AesCtrZipKeyStream<C> {
        AesCtrZipKeyStream {
            counter: 1,
            cipher: C::Cipher::new_varkey(key.as_ref()).expect("key should have correct size"),
            buffer: [0u8; AES_BLOCK_SIZE],
            pos: AES_BLOCK_SIZE,
        }
    }
}

impl<C> AesCtrZipKeyStream<C>
where
    C: AesKind,
    C::Cipher: BlockCipher,
{
    /// Decrypt or encrypt given data.
    #[inline]
    fn crypt(&mut self, mut target: &mut [u8]) {
        while target.len() > 0 {
            if self.pos == AES_BLOCK_SIZE {
                // Note: AES block size is always 16 bytes, same as u128.
                self.buffer
                    .as_mut()
                    .write_u128::<byteorder::LittleEndian>(self.counter)
                    .expect("did not expect u128 le conversion to fail");
                self.cipher
                    .encrypt_block(GenericArray::from_mut_slice(&mut self.buffer));
                self.counter += 1;
                self.pos = 0;
            }

            let target_len = target.len().min(AES_BLOCK_SIZE - self.pos);

            xor(
                &mut target[0..target_len],
                &self.buffer[self.pos..(self.pos + target_len)],
            );
            target = &mut target[target_len..];
            self.pos += target_len;
        }
    }
}

/// XORs a slice in place with another slice.
#[inline]
pub fn xor(dest: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dest.len(), src.len());

    for (lhs, rhs) in dest.iter_mut().zip(src.iter()) {
        *lhs ^= *rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::{Aes256, AesCtrZipKeyStream};

    #[test]
    fn crypt_simple_example() {
        let ciphertext: [u8; 5] = [0xdc, 0x99, 0x93, 0x5e, 0xbf];
        let expected_plaintext = &[b'a', b's', b'd', b'f', b'\n'];
        let key = [
            0xd1, 0x51, 0xa6, 0xab, 0x53, 0x68, 0xd7, 0xb7, 0xbf, 0x49, 0xf7, 0xf5, 0x8a, 0x4e,
            0x10, 0x36, 0x25, 0x1c, 0x13, 0xba, 0x12, 0x45, 0x37, 0x65, 0xa9, 0xe4, 0xed, 0x9f,
            0x4a, 0xa8, 0xda, 0x3b,
        ];

        let mut key_stream = AesCtrZipKeyStream::<Aes256>::new(&key);

        let mut plaintext = ciphertext;
        key_stream.crypt(&mut plaintext);
        assert_eq!(&plaintext, expected_plaintext);

        // Round-tripping should yield the ciphertext again.
        let mut key_stream = AesCtrZipKeyStream::<Aes256>::new(&key);
        key_stream.crypt(&mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }
}
