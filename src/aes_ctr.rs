use aes::block_cipher::generic_array::GenericArray;
use aes::{BlockCipher, NewBlockCipher};
use arrayvec::{Array, ArrayVec};
use std::{any, fmt, io};

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
    type Key: Array<Item = u8>;
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
struct AesCtrZipKeyStream<C: AesKind> {
    counter: u128,
    cipher: C::Cipher,
    buffer: ArrayVec<C::Key>,
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
    #[allow(dead_code)]
    /// Creates a new zip variant AES-CTR key stream.
    pub fn new(key: &C::Key) -> AesCtrZipKeyStream<C> {
        AesCtrZipKeyStream {
            counter: 1,
            cipher: C::Cipher::new_varkey(key.as_slice()).expect("key should have correct size"),
            buffer: ArrayVec::new(),
        }
    }
}

impl<C> io::Read for AesCtrZipKeyStream<C>
where
    C: AesKind,
    C::Cipher: BlockCipher,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.len() == 0 {
            // Note: AES block size is always 16 bytes, same as u128.
            let mut block = GenericArray::clone_from_slice(&self.counter.to_le_bytes());
            self.cipher.encrypt_block(&mut block);
            self.counter += 1;
            self.buffer = block.into_iter().collect();
        }

        let target_len = buf.len().min(self.buffer.len());

        buf.copy_from_slice(&self.buffer[0..target_len]);
        self.buffer.drain(0..target_len);
        Ok(target_len)
    }
}

#[cfg(test)]
/// XORs a slice in place with another slice.
#[inline]
pub fn xor(dest: &mut [u8], src: &[u8]) {
    for (lhs, rhs) in dest.iter_mut().zip(src.iter()) {
        *lhs ^= *rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::{xor, Aes256, AesCtrZipKeyStream};
    use std::io::Read;

    #[test]
    fn simple_example() {
        let ciphertext: [u8; 5] = [0xdc, 0x99, 0x93, 0x5e, 0xbf];
        let expected_plaintext = &[b'a', b's', b'd', b'f', b'\n'];
        let key = [
            0xd1, 0x51, 0xa6, 0xab, 0x53, 0x68, 0xd7, 0xb7, 0xbf, 0x49, 0xf7, 0xf5, 0x8a, 0x4e,
            0x10, 0x36, 0x25, 0x1c, 0x13, 0xba, 0x12, 0x45, 0x37, 0x65, 0xa9, 0xe4, 0xed, 0x9f,
            0x4a, 0xa8, 0xda, 0x3b,
        ];

        let mut key_stream = AesCtrZipKeyStream::<Aes256>::new(&key);

        let mut key_buf = [0u8; 5];
        key_stream.read(&mut key_buf).unwrap();

        let mut plaintext = ciphertext;
        eprintln!("{:?}", plaintext);

        xor(&mut plaintext, &key_buf);
        eprintln!("{:?}", plaintext);

        assert_eq!(&plaintext, expected_plaintext);
    }
}
