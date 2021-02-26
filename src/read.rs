//! Types for reading ZIP archives

use crate::compression::CompressionMethod;
use crate::crc32::Crc32Reader;
use crate::result::{InvalidPassword, ZipError, ZipResult};
use crate::spec;
use crate::zipcrypto::ZipCryptoReader;
use crate::zipcrypto::ZipCryptoReaderValid;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, prelude::*};
use std::path::{Component, Path};

use crate::cp437::FromCp437;
use crate::types::{DateTime, System, ZipFileData};
use byteorder::{LittleEndian, ReadBytesExt};

#[cfg(any(
    feature = "deflate",
    feature = "deflate-miniz",
    feature = "deflate-zlib"
))]
use flate2::read::DeflateDecoder;

#[cfg(feature = "bzip2")]
use bzip2::read::BzDecoder;

#[cfg(feature = "async")]
use crate::async_util::CompatExt;
#[cfg(feature = "async")]
use async_compression::futures::bufread::{
    BzDecoder as AsyncBzDecoder, DeflateDecoder as AsyncDeflateDecoder,
};
#[cfg(feature = "async")]
use futures::{
    io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, BufReader as AsyncBufReader},
    FutureExt,
};
#[cfg(feature = "async")]
use pin_project::pin_project;
#[cfg(feature = "async")]
use std::pin::Pin;
#[cfg(feature = "async")]
use std::task::Poll;
#[cfg(feature = "async")]
use tokio::io::AsyncReadExt as TokioAsyncReadExt;

mod ffi {
    pub const S_IFDIR: u32 = 0o0040000;
    pub const S_IFREG: u32 = 0o0100000;
}

/// ZIP archive reader
///
/// ```no_run
/// use std::io::prelude::*;
/// fn list_zip_contents(reader: impl Read + Seek) -> zip::result::ZipResult<()> {
///     let mut zip = zip::ZipArchive::new(reader)?;
///
///     for i in 0..zip.len() {
///         let mut file = zip.by_index(i)?;
///         println!("Filename: {}", file.name());
///         std::io::copy(&mut file, &mut std::io::stdout());
///     }
///
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ZipArchive<R: Read + io::Seek> {
    reader: R,
    files: Vec<ZipFileData>,
    names_map: HashMap<String, usize>,
    offset: u64,
    comment: Vec<u8>,
}

/// Async ZIP archive reader
#[cfg(feature = "async")]
#[pin_project(project=AsyncZipArchiveProject)]
#[derive(Clone, Debug)]
pub struct AsyncZipArchive<R: AsyncRead + AsyncSeek + Unpin> {
    #[pin]
    reader: R,
    files: Vec<ZipFileData>,
    names_map: HashMap<String, usize>,
    offset: u64,
    comment: Vec<u8>,
}

enum CryptoReader<'a> {
    Plaintext(io::Take<&'a mut dyn Read>),
    ZipCrypto(ZipCryptoReaderValid<io::Take<&'a mut dyn Read>>),
}

impl<'a> Read for CryptoReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            CryptoReader::Plaintext(r) => r.read(buf),
            CryptoReader::ZipCrypto(r) => r.read(buf),
        }
    }
}

#[cfg(feature = "async")]
#[pin_project(project=AsyncCryptoReaderProject)]
enum AsyncCryptoReader<'a> {
    Plaintext(#[pin] futures::io::Take<Pin<&'a mut dyn AsyncRead>>),
    ZipCrypto(#[pin] ZipCryptoReaderValid<futures::io::Take<Pin<&'a mut dyn AsyncRead>>>),
}

#[cfg(feature = "async")]
impl<'a> AsyncRead for AsyncCryptoReader<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.project() {
            AsyncCryptoReaderProject::Plaintext(r) => r.poll_read(cx, buf),
            AsyncCryptoReaderProject::ZipCrypto(r) => r.poll_read(cx, buf),
        }
    }
}

impl<'a> CryptoReader<'a> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> io::Take<&'a mut dyn Read> {
        match self {
            CryptoReader::Plaintext(r) => r,
            CryptoReader::ZipCrypto(r) => r.into_inner(),
        }
    }
}

#[cfg(feature = "async")]
impl<'a> AsyncCryptoReader<'a> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> futures::io::Take<Pin<&'a mut dyn AsyncRead>> {
        match self {
            Self::Plaintext(r) => r,
            Self::ZipCrypto(r) => r.into_inner(),
        }
    }
}

enum ZipFileReader<'a> {
    NoReader,
    Raw(io::Take<&'a mut dyn io::Read>),
    Stored(Crc32Reader<CryptoReader<'a>>),
    #[cfg(any(
        feature = "deflate",
        feature = "deflate-miniz",
        feature = "deflate-zlib"
    ))]
    Deflated(Crc32Reader<flate2::read::DeflateDecoder<CryptoReader<'a>>>),
    #[cfg(feature = "bzip2")]
    Bzip2(Crc32Reader<BzDecoder<CryptoReader<'a>>>),
}

#[cfg(feature = "async")]
#[pin_project(project=AsyncZipFileReaderProject)]
enum AsyncZipFileReader<'a> {
    NoReader,
    Raw(#[pin] futures::io::Take<Pin<&'a mut dyn AsyncRead>>),
    Stored(#[pin] Crc32Reader<AsyncCryptoReader<'a>>),
    #[cfg(any(
        feature = "deflate",
        feature = "deflate-miniz",
        feature = "deflate-zlib"
    ))]
    Deflated(#[pin] Crc32Reader<AsyncDeflateDecoder<AsyncBufReader<AsyncCryptoReader<'a>>>>),
    #[cfg(feature = "bzip2")]
    Bzip2(#[pin] Crc32Reader<AsyncBzDecoder<AsyncBufReader<AsyncCryptoReader<'a>>>>),
}

impl<'a> Read for ZipFileReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ZipFileReader::NoReader => panic!("ZipFileReader was in an invalid state"),
            ZipFileReader::Raw(r) => r.read(buf),
            ZipFileReader::Stored(r) => r.read(buf),
            #[cfg(any(
                feature = "deflate",
                feature = "deflate-miniz",
                feature = "deflate-zlib"
            ))]
            ZipFileReader::Deflated(r) => r.read(buf),
            #[cfg(feature = "bzip2")]
            ZipFileReader::Bzip2(r) => r.read(buf),
        }
    }
}

#[cfg(feature = "async")]
impl<'a> AsyncRead for AsyncZipFileReader<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.project() {
            AsyncZipFileReaderProject::NoReader => panic!("ZipFileReader was in an invalid state"),
            AsyncZipFileReaderProject::Raw(r) => r.poll_read(cx, buf),
            AsyncZipFileReaderProject::Stored(r) => r.poll_read(cx, buf),
            #[cfg(any(
                feature = "deflate",
                feature = "deflate-miniz",
                feature = "deflate-zlib"
            ))]
            AsyncZipFileReaderProject::Deflated(r) => r.poll_read(cx, buf),
            #[cfg(feature = "bzip2")]
            AsyncZipFileReaderProject::Bzip2(r) => r.poll_read(cx, buf),
        }
    }
}

impl<'a> ZipFileReader<'a> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> io::Take<&'a mut dyn Read> {
        match self {
            ZipFileReader::NoReader => panic!("ZipFileReader was in an invalid state"),
            ZipFileReader::Raw(r) => r,
            ZipFileReader::Stored(r) => r.into_inner().into_inner(),
            #[cfg(any(
                feature = "deflate",
                feature = "deflate-miniz",
                feature = "deflate-zlib"
            ))]
            ZipFileReader::Deflated(r) => r.into_inner().into_inner().into_inner(),
            #[cfg(feature = "bzip2")]
            ZipFileReader::Bzip2(r) => r.into_inner().into_inner().into_inner(),
        }
    }
}

/// A struct for reading a zip file
pub struct ZipFile<'a> {
    data: Cow<'a, ZipFileData>,
    crypto_reader: Option<CryptoReader<'a>>,
    reader: ZipFileReader<'a>,
}

/// A struct for reading a zip file
#[cfg(feature = "async")]
#[pin_project]
pub struct AsyncZipFile<'a> {
    data: Cow<'a, ZipFileData>,
    crypto_reader: Option<AsyncCryptoReader<'a>>,
    #[pin]
    reader: AsyncZipFileReader<'a>,
}

fn find_content<'a>(
    data: &mut ZipFileData,
    reader: &'a mut (impl Read + Seek),
) -> ZipResult<io::Take<&'a mut dyn Read>> {
    // Parse local header
    reader.seek(io::SeekFrom::Start(data.header_start))?;
    let signature = reader.read_u32::<LittleEndian>()?;
    if signature != spec::LOCAL_FILE_HEADER_SIGNATURE {
        return Err(ZipError::InvalidArchive("Invalid local file header"));
    }

    reader.seek(io::SeekFrom::Current(22))?;
    let file_name_length = reader.read_u16::<LittleEndian>()? as u64;
    let extra_field_length = reader.read_u16::<LittleEndian>()? as u64;
    let magic_and_header = 4 + 22 + 2 + 2;
    data.data_start = data.header_start + magic_and_header + file_name_length + extra_field_length;

    reader.seek(io::SeekFrom::Start(data.data_start))?;
    Ok((reader as &mut dyn Read).take(data.compressed_size))
}

fn make_crypto_reader<'a>(
    compression_method: crate::compression::CompressionMethod,
    crc32: u32,
    reader: io::Take<&'a mut dyn io::Read>,
    password: Option<&[u8]>,
) -> ZipResult<Result<CryptoReader<'a>, InvalidPassword>> {
    #[allow(deprecated)]
    {
        if let CompressionMethod::Unsupported(_) = compression_method {
            return unsupported_zip_error("Compression method not supported");
        }
    }

    let reader = match password {
        None => CryptoReader::Plaintext(reader),
        Some(password) => match ZipCryptoReader::new(reader, password).validate(crc32)? {
            None => return Ok(Err(InvalidPassword)),
            Some(r) => CryptoReader::ZipCrypto(r),
        },
    };
    Ok(Ok(reader))
}

fn make_reader<'a>(
    compression_method: CompressionMethod,
    crc32: u32,
    reader: CryptoReader<'a>,
) -> ZipFileReader<'a> {
    match compression_method {
        CompressionMethod::Stored => ZipFileReader::Stored(Crc32Reader::new(reader, crc32)),
        #[cfg(any(
            feature = "deflate",
            feature = "deflate-miniz",
            feature = "deflate-zlib"
        ))]
        CompressionMethod::Deflated => {
            let deflate_reader = DeflateDecoder::new(reader);
            ZipFileReader::Deflated(Crc32Reader::new(deflate_reader, crc32))
        }
        #[cfg(feature = "bzip2")]
        CompressionMethod::Bzip2 => {
            let bzip2_reader = BzDecoder::new(reader);
            ZipFileReader::Bzip2(Crc32Reader::new(bzip2_reader, crc32))
        }
        _ => panic!("Compression method not supported"),
    }
}

#[cfg(feature = "async")]
async fn make_crypto_reader_async<'a>(
    compression_method: crate::compression::CompressionMethod,
    crc32: u32,
    reader: futures::io::Take<Pin<&'a mut dyn AsyncRead>>,
    password: Option<&[u8]>,
) -> ZipResult<Result<AsyncCryptoReader<'a>, InvalidPassword>> {
    #[allow(deprecated)]
    {
        if let CompressionMethod::Unsupported(_) = compression_method {
            return unsupported_zip_error("Compression method not supported");
        }
    }

    let reader = match password {
        None => AsyncCryptoReader::Plaintext(reader),
        Some(password) => match ZipCryptoReader::new_async(reader, password)
            .await
            .validate_async(crc32)
            .await?
        {
            None => return Ok(Err(InvalidPassword)),
            Some(r) => AsyncCryptoReader::ZipCrypto(r),
        },
    };
    Ok(Ok(reader))
}

#[cfg(feature = "async")]
async fn make_reader_async<'a>(
    compression_method: crate::compression::CompressionMethod,
    crc32: u32,
    reader: AsyncCryptoReader<'a>,
) -> AsyncZipFileReader<'a> {
    match compression_method {
        CompressionMethod::Stored => AsyncZipFileReader::Stored(Crc32Reader::new(reader, crc32)),
        #[cfg(any(
            feature = "deflate",
            feature = "deflate-miniz",
            feature = "deflate-zlib"
        ))]
        CompressionMethod::Deflated => {
            let deflate_reader = AsyncDeflateDecoder::new(AsyncBufReader::new(reader));
            AsyncZipFileReader::Deflated(Crc32Reader::new(deflate_reader, crc32))
        }
        #[cfg(feature = "bzip2")]
        CompressionMethod::Bzip2 => {
            let bzip2_reader = AsyncBzDecoder::new(AsyncBufReader::new(reader));
            AsyncZipFileReader::Bzip2(Crc32Reader::new(bzip2_reader, crc32))
        }
        _ => panic!("Compression method not supported"),
    }
}

impl<R: Read + io::Seek> ZipArchive<R> {
    /// Get the directory start offset and number of files. This is done in a
    /// separate function to ease the control flow design.
    fn get_directory_counts(
        reader: &mut R,
        footer: &spec::CentralDirectoryEnd,
        cde_start_pos: u64,
    ) -> ZipResult<(u64, u64, usize)> {
        // See if there's a ZIP64 footer. The ZIP64 locator if present will
        // have its signature 20 bytes in front of the standard footer. The
        // standard footer, in turn, is 22+N bytes large, where N is the
        // comment length. Therefore:
        let zip64locator = if reader
            .seek(io::SeekFrom::End(
                -(20 + 22 + footer.zip_file_comment.len() as i64),
            ))
            .is_ok()
        {
            match spec::Zip64CentralDirectoryEndLocator::parse(reader) {
                Ok(loc) => Some(loc),
                Err(ZipError::InvalidArchive(_)) => {
                    // No ZIP64 header; that's actually fine. We're done here.
                    None
                }
                Err(e) => {
                    // Yikes, a real problem
                    return Err(e);
                }
            }
        } else {
            // Empty Zip files will have nothing else so this error might be fine. If
            // not, we'll find out soon.
            None
        };

        match zip64locator {
            None => {
                // Some zip files have data prepended to them, resulting in the
                // offsets all being too small. Get the amount of error by comparing
                // the actual file position we found the CDE at with the offset
                // recorded in the CDE.
                let archive_offset = cde_start_pos
                    .checked_sub(footer.central_directory_size as u64)
                    .and_then(|x| x.checked_sub(footer.central_directory_offset as u64))
                    .ok_or(ZipError::InvalidArchive(
                        "Invalid central directory size or offset",
                    ))?;

                let directory_start = footer.central_directory_offset as u64 + archive_offset;
                let number_of_files = footer.number_of_files_on_this_disk as usize;
                Ok((archive_offset, directory_start, number_of_files))
            }
            Some(locator64) => {
                // If we got here, this is indeed a ZIP64 file.

                if footer.disk_number as u32 != locator64.disk_with_central_directory {
                    return unsupported_zip_error(
                        "Support for multi-disk files is not implemented",
                    );
                }

                // We need to reassess `archive_offset`. We know where the ZIP64
                // central-directory-end structure *should* be, but unfortunately we
                // don't know how to precisely relate that location to our current
                // actual offset in the file, since there may be junk at its
                // beginning. Therefore we need to perform another search, as in
                // read::CentralDirectoryEnd::find_and_parse, except now we search
                // forward.

                let search_upper_bound = cde_start_pos
                    .checked_sub(60) // minimum size of Zip64CentralDirectoryEnd + Zip64CentralDirectoryEndLocator
                    .ok_or(ZipError::InvalidArchive(
                        "File cannot contain ZIP64 central directory end",
                    ))?;
                let (footer, archive_offset) = spec::Zip64CentralDirectoryEnd::find_and_parse(
                    reader,
                    locator64.end_of_central_directory_offset,
                    search_upper_bound,
                )?;

                if footer.disk_number != footer.disk_with_central_directory {
                    return unsupported_zip_error(
                        "Support for multi-disk files is not implemented",
                    );
                }

                let directory_start = footer
                    .central_directory_offset
                    .checked_add(archive_offset)
                    .ok_or_else(|| {
                        ZipError::InvalidArchive("Invalid central directory size or offset")
                    })?;

                Ok((
                    archive_offset,
                    directory_start,
                    footer.number_of_files as usize,
                ))
            }
        }
    }

    /// Read a ZIP archive, collecting the files it contains
    ///
    /// This uses the central directory record of the ZIP file, and ignores local file headers
    pub fn new(mut reader: R) -> ZipResult<ZipArchive<R>> {
        let (footer, cde_start_pos) = spec::CentralDirectoryEnd::find_and_parse(&mut reader)?;

        if footer.disk_number != footer.disk_with_central_directory {
            return unsupported_zip_error("Support for multi-disk files is not implemented");
        }

        let (archive_offset, directory_start, number_of_files) =
            Self::get_directory_counts(&mut reader, &footer, cde_start_pos)?;

        let mut files = Vec::new();
        let mut names_map = HashMap::new();

        if let Err(_) = reader.seek(io::SeekFrom::Start(directory_start)) {
            return Err(ZipError::InvalidArchive(
                "Could not seek to start of central directory",
            ));
        }

        for _ in 0..number_of_files {
            let file = central_header_to_zip_file(&mut reader, archive_offset)?;
            names_map.insert(file.file_name.clone(), files.len());
            files.push(file);
        }

        Ok(ZipArchive {
            reader,
            files,
            names_map,
            offset: archive_offset,
            comment: footer.zip_file_comment,
        })
    }
    /// Extract a Zip archive into a directory, overwriting files if they
    /// already exist. Paths are sanitized with [`ZipFile::enclosed_name`].
    ///
    /// Extraction is not atomic; If an error is encountered, some of the files
    /// may be left on disk.
    pub fn extract<P: AsRef<Path>>(&mut self, directory: P) -> ZipResult<()> {
        use std::fs;

        for i in 0..self.len() {
            let mut file = self.by_index(i)?;
            let filepath = file
                .enclosed_name()
                .ok_or(ZipError::InvalidArchive("Invalid file path"))?;

            let outpath = directory.as_ref().join(filepath);

            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        fs::create_dir_all(&p)?;
                    }
                }
                let mut outfile = fs::File::create(&outpath)?;
                io::copy(&mut file, &mut outfile)?;
            }
            // Get and Set permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                }
            }
        }
        Ok(())
    }

    /// Number of files contained in this zip.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether this zip archive contains no files
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the offset from the beginning of the underlying reader that this zip begins at, in bytes.
    ///
    /// Normally this value is zero, but if the zip has arbitrary data prepended to it, then this value will be the size
    /// of that prepended data.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Get the comment of the zip archive.
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// Returns an iterator over all the file and directory names in this archive.
    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.names_map.keys().map(|s| s.as_str())
    }

    /// Search for a file entry by name, decrypt with given password
    pub fn by_name_decrypt<'a>(
        &'a mut self,
        name: &str,
        password: &[u8],
    ) -> ZipResult<Result<ZipFile<'a>, InvalidPassword>> {
        self.by_name_with_optional_password(name, Some(password))
    }

    /// Search for a file entry by name
    pub fn by_name<'a>(&'a mut self, name: &str) -> ZipResult<ZipFile<'a>> {
        Ok(self.by_name_with_optional_password(name, None)?.unwrap())
    }

    fn by_name_with_optional_password<'a>(
        &'a mut self,
        name: &str,
        password: Option<&[u8]>,
    ) -> ZipResult<Result<ZipFile<'a>, InvalidPassword>> {
        let index = match self.names_map.get(name) {
            Some(index) => *index,
            None => {
                return Err(ZipError::FileNotFound);
            }
        };
        self.by_index_with_optional_password(index, password)
    }

    /// Get a contained file by index, decrypt with given password
    pub fn by_index_decrypt<'a>(
        &'a mut self,
        file_number: usize,
        password: &[u8],
    ) -> ZipResult<Result<ZipFile<'a>, InvalidPassword>> {
        self.by_index_with_optional_password(file_number, Some(password))
    }

    /// Get a contained file by index
    pub fn by_index<'a>(&'a mut self, file_number: usize) -> ZipResult<ZipFile<'a>> {
        Ok(self
            .by_index_with_optional_password(file_number, None)?
            .unwrap())
    }

    /// Get a contained file by index without decompressing it
    pub fn by_index_raw<'a>(&'a mut self, file_number: usize) -> ZipResult<ZipFile<'a>> {
        let reader = &mut self.reader;
        self.files
            .get_mut(file_number)
            .ok_or(ZipError::FileNotFound)
            .and_then(move |data| {
                Ok(ZipFile {
                    crypto_reader: None,
                    reader: ZipFileReader::Raw(find_content(data, reader)?),
                    data: Cow::Borrowed(data),
                })
            })
    }

    fn by_index_with_optional_password<'a>(
        &'a mut self,
        file_number: usize,
        mut password: Option<&[u8]>,
    ) -> ZipResult<Result<ZipFile<'a>, InvalidPassword>> {
        if file_number >= self.files.len() {
            return Err(ZipError::FileNotFound);
        }
        let data = &mut self.files[file_number];

        match (password, data.encrypted) {
            (None, true) => {
                return Err(ZipError::UnsupportedArchive(
                    "Password required to decrypt file",
                ))
            }
            (Some(_), false) => password = None, //Password supplied, but none needed! Discard.
            _ => {}
        }
        let limit_reader = find_content(data, &mut self.reader)?;

        match make_crypto_reader(data.compression_method, data.crc32, limit_reader, password) {
            Ok(Ok(crypto_reader)) => Ok(Ok(ZipFile {
                crypto_reader: Some(crypto_reader),
                reader: ZipFileReader::NoReader,
                data: Cow::Borrowed(data),
            })),
            Err(e) => Err(e),
            Ok(Err(e)) => Ok(Err(e)),
        }
    }

    /// Unwrap and return the inner reader object
    ///
    /// The position of the reader is undefined.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + AsyncSeek + Unpin> AsyncZipArchive<R> {
    /// Read a ZIP archive, collecting the files it contains
    ///
    /// This uses the central directory record of the ZIP file, and ignores local file headers
    pub async fn new(mut reader: R) -> ZipResult<Self> {
        let mut preader = Pin::new(&mut reader);
        let (footer, cde_start_pos) =
            spec::CentralDirectoryEnd::find_and_parse_async(preader.as_mut()).await?;

        if footer.disk_number != footer.disk_with_central_directory {
            return unsupported_zip_error("Support for multi-disk files is not implemented");
        }

        let (archive_offset, directory_start, number_of_files) =
            Self::get_directory_counts(&mut preader.as_mut(), &footer, cde_start_pos).await?;

        let mut files = Vec::new();
        let mut names_map = HashMap::new();

        if let Err(_) = preader
            .as_mut()
            .seek(io::SeekFrom::Start(directory_start))
            .await
        {
            return Err(ZipError::InvalidArchive(
                "Could not seek to start of central directory",
            ));
        }

        for _ in 0..number_of_files {
            let file = central_header_to_zip_file_async(preader.as_mut(), archive_offset).await?;
            names_map.insert(file.file_name.clone(), files.len());
            files.push(file);
        }

        Ok(Self {
            reader,
            files,
            names_map,
            offset: archive_offset,
            comment: footer.zip_file_comment,
        })
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + AsyncSeek + Unpin> AsyncZipArchive<R> {
    /// Get the directory start offset and number of files. This is done in a
    /// separate function to ease the control flow design.
    async fn get_directory_counts(
        reader: &mut R,
        footer: &spec::CentralDirectoryEnd,
        cde_start_pos: u64,
    ) -> ZipResult<(u64, u64, usize)> {
        // See if there's a ZIP64 footer. The ZIP64 locator if present will
        // have its signature 20 bytes in front of the standard footer. The
        // standard footer, in turn, is 22+N bytes large, where N is the
        // comment length. Therefore:
        let zip64locator = if reader
            .seek(io::SeekFrom::End(
                -(20 + 22 + footer.zip_file_comment.len() as i64),
            ))
            .await
            .is_ok()
        {
            match spec::Zip64CentralDirectoryEndLocator::parse_async(Pin::new(reader)).await {
                Ok(loc) => Some(loc),
                Err(ZipError::InvalidArchive(_)) => {
                    // No ZIP64 header; that's actually fine. We're done here.
                    None
                }
                Err(e) => {
                    // Yikes, a real problem
                    return Err(e);
                }
            }
        } else {
            // Empty Zip files will have nothing else so this error might be fine. If
            // not, we'll find out soon.
            None
        };

        match zip64locator {
            None => {
                // Some zip files have data prepended to them, resulting in the
                // offsets all being too small. Get the amount of error by comparing
                // the actual file position we found the CDE at with the offset
                // recorded in the CDE.
                let archive_offset = cde_start_pos
                    .checked_sub(footer.central_directory_size as u64)
                    .and_then(|x| x.checked_sub(footer.central_directory_offset as u64))
                    .ok_or(ZipError::InvalidArchive(
                        "Invalid central directory size or offset",
                    ))?;

                let directory_start = footer.central_directory_offset as u64 + archive_offset;
                let number_of_files = footer.number_of_files_on_this_disk as usize;
                Ok((archive_offset, directory_start, number_of_files))
            }
            Some(locator64) => {
                // If we got here, this is indeed a ZIP64 file.

                if footer.disk_number as u32 != locator64.disk_with_central_directory {
                    return unsupported_zip_error(
                        "Support for multi-disk files is not implemented",
                    );
                }

                // We need to reassess `archive_offset`. We know where the ZIP64
                // central-directory-end structure *should* be, but unfortunately we
                // don't know how to precisely relate that location to our current
                // actual offset in the file, since there may be junk at its
                // beginning. Therefore we need to perform another search, as in
                // read::CentralDirectoryEnd::find_and_parse, except now we search
                // forward.

                let search_upper_bound = cde_start_pos
                    .checked_sub(60) // minimum size of Zip64CentralDirectoryEnd + Zip64CentralDirectoryEndLocator
                    .ok_or(ZipError::InvalidArchive(
                        "File cannot contain ZIP64 central directory end",
                    ))?;
                let (footer, archive_offset) =
                    spec::Zip64CentralDirectoryEnd::find_and_parse_async(
                        Pin::new(reader),
                        locator64.end_of_central_directory_offset,
                        search_upper_bound,
                    )
                    .await?;

                if footer.disk_number != footer.disk_with_central_directory {
                    return unsupported_zip_error(
                        "Support for multi-disk files is not implemented",
                    );
                }

                let directory_start = footer
                    .central_directory_offset
                    .checked_add(archive_offset)
                    .ok_or_else(|| {
                        ZipError::InvalidArchive("Invalid central directory size or offset")
                    })?;

                Ok((
                    archive_offset,
                    directory_start,
                    footer.number_of_files as usize,
                ))
            }
        }
    }

    /// Number of files contained in this zip.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether this zip archive contains no files
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the offset from the beginning of the underlying reader that this zip begins at, in bytes.
    ///
    /// Normally this value is zero, but if the zip has arbitrary data prepended to it, then this value will be the size
    /// of that prepended data.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Get the comment of the zip archive.
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// Returns an iterator over all the file and directory names in this archive.
    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.names_map.keys().map(|s| s.as_str())
    }

    /// Search for a file entry by name, decrypt with given password
    pub async fn by_name_decrypt<'a>(
        &'a mut self,
        name: &str,
        password: &[u8],
    ) -> ZipResult<Result<AsyncZipFile<'a>, InvalidPassword>> {
        self.by_name_with_optional_password(name, Some(password))
            .await
    }

    /// Search for a file entry by name
    pub async fn by_name<'a>(&'a mut self, name: &str) -> ZipResult<AsyncZipFile<'a>> {
        Ok(self
            .by_name_with_optional_password(name, None)
            .await?
            .unwrap())
    }

    async fn by_name_with_optional_password<'a>(
        &'a mut self,
        name: &str,
        password: Option<&[u8]>,
    ) -> ZipResult<Result<AsyncZipFile<'a>, InvalidPassword>> {
        let index = match self.names_map.get(name) {
            Some(index) => *index,
            None => {
                return Err(ZipError::FileNotFound);
            }
        };
        self.by_index_with_optional_password(index, password).await
    }

    /// Get a contained file by index, decrypt with given password
    pub async fn by_index_decrypt<'a>(
        &'a mut self,
        file_number: usize,
        password: &[u8],
    ) -> ZipResult<Result<AsyncZipFile<'a>, InvalidPassword>> {
        self.by_index_with_optional_password(file_number, Some(password))
            .await
    }

    /// Get a contained file by index
    pub async fn by_index<'a>(
        self: &'a mut Self,
        file_number: usize,
    ) -> ZipResult<AsyncZipFile<'a>> {
        Ok(self
            .by_index_with_optional_password(file_number, None)
            .await?
            .unwrap())
    }

    async fn by_index_with_optional_password<'a>(
        &'a mut self,
        file_number: usize,
        mut password: Option<&[u8]>,
    ) -> ZipResult<Result<AsyncZipFile<'a>, InvalidPassword>> {
        if file_number >= self.files.len() {
            return Err(ZipError::FileNotFound);
        }

        let data = &mut self.files[file_number];

        match (password, data.encrypted) {
            (None, true) => {
                return Err(ZipError::UnsupportedArchive(
                    "Password required to decrypt file",
                ))
            }
            (Some(_), false) => password = None, //Password supplied, but none needed! Discard.
            _ => {}
        }

        // Parse local header
        self.reader
            .seek(io::SeekFrom::Start(data.header_start))
            .await?;
        let signature = self.reader.compat_mut().read_u32_le().await?;
        if signature != spec::LOCAL_FILE_HEADER_SIGNATURE {
            return Err(ZipError::InvalidArchive("Invalid local file header"));
        }

        self.reader.seek(io::SeekFrom::Current(22)).await?;
        let file_name_length = self.reader.compat_mut().read_u16_le().await? as u64;
        let extra_field_length = self.reader.compat_mut().read_u16_le().await? as u64;
        let magic_and_header = 4 + 22 + 2 + 2;
        data.data_start =
            data.header_start + magic_and_header + file_name_length + extra_field_length;

        self.reader
            .seek(io::SeekFrom::Start(data.data_start))
            .await?;
        let limit_reader =
            (Pin::new(&mut self.reader) as Pin<&'a mut dyn AsyncRead>).take(data.compressed_size);

        match make_crypto_reader_async(data.compression_method, data.crc32, limit_reader, password)
            .await
        {
            Ok(Ok(crypto_reader)) => Ok(Ok(AsyncZipFile {
                crypto_reader: Some(crypto_reader),
                reader: AsyncZipFileReader::NoReader,
                data: Cow::Borrowed(data),
            })),
            Err(e) => Err(e),
            Ok(Err(e)) => Ok(Err(e)),
        }
    }

    /// Unwrap and return the inner reader object
    ///
    /// The position of the reader is undefined.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

fn unsupported_zip_error<T>(detail: &'static str) -> ZipResult<T> {
    Err(ZipError::UnsupportedArchive(detail))
}

fn central_header_to_zip_file<R: Read + io::Seek>(
    reader: &mut R,
    archive_offset: u64,
) -> ZipResult<ZipFileData> {
    let central_header_start = reader.seek(io::SeekFrom::Current(0))?;
    // Parse central header
    let signature = reader.read_u32::<LittleEndian>()?;
    if signature != spec::CENTRAL_DIRECTORY_HEADER_SIGNATURE {
        return Err(ZipError::InvalidArchive("Invalid Central Directory header"));
    }

    let version_made_by = reader.read_u16::<LittleEndian>()?;
    let _version_to_extract = reader.read_u16::<LittleEndian>()?;
    let flags = reader.read_u16::<LittleEndian>()?;
    let encrypted = flags & 1 == 1;
    let is_utf8 = flags & (1 << 11) != 0;
    let compression_method = reader.read_u16::<LittleEndian>()?;
    let last_mod_time = reader.read_u16::<LittleEndian>()?;
    let last_mod_date = reader.read_u16::<LittleEndian>()?;
    let crc32 = reader.read_u32::<LittleEndian>()?;
    let compressed_size = reader.read_u32::<LittleEndian>()?;
    let uncompressed_size = reader.read_u32::<LittleEndian>()?;
    let file_name_length = reader.read_u16::<LittleEndian>()? as usize;
    let extra_field_length = reader.read_u16::<LittleEndian>()? as usize;
    let file_comment_length = reader.read_u16::<LittleEndian>()? as usize;
    let _disk_number = reader.read_u16::<LittleEndian>()?;
    let _internal_file_attributes = reader.read_u16::<LittleEndian>()?;
    let external_file_attributes = reader.read_u32::<LittleEndian>()?;
    let offset = reader.read_u32::<LittleEndian>()? as u64;
    let mut file_name_raw = vec![0; file_name_length];
    reader.read_exact(&mut file_name_raw)?;
    let mut extra_field = vec![0; extra_field_length];
    reader.read_exact(&mut extra_field)?;
    let mut file_comment_raw = vec![0; file_comment_length];
    reader.read_exact(&mut file_comment_raw)?;

    let file_name = match is_utf8 {
        true => String::from_utf8_lossy(&*file_name_raw).into_owned(),
        false => file_name_raw.clone().from_cp437(),
    };
    let file_comment = match is_utf8 {
        true => String::from_utf8_lossy(&*file_comment_raw).into_owned(),
        false => file_comment_raw.from_cp437(),
    };

    // Construct the result
    let mut result = ZipFileData {
        system: System::from_u8((version_made_by >> 8) as u8),
        version_made_by: version_made_by as u8,
        encrypted,
        compression_method: {
            #[allow(deprecated)]
            CompressionMethod::from_u16(compression_method)
        },
        last_modified_time: DateTime::from_msdos(last_mod_date, last_mod_time),
        crc32,
        compressed_size: compressed_size as u64,
        uncompressed_size: uncompressed_size as u64,
        file_name,
        file_name_raw,
        file_comment,
        header_start: offset,
        central_header_start,
        data_start: 0,
        external_attributes: external_file_attributes,
    };

    match parse_extra_field(&mut result, &*extra_field) {
        Ok(..) | Err(ZipError::Io(..)) => {}
        Err(e) => return Err(e),
    }

    // Account for shifted zip offsets.
    result.header_start += archive_offset;

    Ok(result)
}

#[cfg(feature = "async")]
async fn central_header_to_zip_file_async<R: AsyncRead + AsyncSeek>(
    mut reader: Pin<&mut R>,
    archive_offset: u64,
) -> ZipResult<ZipFileData> {
    let central_header_start = reader.seek(io::SeekFrom::Current(0)).await?;
    let mut reader = reader.compat();
    // Parse central header
    let signature = reader.read_u32_le().await?;
    if signature != spec::CENTRAL_DIRECTORY_HEADER_SIGNATURE {
        return Err(ZipError::InvalidArchive("Invalid Central Directory header"));
    }

    let version_made_by = reader.read_u16_le().await?;
    let _version_to_extract = reader.read_u16_le().await?;
    let flags = reader.read_u16_le().await?;
    let encrypted = flags & 1 == 1;
    let is_utf8 = flags & (1 << 11) != 0;
    let compression_method = reader.read_u16_le().await?;
    let last_mod_time = reader.read_u16_le().await?;
    let last_mod_date = reader.read_u16_le().await?;
    let crc32 = reader.read_u32_le().await?;
    let compressed_size = reader.read_u32_le().await?;
    let uncompressed_size = reader.read_u32_le().await?;
    let file_name_length = reader.read_u16_le().await? as usize;
    let extra_field_length = reader.read_u16_le().await? as usize;
    let file_comment_length = reader.read_u16_le().await? as usize;
    let _disk_number = reader.read_u16_le().await?;
    let _internal_file_attributes = reader.read_u16_le().await?;
    let external_file_attributes = reader.read_u32_le().await?;
    let offset = reader.read_u32_le().await? as u64;
    let mut file_name_raw = vec![0; file_name_length];
    let mut reader = reader.into_inner();
    reader.read_exact(&mut file_name_raw).await?;
    let mut extra_field = vec![0; extra_field_length];
    reader.read_exact(&mut extra_field).await?;
    let mut file_comment_raw = vec![0; file_comment_length];
    reader.read_exact(&mut file_comment_raw).await?;

    let file_name = match is_utf8 {
        true => String::from_utf8_lossy(&*file_name_raw).into_owned(),
        false => file_name_raw.clone().from_cp437(),
    };
    let file_comment = match is_utf8 {
        true => String::from_utf8_lossy(&*file_comment_raw).into_owned(),
        false => file_comment_raw.from_cp437(),
    };

    // Construct the result
    let mut result = ZipFileData {
        system: System::from_u8((version_made_by >> 8) as u8),
        version_made_by: version_made_by as u8,
        encrypted,
        compression_method: {
            #[allow(deprecated)]
            CompressionMethod::from_u16(compression_method)
        },
        last_modified_time: DateTime::from_msdos(last_mod_date, last_mod_time),
        crc32,
        compressed_size: compressed_size as u64,
        uncompressed_size: uncompressed_size as u64,
        file_name,
        file_name_raw,
        file_comment,
        header_start: offset,
        central_header_start,
        data_start: 0,
        external_attributes: external_file_attributes,
    };

    match parse_extra_field(&mut result, &*extra_field) {
        Ok(..) | Err(ZipError::Io(..)) => {}
        Err(e) => return Err(e),
    }

    // Account for shifted zip offsets.
    result.header_start += archive_offset;

    Ok(result)
}

fn parse_extra_field(file: &mut ZipFileData, data: &[u8]) -> ZipResult<()> {
    let mut reader = io::Cursor::new(data);

    while (reader.position() as usize) < data.len() {
        let kind = ReadBytesExt::read_u16::<LittleEndian>(&mut reader)?;
        let len = ReadBytesExt::read_u16::<LittleEndian>(&mut reader)?;
        let mut len_left = len as i64;
        // Zip64 extended information extra field
        if kind == 0x0001 {
            if file.uncompressed_size == 0xFFFFFFFF {
                file.uncompressed_size = ReadBytesExt::read_u64::<LittleEndian>(&mut reader)?;
                len_left -= 8;
            }
            if file.compressed_size == 0xFFFFFFFF {
                file.compressed_size = ReadBytesExt::read_u64::<LittleEndian>(&mut reader)?;
                len_left -= 8;
            }
            if file.header_start == 0xFFFFFFFF {
                file.header_start = ReadBytesExt::read_u64::<LittleEndian>(&mut reader)?;
                len_left -= 8;
            }
            // Unparsed fields:
            // u32: disk start number
        }

        // We could also check for < 0 to check for errors
        if len_left > 0 {
            reader.seek(io::SeekFrom::Current(len_left))?;
        }
    }
    Ok(())
}

/// Methods for retrieving information on zip files
impl<'a> ZipFile<'a> {
    fn get_reader(&mut self) -> &mut ZipFileReader<'a> {
        if let ZipFileReader::NoReader = self.reader {
            let data = &self.data;
            let crypto_reader = self.crypto_reader.take().expect("Invalid reader state");
            self.reader = make_reader(data.compression_method, data.crc32, crypto_reader)
        }
        &mut self.reader
    }

    pub(crate) fn get_raw_reader(&mut self) -> &mut dyn Read {
        if let ZipFileReader::NoReader = self.reader {
            let crypto_reader = self.crypto_reader.take().expect("Invalid reader state");
            self.reader = ZipFileReader::Raw(crypto_reader.into_inner())
        }
        &mut self.reader
    }

    /// Get the version of the file
    pub fn version_made_by(&self) -> (u8, u8) {
        (
            self.data.version_made_by / 10,
            self.data.version_made_by % 10,
        )
    }

    /// Get the name of the file
    ///
    /// # Warnings
    ///
    /// It is dangerous to use this name directly when extracting an archive.
    /// It may contain an absolute path (`/etc/shadow`), or break out of the
    /// current directory (`../runtime`). Carelessly writing to these paths
    /// allows an attacker to craft a ZIP archive that will overwrite critical
    /// files.
    ///
    /// You can use the [`ZipFile::enclosed_name`] method to validate the name
    /// as a safe path.
    pub fn name(&self) -> &str {
        &self.data.file_name
    }

    /// Get the name of the file, in the raw (internal) byte representation.
    ///
    /// The encoding of this data is currently undefined.
    pub fn name_raw(&self) -> &[u8] {
        &self.data.file_name_raw
    }

    /// Get the name of the file in a sanitized form. It truncates the name to the first NULL byte,
    /// removes a leading '/' and removes '..' parts.
    #[deprecated(
        since = "0.5.7",
        note = "by stripping `..`s from the path, the meaning of paths can change.
                `mangled_name` can be used if this behaviour is desirable"
    )]
    pub fn sanitized_name(&self) -> ::std::path::PathBuf {
        self.mangled_name()
    }

    /// Rewrite the path, ignoring any path components with special meaning.
    ///
    /// - Absolute paths are made relative
    /// - [`ParentDir`]s are ignored
    /// - Truncates the filename at a NULL byte
    ///
    /// This is appropriate if you need to be able to extract *something* from
    /// any archive, but will easily misrepresent trivial paths like
    /// `foo/../bar` as `foo/bar` (instead of `bar`). Because of this,
    /// [`ZipFile::enclosed_name`] is the better option in most scenarios.
    ///
    /// [`ParentDir`]: `Component::ParentDir`
    pub fn mangled_name(&self) -> ::std::path::PathBuf {
        self.data.file_name_sanitized()
    }

    /// Ensure the file path is safe to use as a [`Path`].
    ///
    /// - It can't contain NULL bytes
    /// - It can't resolve to a path outside the current directory
    ///   > `foo/../bar` is fine, `foo/../../bar` is not.
    /// - It can't be an absolute path
    ///
    /// This will read well-formed ZIP files correctly, and is resistant
    /// to path-based exploits. It is recommended over
    /// [`ZipFile::mangled_name`].
    pub fn enclosed_name(&self) -> Option<&Path> {
        if self.data.file_name.contains('\0') {
            return None;
        }
        let path = Path::new(&self.data.file_name);
        let mut depth = 0usize;
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => return None,
                Component::ParentDir => depth = depth.checked_sub(1)?,
                Component::Normal(_) => depth += 1,
                Component::CurDir => (),
            }
        }
        Some(path)
    }

    /// Get the comment of the file
    pub fn comment(&self) -> &str {
        &self.data.file_comment
    }

    /// Get the compression method used to store the file
    pub fn compression(&self) -> CompressionMethod {
        self.data.compression_method
    }

    /// Get the size of the file in the archive
    pub fn compressed_size(&self) -> u64 {
        self.data.compressed_size
    }

    /// Get the size of the file when uncompressed
    pub fn size(&self) -> u64 {
        self.data.uncompressed_size
    }

    /// Get the time the file was last modified
    pub fn last_modified(&self) -> DateTime {
        self.data.last_modified_time
    }
    /// Returns whether the file is actually a directory
    pub fn is_dir(&self) -> bool {
        self.name()
            .chars()
            .rev()
            .next()
            .map_or(false, |c| c == '/' || c == '\\')
    }

    /// Returns whether the file is a regular file
    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    /// Get unix mode for the file
    pub fn unix_mode(&self) -> Option<u32> {
        if self.data.external_attributes == 0 {
            return None;
        }

        match self.data.system {
            System::Unix => Some(self.data.external_attributes >> 16),
            System::Dos => {
                // Interpret MSDOS directory bit
                let mut mode = if 0x10 == (self.data.external_attributes & 0x10) {
                    ffi::S_IFDIR | 0o0775
                } else {
                    ffi::S_IFREG | 0o0664
                };
                if 0x01 == (self.data.external_attributes & 0x01) {
                    // Read-only bit; strip write permissions
                    mode &= 0o0555;
                }
                Some(mode)
            }
            _ => None,
        }
    }

    /// Get the CRC32 hash of the original file
    pub fn crc32(&self) -> u32 {
        self.data.crc32
    }

    /// Get the starting offset of the data of the compressed file
    pub fn data_start(&self) -> u64 {
        self.data.data_start
    }

    /// Get the starting offset of the zip header for this file
    pub fn header_start(&self) -> u64 {
        self.data.header_start
    }
    /// Get the starting offset of the zip header in the central directory for this file
    pub fn central_header_start(&self) -> u64 {
        self.data.central_header_start
    }
}

/// Methods for retrieving information on zip files
#[cfg(feature = "async")]
impl<'a> AsyncZipFile<'a> {
    async fn get_reader(&mut self) -> &mut AsyncZipFileReader<'a> {
        if let AsyncZipFileReader::NoReader = self.reader {
            let data = &self.data;
            let crypto_reader = self.crypto_reader.take().expect("Invalid reader state");
            self.reader =
                make_reader_async(data.compression_method, data.crc32, crypto_reader).await
        }
        &mut self.reader
    }

    pub(crate) fn get_raw_reader(&mut self) -> &mut (dyn AsyncRead + Unpin) {
        if let AsyncZipFileReader::NoReader = self.reader {
            let crypto_reader = self.crypto_reader.take().expect("Invalid reader state");
            self.reader = AsyncZipFileReader::Raw(crypto_reader.into_inner())
        }
        &mut self.reader
    }

    /// Get the version of the file
    pub fn version_made_by(&self) -> (u8, u8) {
        (
            self.data.version_made_by / 10,
            self.data.version_made_by % 10,
        )
    }

    /// Get the name of the file
    pub fn name(&self) -> &str {
        &self.data.file_name
    }

    /// Get the name of the file, in the raw (internal) byte representation.
    pub fn name_raw(&self) -> &[u8] {
        &self.data.file_name_raw
    }

    /// Get the comment of the file
    pub fn comment(&self) -> &str {
        &self.data.file_comment
    }

    /// Get the compression method used to store the file
    pub fn compression(&self) -> CompressionMethod {
        self.data.compression_method
    }

    /// Get the size of the file in the archive
    pub fn compressed_size(&self) -> u64 {
        self.data.compressed_size
    }

    /// Get the size of the file when uncompressed
    pub fn size(&self) -> u64 {
        self.data.uncompressed_size
    }

    /// Get the time the file was last modified
    pub fn last_modified(&self) -> DateTime {
        self.data.last_modified_time
    }
    /// Returns whether the file is actually a directory
    pub fn is_dir(&self) -> bool {
        self.name()
            .chars()
            .rev()
            .next()
            .map_or(false, |c| c == '/' || c == '\\')
    }

    /// Returns whether the file is a regular file
    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    /// Get unix mode for the file
    pub fn unix_mode(&self) -> Option<u32> {
        if self.data.external_attributes == 0 {
            return None;
        }

        match self.data.system {
            System::Unix => Some(self.data.external_attributes >> 16),
            System::Dos => {
                // Interpret MSDOS directory bit
                let mut mode = if 0x10 == (self.data.external_attributes & 0x10) {
                    ffi::S_IFDIR | 0o0775
                } else {
                    ffi::S_IFREG | 0o0664
                };
                if 0x01 == (self.data.external_attributes & 0x01) {
                    // Read-only bit; strip write permissions
                    mode &= 0o0555;
                }
                Some(mode)
            }
            _ => None,
        }
    }

    /// Get the CRC32 hash of the original file
    pub fn crc32(&self) -> u32 {
        self.data.crc32
    }

    /// Get the starting offset of the data of the compressed file
    pub fn data_start(&self) -> u64 {
        self.data.data_start
    }

    /// Get the starting offset of the zip header for this file
    pub fn header_start(&self) -> u64 {
        self.data.header_start
    }
    /// Get the starting offset of the zip header in the central directory for this file
    pub fn central_header_start(&self) -> u64 {
        self.data.central_header_start
    }
}

impl<'a> Read for ZipFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.get_reader().read(buf)
    }
}

#[cfg(feature = "async")]
impl<'a> AsyncRead for AsyncZipFile<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let reader = &mut self.get_reader().boxed_local().as_mut().poll(cx);

        match reader {
            Poll::Ready(reader) => Pin::new(reader).poll_read(cx, buf),
            Poll::Pending => Poll::Pending,
        }
        // reader.poll_read(cx, buf)
    }
}

impl<'a> Drop for ZipFile<'a> {
    fn drop(&mut self) {
        // self.data is Owned, this reader is constructed by a streaming reader.
        // In this case, we want to exhaust the reader so that the next file is accessible.
        if let Cow::Owned(_) = self.data {
            let mut buffer = [0; 1 << 16];

            // Get the inner `Take` reader so all decryption, decompression and CRC calculation is skipped.
            let mut reader: std::io::Take<&mut dyn std::io::Read> = match &mut self.reader {
                ZipFileReader::NoReader => {
                    let innerreader = ::std::mem::replace(&mut self.crypto_reader, None);
                    innerreader.expect("Invalid reader state").into_inner()
                }
                reader => {
                    let innerreader = ::std::mem::replace(reader, ZipFileReader::NoReader);
                    innerreader.into_inner()
                }
            };

            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => (),
                    Err(e) => panic!(
                        "Could not consume all of the output of the current ZipFile: {:?}",
                        e
                    ),
                }
            }
        }
    }
}

/// Read ZipFile structures from a non-seekable reader.
///
/// This is an alternative method to read a zip file. If possible, use the ZipArchive functions
/// as some information will be missing when reading this manner.
///
/// Reads a file header from the start of the stream. Will return `Ok(Some(..))` if a file is
/// present at the start of the stream. Returns `Ok(None)` if the start of the central directory
/// is encountered. No more files should be read after this.
///
/// The Drop implementation of ZipFile ensures that the reader will be correctly positioned after
/// the structure is done.
///
/// Missing fields are:
/// * `comment`: set to an empty string
/// * `data_start`: set to 0
/// * `external_attributes`: `unix_mode()`: will return None
pub fn read_zipfile_from_stream<'a, R: io::Read>(
    reader: &'a mut R,
) -> ZipResult<Option<ZipFile<'_>>> {
    let signature = reader.read_u32::<LittleEndian>()?;

    match signature {
        spec::LOCAL_FILE_HEADER_SIGNATURE => (),
        spec::CENTRAL_DIRECTORY_HEADER_SIGNATURE => return Ok(None),
        _ => return Err(ZipError::InvalidArchive("Invalid local file header")),
    }

    let version_made_by = reader.read_u16::<LittleEndian>()?;
    let flags = reader.read_u16::<LittleEndian>()?;
    let encrypted = flags & 1 == 1;
    let is_utf8 = flags & (1 << 11) != 0;
    let using_data_descriptor = flags & (1 << 3) != 0;
    #[allow(deprecated)]
    let compression_method = CompressionMethod::from_u16(reader.read_u16::<LittleEndian>()?);
    let last_mod_time = reader.read_u16::<LittleEndian>()?;
    let last_mod_date = reader.read_u16::<LittleEndian>()?;
    let crc32 = reader.read_u32::<LittleEndian>()?;
    let compressed_size = reader.read_u32::<LittleEndian>()?;
    let uncompressed_size = reader.read_u32::<LittleEndian>()?;
    let file_name_length = reader.read_u16::<LittleEndian>()? as usize;
    let extra_field_length = reader.read_u16::<LittleEndian>()? as usize;

    let mut file_name_raw = vec![0; file_name_length];
    reader.read_exact(&mut file_name_raw)?;
    let mut extra_field = vec![0; extra_field_length];
    reader.read_exact(&mut extra_field)?;

    let file_name = match is_utf8 {
        true => String::from_utf8_lossy(&*file_name_raw).into_owned(),
        false => file_name_raw.clone().from_cp437(),
    };

    let mut result = ZipFileData {
        system: System::from_u8((version_made_by >> 8) as u8),
        version_made_by: version_made_by as u8,
        encrypted,
        compression_method,
        last_modified_time: DateTime::from_msdos(last_mod_date, last_mod_time),
        crc32,
        compressed_size: compressed_size as u64,
        uncompressed_size: uncompressed_size as u64,
        file_name,
        file_name_raw,
        file_comment: String::new(), // file comment is only available in the central directory
        // header_start and data start are not available, but also don't matter, since seeking is
        // not available.
        header_start: 0,
        data_start: 0,
        central_header_start: 0,
        // The external_attributes field is only available in the central directory.
        // We set this to zero, which should be valid as the docs state 'If input came
        // from standard input, this field is set to zero.'
        external_attributes: 0,
    };

    match parse_extra_field(&mut result, &extra_field) {
        Ok(..) | Err(ZipError::Io(..)) => {}
        Err(e) => return Err(e),
    }

    if encrypted {
        return unsupported_zip_error("Encrypted files are not supported");
    }
    if using_data_descriptor {
        return unsupported_zip_error("The file length is not available in the local header");
    }

    let limit_reader = (reader as &'a mut dyn io::Read).take(result.compressed_size as u64);

    let result_crc32 = result.crc32;
    let result_compression_method = result.compression_method;
    let crypto_reader =
        make_crypto_reader(result_compression_method, result_crc32, limit_reader, None)?.unwrap();

    Ok(Some(ZipFile {
        data: Cow::Owned(result),
        crypto_reader: None,
        reader: make_reader(result_compression_method, result_crc32, crypto_reader),
    }))
}

/// See [read_zipfile_from_stream_async]
///
/// In contrast, there is no drop implementation in the asynchronous implementation.
/// You must call `AsyncReadExt::read_to_end` or similar to drain each file before reusing the reader.
#[cfg(feature = "async")]
pub async fn read_zipfile_from_stream_async<'a, R: AsyncRead + Unpin>(
    reader: &'a mut R,
) -> ZipResult<Option<AsyncZipFile<'_>>> {
    let mut r = reader.compat_mut();
    let signature = r.read_u32_le().await?;

    match signature {
        spec::LOCAL_FILE_HEADER_SIGNATURE => (),
        spec::CENTRAL_DIRECTORY_HEADER_SIGNATURE => return Ok(None),
        _ => return Err(ZipError::InvalidArchive("Invalid local file header")),
    }

    let version_made_by = r.read_u16_le().await?;
    let flags = r.read_u16_le().await?;
    let encrypted = flags & 1 == 1;
    let is_utf8 = flags & (1 << 11) != 0;
    let using_data_descriptor = flags & (1 << 3) != 0;
    #[allow(deprecated)]
    let compression_method = CompressionMethod::from_u16(r.read_u16_le().await?);
    let last_mod_time = r.read_u16_le().await?;
    let last_mod_date = r.read_u16_le().await?;
    let crc32 = r.read_u32_le().await?;
    let compressed_size = r.read_u32_le().await?;
    let uncompressed_size = r.read_u32_le().await?;
    let file_name_length = r.read_u16_le().await? as usize;
    let extra_field_length = r.read_u16_le().await? as usize;

    let mut file_name_raw = vec![0; file_name_length];
    reader.read_exact(&mut file_name_raw).await?;
    let mut extra_field = vec![0; extra_field_length];
    reader.read_exact(&mut extra_field).await?;

    let file_name = match is_utf8 {
        true => String::from_utf8_lossy(&*file_name_raw).into_owned(),
        false => file_name_raw.clone().from_cp437(),
    };

    let mut result = ZipFileData {
        system: System::from_u8((version_made_by >> 8) as u8),
        version_made_by: version_made_by as u8,
        encrypted,
        compression_method,
        last_modified_time: DateTime::from_msdos(last_mod_date, last_mod_time),
        crc32,
        compressed_size: compressed_size as u64,
        uncompressed_size: uncompressed_size as u64,
        file_name,
        file_name_raw,
        file_comment: String::new(), // file comment is only available in the central directory
        // header_start and data start are not available, but also don't matter, since seeking is
        // not available.
        header_start: 0,
        data_start: 0,
        central_header_start: 0,
        // The external_attributes field is only available in the central directory.
        // We set this to zero, which should be valid as the docs state 'If input came
        // from standard input, this field is set to zero.'
        external_attributes: 0,
    };

    match parse_extra_field(&mut result, &extra_field) {
        Ok(..) | Err(ZipError::Io(..)) => {}
        Err(e) => return Err(e),
    }

    if encrypted {
        return unsupported_zip_error("Encrypted files are not supported");
    }
    if using_data_descriptor {
        return unsupported_zip_error("The file length is not available in the local header");
    }

    let limit_reader =
        (Pin::new(reader) as Pin<&'a mut dyn AsyncRead>).take(result.compressed_size as u64);

    let result_crc32 = result.crc32;
    let result_compression_method = result.compression_method;
    let crypto_reader =
        make_crypto_reader_async(result_compression_method, result_crc32, limit_reader, None)
            .await?
            .unwrap();
    Ok(Some(AsyncZipFile {
        data: Cow::Owned(result),
        crypto_reader: None,
        reader: make_reader_async(result_compression_method, result_crc32, crypto_reader).await,
    }))
}

#[cfg(test)]
mod test {
    #[test]
    fn invalid_offset() {
        use super::ZipArchive;
        use std::io;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/invalid_offset.zip"));
        let reader = ZipArchive::new(io::Cursor::new(v));
        assert!(reader.is_err());
    }

    #[test]
    fn invalid_offset2() {
        use super::ZipArchive;
        use std::io;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/invalid_offset2.zip"));
        let reader = ZipArchive::new(io::Cursor::new(v));
        assert!(reader.is_err());
    }

    #[test]
    fn zip64_with_leading_junk() {
        use super::ZipArchive;
        use std::io;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/zip64_demo.zip"));
        let reader = ZipArchive::new(io::Cursor::new(v)).unwrap();
        assert!(reader.len() == 1);
    }

    #[test]
    fn zip_contents() {
        use super::ZipArchive;
        use std::io;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        let mut reader = ZipArchive::new(io::Cursor::new(v)).unwrap();
        assert!(reader.comment() == b"");
        assert_eq!(reader.by_index(0).unwrap().central_header_start(), 77);
    }

    #[test]
    fn zip_read_streaming() {
        use super::read_zipfile_from_stream;
        use std::io;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        let mut reader = io::Cursor::new(v);
        loop {
            match read_zipfile_from_stream(&mut reader).unwrap() {
                None => break,
                _ => (),
            }
        }
    }

    #[test]
    fn zip_clone() {
        use super::ZipArchive;
        use std::io::{self, Read};

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        let mut reader1 = ZipArchive::new(io::Cursor::new(v)).unwrap();
        let mut reader2 = reader1.clone();

        let mut file1 = reader1.by_index(0).unwrap();
        let mut file2 = reader2.by_index(0).unwrap();

        let t = file1.last_modified();
        assert_eq!(
            (
                t.year(),
                t.month(),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            ),
            (1980, 1, 1, 0, 0, 0)
        );

        let mut buf1 = [0; 5];
        let mut buf2 = [0; 5];
        let mut buf3 = [0; 5];
        let mut buf4 = [0; 5];

        file1.read(&mut buf1).unwrap();
        file2.read(&mut buf2).unwrap();
        file1.read(&mut buf3).unwrap();
        file2.read(&mut buf4).unwrap();

        assert_eq!(buf1, buf2);
        assert_eq!(buf3, buf4);
        assert!(buf1 != buf3);
    }

    #[test]
    fn file_and_dir_predicates() {
        use super::ZipArchive;
        use std::io;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/files_and_dirs.zip"));
        let mut zip = ZipArchive::new(io::Cursor::new(v)).unwrap();

        for i in 0..zip.len() {
            let zip_file = zip.by_index(i).unwrap();
            let full_name = zip_file.enclosed_name().unwrap();
            let file_name = full_name.file_name().unwrap().to_str().unwrap();
            assert!(
                (file_name.starts_with("dir") && zip_file.is_dir())
                    || (file_name.starts_with("file") && zip_file.is_file())
            );
        }
    }
}

#[cfg(all(test, feature = "async"))]
mod async_tests {
    use futures::{io::Cursor, AsyncReadExt};
    use futures_await_test::async_test;

    #[async_test]
    async fn async_contents() {
        use super::AsyncZipArchive;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        let mut cursor = Cursor::new(v);
        let mut reader = AsyncZipArchive::new(&mut cursor).await.unwrap();
        assert!(&mut reader.comment() == b"");
        assert_eq!(reader.by_index(0).await.unwrap().central_header_start(), 77);
    }

    #[async_test]
    async fn zip_read_streaming_async() {
        use super::read_zipfile_from_stream_async;

        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("../tests/data/mimetype.zip"));
        let mut reader = Cursor::new(v);
        loop {
            match read_zipfile_from_stream_async(&mut reader).await.unwrap() {
                None => break,
                f => {
                    let mut buf = Vec::new();
                    f.unwrap().read_to_end(&mut buf).await.unwrap();
                }
            }
        }
    }
}
