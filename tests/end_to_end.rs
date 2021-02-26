use std::collections::HashSet;
use std::io::prelude::*;
use std::io::{Cursor, Seek};
use std::iter::FromIterator;

#[cfg(feature = "async")]
use futures::AsyncReadExt;
#[cfg(feature = "async")]
use futures_await_test::async_test;

use zip::write::FileOptions;
use zip::CompressionMethod;

// This test asserts that after creating a zip file, then reading its contents back out,
// the extracted data will *always* be exactly the same as the original data.
#[test]
fn end_to_end() {
    let file = &mut Cursor::new(Vec::new());

    write_to_zip(file).expect("file written");

    check_zip_contents(file, ENTRY_NAME);
}

// This test asserts that after copying a `ZipFile` to a new `ZipWriter`, then reading its
// contents back out, the extracted data will *always* be exactly the same as the original data.
#[test]
fn copy() {
    let src_file = &mut Cursor::new(Vec::new());
    write_to_zip(src_file).expect("file written");

    let mut tgt_file = &mut Cursor::new(Vec::new());

    {
        let mut src_archive = zip::ZipArchive::new(src_file).unwrap();
        let mut zip = zip::ZipWriter::new(&mut tgt_file);

        {
            let file = src_archive.by_name(ENTRY_NAME).expect("file found");
            zip.raw_copy_file(file).unwrap();
        }

        {
            let file = src_archive.by_name(ENTRY_NAME).expect("file found");
            zip.raw_copy_file_rename(file, COPY_ENTRY_NAME).unwrap();
        }
    }

    let mut tgt_archive = zip::ZipArchive::new(tgt_file).unwrap();

    check_zip_file_contents(&mut tgt_archive, ENTRY_NAME);
    check_zip_file_contents(&mut tgt_archive, COPY_ENTRY_NAME);
}

#[cfg(feature = "async")]
#[async_test]
async fn async_end_to_end() {
    let mut file = Cursor::new(Vec::new());

    write_to_zip(&mut file).expect("file written");

    let position = file.position();
    let mut file = futures::io::Cursor::new(file.into_inner());
    file.set_position(position);

    let file_contents: String = read_zip_file_async(&mut file).await.unwrap();

    assert!(file_contents.as_bytes() == LOREM_IPSUM);
}

fn write_to_zip(file: &mut Cursor<Vec<u8>>) -> zip::result::ZipResult<()> {
    let mut zip = zip::ZipWriter::new(file);

    zip.add_directory("test/", Default::default())?;

    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o755);
    zip.start_file("test/☃.txt", options)?;
    zip.write_all(b"Hello, World!\n")?;

    zip.start_file(ENTRY_NAME, Default::default())?;
    zip.write_all(LOREM_IPSUM)?;

    zip.finish()?;
    Ok(())
}

fn read_zip<R: Read + Seek>(zip_file: R) -> zip::result::ZipResult<zip::ZipArchive<R>> {
    let archive = zip::ZipArchive::new(zip_file).unwrap();

    let expected_file_names = ["test/", "test/☃.txt", ENTRY_NAME];
    let expected_file_names = HashSet::from_iter(expected_file_names.iter().map(|&v| v));
    let file_names = archive.file_names().collect::<HashSet<_>>();
    assert_eq!(file_names, expected_file_names);

    Ok(archive)
}

fn read_zip_file<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    name: &str,
) -> zip::result::ZipResult<String> {
    let mut file = archive.by_name(name)?;

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    Ok(contents)
}

fn check_zip_contents(zip_file: &mut Cursor<Vec<u8>>, name: &str) {
    let mut archive = read_zip(zip_file).unwrap();
    check_zip_file_contents(&mut archive, name);
}

fn check_zip_file_contents<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, name: &str) {
    let file_contents: String = read_zip_file(archive, name).unwrap();
    assert!(file_contents.as_bytes() == LOREM_IPSUM);
}

#[cfg(feature = "async")]
async fn read_zip_file_async(
    zip_file: &mut futures::io::Cursor<Vec<u8>>,
) -> zip::result::ZipResult<String> {
    let mut archive = zip::AsyncZipArchive::new(zip_file).await.unwrap();

    let expected_file_names = ["test/", "test/☃.txt", "test/lorem_ipsum.txt"];
    let expected_file_names = HashSet::from_iter(expected_file_names.iter().map(|&v| v));
    let file_names = archive.file_names().collect::<HashSet<_>>();
    assert_eq!(file_names, expected_file_names);

    let mut file = archive.by_name("test/lorem_ipsum.txt").await?;

    let mut contents = String::new();
    file.read_to_string(&mut contents).await.unwrap();
    Ok(contents)
}

const LOREM_IPSUM : &'static [u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. In tellus elit, tristique vitae mattis egestas, ultricies vitae risus. Quisque sit amet quam ut urna aliquet
molestie. Proin blandit ornare dui, a tempor nisl accumsan in. Praesent a consequat felis. Morbi metus diam, auctor in auctor vel, feugiat id odio. Curabitur ex ex,
dictum quis auctor quis, suscipit id lorem. Aliquam vestibulum dolor nec enim vehicula, porta tristique augue tincidunt. Vivamus ut gravida est. Sed pellentesque, dolor
vitae tristique consectetur, neque lectus pulvinar dui, sed feugiat purus diam id lectus. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per
inceptos himenaeos. Maecenas feugiat velit in ex ultrices scelerisque id id neque.
";

const ENTRY_NAME: &str = "test/lorem_ipsum.txt";

const COPY_ENTRY_NAME: &str = "test/lorem_ipsum_renamed.txt";
