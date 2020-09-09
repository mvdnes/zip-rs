use std::collections::HashSet;
use std::io::prelude::*;
use std::io::Cursor;
use std::iter::FromIterator;
use zip::write::FileOptions;

// This test asserts that after creating a zip file, then reading its contents back out,
// the extracted data will *always* be exactly the same as the original data.
#[test]
fn end_to_end() {
    let file = &mut Cursor::new(Vec::new());

    write_to_zip_file(file).expect("file written");

    let file_contents: String = read_zip_file(file).unwrap();

    assert!(file_contents.as_bytes() == LOREM_IPSUM);
}

fn write_to_zip_file(file: &mut Cursor<Vec<u8>>) -> zip::result::ZipResult<()> {
    let mut zip = zip::ZipWriter::new(file);

    zip.add_directory("test/", Default::default())?;

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);
    zip.start_file("test/☃.txt", options)?;
    zip.write_all(b"Hello, World!\n")?;

    zip.start_file("test/lorem_ipsum.txt", Default::default())?;
    zip.write_all(LOREM_IPSUM)?;

    zip.finish()?;
    Ok(())
}

fn read_zip_file(zip_file: &mut Cursor<Vec<u8>>) -> zip::result::ZipResult<String> {
    let mut archive = zip::ZipArchive::new(zip_file).unwrap();

    let expected_file_names = ["test/", "test/☃.txt", "test/lorem_ipsum.txt"];
    let expected_file_names = HashSet::from_iter(expected_file_names.iter().map(|&v| v));
    let file_names = archive.file_names().collect::<HashSet<_>>();
    assert_eq!(file_names, expected_file_names);

    let mut file = archive.by_name("test/lorem_ipsum.txt")?.unwrap();

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    Ok(contents)
}

const LOREM_IPSUM : &'static [u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. In tellus elit, tristique vitae mattis egestas, ultricies vitae risus. Quisque sit amet quam ut urna aliquet
molestie. Proin blandit ornare dui, a tempor nisl accumsan in. Praesent a consequat felis. Morbi metus diam, auctor in auctor vel, feugiat id odio. Curabitur ex ex,
dictum quis auctor quis, suscipit id lorem. Aliquam vestibulum dolor nec enim vehicula, porta tristique augue tincidunt. Vivamus ut gravida est. Sed pellentesque, dolor
vitae tristique consectetur, neque lectus pulvinar dui, sed feugiat purus diam id lectus. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per
inceptos himenaeos. Maecenas feugiat velit in ex ultrices scelerisque id id neque.
";
