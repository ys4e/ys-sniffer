use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Read a file from a file path.
/// file_path: The path to the file.
pub fn read_file(file_path: &Path) -> std::io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Write a file from a string.
/// file_path: The path to the file.
pub fn write_file(file_path: &Path, content: String) -> std::io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}