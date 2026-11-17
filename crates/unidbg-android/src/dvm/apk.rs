use std::io::Read;
use std::path::{Path, PathBuf};
use unidbg_api::arm::Arch;
use unidbg_api::error::{Result, UnidbgError};
use unidbg_api::spi::LibraryFile;
use zip::ZipArchive;

/// Loads native `.so` libraries directly from an Android `.apk` archive (`ApkLibraryFile`).
pub struct ApkLibraryFile {
    apk_path: PathBuf,
    so_name: String,
    abi_dir: String,
}

impl ApkLibraryFile {
    pub fn new(apk_path: impl AsRef<Path>, so_name: impl Into<String>, arch: Arch) -> Self {
        let abi_dir = match arch {
            Arch::Arm32 => "armeabi-v7a".to_string(),
            Arch::Arm64 => "arm64-v8a".to_string(),
        };
        Self {
            apk_path: apk_path.as_ref().to_path_buf(),
            so_name: so_name.into(),
            abi_dir,
        }
    }

    pub fn entry_path(&self) -> String {
        format!("lib/{}/{}", self.abi_dir, self.so_name)
    }

    pub fn read_manifest(&self) -> Result<Vec<u8>> {
        self.read_entry("AndroidManifest.xml")
    }

    pub fn list_libraries(&self) -> Result<Vec<String>> {
        let file = std::fs::File::open(&self.apk_path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| UnidbgError::ElfLoad(format!("open apk {}: {e}", self.apk_path.display())))?;
        let prefix = format!("lib/{}/", self.abi_dir);
        let mut libs = Vec::new();
        for i in 0..archive.len() {
            if let Ok(f) = archive.by_index(i) {
                if let Some(name) = f.name().strip_prefix(&prefix) {
                    if name.ends_with(".so") {
                        libs.push(name.to_string());
                    }
                }
            }
        }
        Ok(libs)
    }

    pub fn read_entry(&self, entry_name: &str) -> Result<Vec<u8>> {
        let file = std::fs::File::open(&self.apk_path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| UnidbgError::ElfLoad(format!("open apk {}: {e}", self.apk_path.display())))?;
        let mut entry = archive.by_name(entry_name).map_err(|e| {
            UnidbgError::ElfLoad(format!("apk entry {entry_name} not found: {e}"))
        })?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        Ok(buf)
    }
}

impl LibraryFile for ApkLibraryFile {
    fn name(&self) -> &str {
        &self.so_name
    }

    fn read_bytes(&self) -> Result<Vec<u8>> {
        self.read_entry(&self.entry_path())
    }

    fn resolve_library(&self, so_name: &str) -> Option<Box<dyn LibraryFile>> {
        let candidate = ApkLibraryFile {
            apk_path: self.apk_path.clone(),
            so_name: so_name.to_string(),
            abi_dir: self.abi_dir.clone(),
        };
        if candidate.read_bytes().is_ok() {
            Some(Box::new(candidate))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    #[test]
    fn apk_library_file_reads_so_from_zip() {
        let tmp_dir = std::env::temp_dir();
        let apk_path = tmp_dir.join("unidbg_rs_test_dummy.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            zip.start_file("lib/arm64-v8a/libdemo.so", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"\x7fELFdummy").unwrap();
            zip.finish().unwrap();
        }

        let lib = ApkLibraryFile::new(&apk_path, "libdemo.so", Arch::Arm64);
        assert_eq!(lib.read_bytes().unwrap(), b"\x7fELFdummy");
        let _ = std::fs::remove_file(&apk_path);
    }
}
