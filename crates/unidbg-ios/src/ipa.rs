use std::io::Read;
use std::path::{Path, PathBuf};
use unidbg_api::error::{Result, UnidbgError};
use zip::ZipArchive;

/// Loads Info.plist and main Mach-O executable from an iOS `.ipa` archive (`IpaLoader`).
pub struct IpaLoader {
    ipa_path: PathBuf,
}

impl IpaLoader {
    pub fn new(ipa_path: impl AsRef<Path>) -> Self {
        Self {
            ipa_path: ipa_path.as_ref().to_path_buf(),
        }
    }

    pub fn read_info_plist(&self) -> Result<plist::Dictionary> {
        let file = std::fs::File::open(&self.ipa_path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| UnidbgError::ElfLoad(format!("open ipa: {e}")))?;

        let mut plist_entry_name = None;
        for i in 0..archive.len() {
            if let Ok(f) = archive.by_index(i) {
                let n = f.name();
                if n.starts_with("Payload/") && n.ends_with(".app/Info.plist") {
                    plist_entry_name = Some(n.to_string());
                    break;
                }
            }
        }
        let entry_name = plist_entry_name
            .ok_or_else(|| UnidbgError::ElfLoad("Info.plist not found in ipa".into()))?;
        let mut entry = archive
            .by_name(&entry_name)
            .map_err(|e| UnidbgError::ElfLoad(format!("read {entry_name}: {e}")))?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        let val = plist::Value::from_reader(std::io::Cursor::new(&bytes))
            .map_err(|e| UnidbgError::ElfLoad(format!("parse plist: {e}")))?;
        val.into_dictionary()
            .ok_or_else(|| UnidbgError::ElfLoad("Info.plist root is not a dictionary".into()))
    }
}
