use std::path::{Path, PathBuf};

use walkdir::WalkDir;

pub fn find_iso_files(root: &Path) -> Vec<PathBuf> {
    let mut matches = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().eq_ignore_ascii_case("iso") {
                    matches.push(path.to_path_buf());
                }
            }
        }
    }

    matches
}
