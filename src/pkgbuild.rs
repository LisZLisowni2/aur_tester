use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn extract_allowed_domains<P: AsRef<Path>>(path: P) -> Result<HashSet<String>, io::Error> {
    let mut domains = HashSet::new();

    domains.insert("aur.archlinux.org".to_string());
    domains.insert("archlinux.org".to_string());
    domains.insert("github.com".to_string());
    domains.insert("codeload.github.com".to_string());
    domains.insert("raw.githubusercontent.com".to_string());
    domains.insert("gitlab.com".to_string());
    domains.insert("bitbucket.org".to_string());
    domains.insert("codeberg.org".to_string());

    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let url_regex = Regex::new(r"https?://([^/:\s]+)").unwrap();

    for line in reader.lines() {
        let line = line?;

        for cap in url_regex.captures_iter(&line) {
            if let Some(domain) = cap.get(1) {
                domains.insert(domain.as_str().to_string());
            }
        }
    }

    Ok(domains)
}