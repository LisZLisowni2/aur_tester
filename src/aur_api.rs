use std::fmt::format;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AurPackageDetails {
    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "URLPath")]
    url_path: String,
}

#[derive(Debug, Deserialize)]
struct AurResponse {
    results: Vec<AurPackageDetails>
}

async fn get_aur_git_url(package_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("https://aur.archlinux.org/rpc/?v=5&type=info&arg={}", package_name);

    let response: AurResponse = reqwest::get(&url)
        .await?
        .json()
        .await?;

    if response.results.is_empty() {
        return Err(format!("Package {} not found", package_name).into());
    }

    let git_url = format!("https://aur.archlinux.org/{}.git", response.results[0].name);
    Ok(git_url)
}