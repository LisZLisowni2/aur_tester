mod sniffer;
mod aur_api;
mod command;

use std::collections::HashSet;
use std::process::Command;
use bollard::models::ContainerCreateBody;
use bollard::Docker;
use futures_util::{StreamExt, TryStreamExt};
use is_root::is_root;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(author = "LisZLisowni", version = "0.1.0", about = "A shelter for AUR packages", long_about = None)]
pub struct Cli {
    /// Name for AUR package
    package: String,

    /// Custom docker's interface name
    #[clap(short, long, default_value = "docker0")]
    interface: String,

    // /// Agresive mode: Instant destroy of container after unknown IP
    // #[arg(short, long, default_value_t = false)]
    // kill_on_alert: bool,

    /// Quiets the network's communicates
    #[clap(short, long, default_value_t = false)]
    quiet_network_allerts: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let cli = Cli::parse();

    if cli.package.is_empty() {
        eprintln!("[!] ERROR: package must not be empty");
        std::process::exit(1);
    }

    if !is_root() {
        eprintln!("[!] ERROR: You have no permission to operate!");
        eprintln!("    Use command with `sudo`");
        std::process::exit(1);
    }

    match Command::new("git").arg("--version").spawn() {
        Ok(mut child) => {
            let _ = child.kill();
        }
        Err(_) => {
            eprintln!("[!] ERROR: Git not found.");
            std::process::exit(1);
        }
    }

    let tmp_dir = format!("/tmp/aur_build_{}", &cli.package);
    println!("[-] Creating temporary directory at {}", tmp_dir);

    println!("[-] Connecting with AUR RPC API for package {}", &cli.package);
    let git_url = match aur_api::get_aur_git_url(&cli.package).await {
        Ok(url) => url,
        Err(e) => {
            eprintln!("[!] Error: {}", e);
            std::process::exit(1);
        }
    };

    Command::new("git")
        .args(&["clone", &git_url, &tmp_dir])
        .output()?;
    
    let mut allowed_domains = HashSet::new();

    allowed_domains.insert("aur.archlinux.org".to_string());
    allowed_domains.insert("archlinux.org".to_string());
    allowed_domains.insert("github.com".to_string());
    allowed_domains.insert("codeload.github.com".to_string());
    allowed_domains.insert("raw.githubusercontent.com".to_string());
    allowed_domains.insert("gitlab.com".to_string());
    allowed_domains.insert("bitbucket.org".to_string());
    allowed_domains.insert("codeberg.org".to_string());

    const IMAGE: &str = "archlinux:latest";

    let docker = Docker::connect_with_local_defaults()?;
    println!("[-] Connected with Docker.");

    docker.create_image(
        Some(
            bollard::query_parameters::CreateImageOptionsBuilder::default()
                .from_image(IMAGE)
                .build()
        ),
        None,
        None,
    )
        .try_collect::<Vec<_>>()
        .await?;

    println!("[+] Image created.");

    let archlinux_config = ContainerCreateBody {
        image: Some(String::from(IMAGE)),
        tty: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        ..Default::default()
    };

    let id = docker
        .create_container(
            None::<bollard::query_parameters::CreateContainerOptions>,
            archlinux_config
        )
        .await?
        .id;

    println!("[+] Container created.");

    docker.start_container(
        &id,
        None::<bollard::query_parameters::StartContainerOptions>,
    )
        .await?;

    println!("[+] Container started.");
    let url = format!("https://aur.archlinux.org/{}.git", cli.package);
    let path = format!("/home/builder/{}", cli.package);

    command::run_command_in_container(&docker, &id, "root", "/", vec!["pacman", "-Syu", "--noconfirm"]).await?;
    command::run_command_in_container(&docker, &id, "root", "/",vec!["pacman", "-S", "--noconfirm", "git", "base-devel"]).await?;
    command::run_command_in_container(&docker, &id, "root", "/", vec!["useradd", "-mG", "wheel", "builder"]).await?;
    command::run_command_in_container(&docker, &id, "root", "/",vec!["sh", "-c", "echo 'builder ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers"]).await?;
    command::run_command_in_container(&docker, &id, "builder", "/",vec!["git", "clone", &url, &path]).await?;

    let inspect = docker.inspect_container(&id, None).await?;
    let container_ip = inspect
        .network_settings
        .and_then(|ns| ns.networks)
        .and_then(|net| net.get("bridge").cloned())
        .and_then(|bridge| bridge.ip_address)
        .unwrap_or_else(|| "".to_string());

    if container_ip.is_empty() {
        panic!("[-] Container ip address is empty.");
    }
    println!("[+] Container ip address: {}", container_ip);
    let (kill_tx, mut kill_rx) = tokio::sync::mpsc::channel::<String>(100);

    let sniffer_handler = tokio::task::spawn_blocking(move || {
        if let Err(e) = sniffer::run_sniffer(&container_ip, &cli.interface, allowed_domains, kill_tx, &cli.quiet_network_allerts) {
            eprintln!("[-] Sniffer error: {}", e);
        }
    });

    println!("[+] Sniffer started.");

    tokio::select! {
        _ = kill_rx.recv() => {
            println!("[!!!] Kill container order received.");

            docker
                .remove_container(
                    &id,
                    Some(
                        bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                            .force(true)
                            .build(),
                    ),
                )
                .await?;

            std::process::exit(1);
        }

        build_result = command::run_command_in_container(&docker, &id, "builder", &path,vec!["makepkg", "-is", "--noconfirm"]) => {
            match build_result {
                Ok(_) => println!("[SUCCESS] Makepkg completed successfully without network violations."),
                Err(e) => println!("[-] Makepkg exited with error (or was interrupted): {}", e),
            }
        }
    }

    docker
        .remove_container(
            &id,
            Some(
                bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                    .force(true)
                    .build(),
            ),
        )
        .await?;

    println!("[+] Container removed.");
    sniffer_handler.abort();
    println!("[+] Sniffer stopped.");
    Ok(())
}