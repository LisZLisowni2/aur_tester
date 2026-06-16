pub mod sniffer;

use bollard::models::ContainerCreateBody;
use bollard::Docker;
use futures_util::{StreamExt, TryStreamExt};
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecResults};
use is_root::is_root;

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(author = "LisZLisowni", version = "0.1.0", about = "A shelter for AUR packages", long_about = None)]
pub struct Cli {
    /// Name for AUR package
    package: String,

    /// Custom docker's interface name
    #[clap(short, long, default_value = "docker0")]
    interface: String,

    /// Agresive mode: Instant destroy of container after unknown IP
    #[arg(short, long, default_value_t = false)]
    kill_on_alert: bool,
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

    run_command_in_container(&docker, &id, "root", "/", vec!["pacman", "-Syu", "--noconfirm"]).await?;
    run_command_in_container(&docker, &id, "root", "/",vec!["pacman", "-S", "--noconfirm", "git", "base-devel"]).await?;
    run_command_in_container(&docker, &id, "root", "/", vec!["useradd", "-mG", "wheel", "builder"]).await?;
    run_command_in_container(&docker, &id, "root", "/",vec!["echo \"builder ALL=(ALL:ALL) NOPASSWD: ALL\" >> /etc/sudoers"]).await?;
    run_command_in_container(&docker, &id, "builder", "/",vec!["git", "clone", &url, &path]).await?;

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

    let sniffer_handler = tokio::task::spawn_blocking(move || {
        if let Err(e) = sniffer::run_sniffer(&container_ip) {
            eprintln!("[-] Sniffer error: {}", e);
        }
    });

    println!("[+] Sniffer started.");
    run_command_in_container(&docker, &id, "builder", &path,vec!["makepkg", "-isS"]).await?;

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

/// Execute a command inside a running container and stream its output.
async fn run_command_in_container(
    docker: &Docker,
    container_id: &str,
    user: &str,
    working_dir: &str,
    cmd: Vec<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let exec_config = CreateExecOptions {
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        user: Some(user),
        cmd: Some(cmd),
        working_dir: Some(working_dir),
        ..Default::default()
    };

    let exec = docker.create_exec(container_id, exec_config).await?;

    // start_exec now returns StartExecResults which is an enum over Attached / Detached
    if let StartExecResults::Attached { mut output, .. } =
        docker.start_exec(&exec.id, None).await?
    {
        while let Some(msg) = output.next().await {
            match msg? {
                LogOutput::StdOut { message } => print!("{}", String::from_utf8_lossy(&message)),
                LogOutput::StdErr { message } => eprint!("{}", String::from_utf8_lossy(&message)),
                _ => {}
            }
        }
    }

    Ok(())
}
