pub mod sniffer;

use std::collections::HashMap;
use bollard::models::ContainerCreateBody;
use bollard::Docker;
use pcap::Capture;

use futures_util::{StreamExt, TryStreamExt};
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecResults};

const IMAGE: &str = "archlinux:latest";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let docker = Docker::connect_with_local_defaults().unwrap();
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
        .await
        .unwrap();

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
        .await
        .unwrap()
        .id;

    println!("[+] Container created.");

    docker.start_container(
        &id,
        None::<bollard::query_parameters::StartContainerOptions>,
    )
        .await
        .unwrap();

    println!("[+] Container started.");

    run_command_in_container(&docker, &id, "root", "/", vec!["pacman", "-Syu", "--noconfirm"]).await?;
    run_command_in_container(&docker, &id, "root", "/",vec!["pacman", "-S", "--noconfirm", "git", "base-devel"]).await?;
    run_command_in_container(&docker, &id, "root", "/", vec!["useradd", "-mG", "wheel", "builder"]).await?;
    run_command_in_container(&docker, &id, "root", "/",vec!["echo \"builder ALL=(ALL:ALL) NOPASSWD: ALL\" >> /etc/sudoers"]).await?;
    run_command_in_container(&docker, &id, "builder", "/",vec!["git", "clone", "https://aur.archlinux.org/yay.git", "/home/builder/yay"]).await?;

    let inspect = docker.inspect_container(&id, None).await.unwrap();
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

    let ip_clone = container_ip.clone();
    let sniffer_handler = tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::sniffer::run_sniffer(&container_ip) {
            eprintln!("[-] Sniffer error: {}", e);
        }
    });

    println!("[+] Sniffer started.");
    run_command_in_container(&docker, &id, "builder", "/home/builder/yay/",vec!["makepkg", "-isS"]).await?;

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
