use std::collections::HashMap;
use bollard::models::ContainerCreateBody;
use bollard::Docker;

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

    run_command_in_container(&docker, &id, vec!["pacman", "-Syu", "--noconfirm"]).await?;
    run_command_in_container(&docker, &id, vec!["pacman", "-S", ""]).await?;

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
    Ok(())
}

/// Execute a command inside a running container and stream its output.
async fn run_command_in_container(
    docker: &Docker,
    container_id: &str,
    cmd: Vec<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let exec_config = CreateExecOptions {
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        cmd: Some(cmd),
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
