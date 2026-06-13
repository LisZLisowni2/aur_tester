use std::collections::HashMap;
use bollard::models::ContainerCreateBody;
use bollard::Docker;

use futures_util::{StreamExt, TryStreamExt};
use std::io::{stdout, Read, Write};
use std::time::Duration;
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecResults};
#[cfg(not(windows))]
use termion::async_stdin;
#[cfg(not(windows))]
use termion::raw::IntoRawMode;
use tokio::io::AsyncWriteExt;
use tokio::task::spawn;
use tokio::time::sleep;

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
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        open_stdin: Some(true),
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

    #[cfg(not(windows))]
    {
        let bollard::container::AttachContainerResults {
            mut output,
            mut input,
        } = docker
            .attach_container(
                &id,
                Some(
                    bollard::query_parameters::AttachContainerOptionsBuilder::default()
                        .stdout(true)
                        .stderr(true)
                        .stdin(true)
                        .stream(true)
                        .build(),
                ),
            )
            .await?;

        // pipe stdin into the docker attach stream input
        spawn(async move {
            #[allow(clippy::unbuffered_bytes)]
            let mut stdin = async_stdin().bytes();
            loop {
                if let Some(Ok(byte)) = stdin.next() {
                    input.write_all(&[byte]).await.ok();
                } else {
                    sleep(Duration::from_nanos(10)).await;
                }
            }
        });

        // set stdout in raw mode so we can do tty stuff
        let stdout = stdout();
        let mut stdout = stdout.lock().into_raw_mode()?;

        // pipe docker attach output into stdout
        while let Some(Ok(output)) = output.next().await {
            stdout.write_all(output.into_bytes().as_ref())?;
            stdout.flush()?;
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

    Ok(())
}

// /// Execute a command inside a running container and stream its output.
// async fn run_command_in_container(
//     docker: &Docker,
//     container_id: &str,
//     cmd: Vec<&str>,
//     user: &str,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     // bollard 0.20+ CreateExecOptions lives in bollard::exec (not bollard::container)
//     let exec_config = CreateExecOptions {
//         attach_stdout: Some(true),
//         attach_stderr: Some(true),
//         user: Some(user),
//         cmd: Some(cmd),
//         ..Default::default()
//     };
//
//     let exec = docker.create_exec(container_id, exec_config).await?;
//
//     // start_exec now returns StartExecResults which is an enum over Attached / Detached
//     if let StartExecResults::Attached { mut output, .. } =
//         docker.start_exec(&exec.id, None).await?
//     {
//         while let Some(msg) = output.next().await {
//             match msg? {
//                 LogOutput::StdOut { message } => print!("{}", String::from_utf8_lossy(&message)),
//                 LogOutput::StdErr { message } => eprint!("{}", String::from_utf8_lossy(&message)),
//                 _ => {}
//             }
//         }
//     }
//
//     Ok(())
// }
