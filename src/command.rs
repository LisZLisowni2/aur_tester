use bollard::container::LogOutput;
use bollard::Docker;
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures_util::{StreamExt};

/// Execute a command inside a running container and stream its output.
pub async fn run_command_in_container(
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