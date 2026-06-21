#[cfg(test)]
mod integration_tests {
    use std::collections::HashSet;
    use tokio::sync::mpsc;
    use bollard::config::ContainerCreateBody;
    use futures_util::TryStreamExt;
    use aur_tester::{command, sniffer};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    async fn create_test_image(docker: &bollard::Docker, image: &str) -> Option<String> {
        docker.create_image(
            Some(
                bollard::query_parameters::CreateImageOptionsBuilder::default()
                    .from_image(image)
                    .build()
            ),
            None,
            None,
        )
            .try_collect::<Vec<_>>()
            .await
            .unwrap();

        let archlinux_config = ContainerCreateBody {
            image: Some(String::from(image)),
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

        docker.start_container(
            &id,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
            .await
            .unwrap();

        Some(id)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_sniffer_detects_unauthorized_domain() {
        const IMAGE: &str = "liszlisowni/test-archlinux:latest";
        
        let mut allowed_domains = HashSet::new();
        let mut suspicious_domains = HashSet::new();

        allowed_domains.insert("aur.archlinux.org".to_string());
        allowed_domains.insert("archlinux.org".to_string());
        allowed_domains.insert("github.com".to_string());
        allowed_domains.insert("codeload.github.com".to_string());
        allowed_domains.insert("raw.githubusercontent.com".to_string());
        allowed_domains.insert("gitlab.com".to_string());
        allowed_domains.insert("bitbucket.org".to_string());
        allowed_domains.insert("codeberg.org".to_string());

        let (signal_tx, mut signal_rx) = mpsc::unbounded_channel();

        let interface = "docker0";

        let docker = bollard::Docker::connect_with_local_defaults().unwrap();
        let content = r#"
pkgname=yay
pkgver=13.0.1
pkgrel=1
arch=('any')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/Jguer/yay/archive/v${pkgver}.tar.gz")
sha256sums=('SKIP')
package() {
    curl -s https://www.wikipedia.org > /dev/null
}
build() {
    curl -s https://www.wikipedia.org > /dev/null
}
prepare() {
    curl -s https://www.wikipedia.org > /dev/null
}
        "#;

        let cat_content = format!(
            "printf '%s' '{}' > PKGBUILD", content
        );

        let id = create_test_image(&docker, IMAGE).await.unwrap();
        command::run_command_in_container(&docker, &id, "builder", "/home/builder",vec!["mkdir", "aur_fake"]).await.unwrap();
        command::run_command_in_container(&docker, &id, "builder", "/home/builder/aur_fake",vec!["sh", "-c", &cat_content]).await.unwrap();

        let inspect = docker.inspect_container(&id, None).await.unwrap();

        let container_ip = inspect.network_settings.unwrap().networks.unwrap().get("bridge").unwrap().ip_address.clone().unwrap();
        let is_quiet = false;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let ip_clone = container_ip.clone();
        let sniffer_handle = tokio::task::spawn_blocking(move || {
            sniffer::run_sniffer(&ip_clone, interface, allowed_domains, &is_quiet, signal_tx, stop_flag_clone).unwrap();
        });

        let build_fut = command::run_command_in_container(&docker, &id, "builder", "/home/builder/aur_fake", vec!["makepkg", "-is", "--noconfirm"]);

        tokio::pin!(build_fut);

        let build_result = loop {
            tokio::select! {
                message = signal_rx.recv() => {
                    match message {
                        Some(domain) => {
                            if !is_quiet { println!("[-] Signal received") };
                            suspicious_domains.insert(domain);
                        }
                        None => {

                        }
                    }
                }
                result = &mut build_fut => {
                    break result;
                }
            }
        };

        match build_result {
            Ok(_) => println!("[SUCCESS] Makepkg completed successfully."),
            Err(e) => println!("[-] Makepkg exited with error (or was interrupted): {}", e),
        }

        let _ = docker.remove_container(&id, Some(bollard::query_parameters::RemoveContainerOptions { force: true, ..Default::default() })).await;
        stop_flag.store(true, Ordering::Relaxed);
        sniffer_handle.await.unwrap();

        assert!(suspicious_domains.contains("dyna.wikimedia.org"), "Sniffer doesn't detect connection to wikipedia.org!");
    }
}
