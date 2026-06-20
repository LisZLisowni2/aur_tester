#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::fs::{self, File};
    use std::io::Write;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;
    use std::time::Duration;
    use bollard::config::ContainerCreateBody;
    use futures_util::TryStreamExt;
    use aur_tester::{command, sniffer};

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
//
//     fn setup_malicious_pkgbuild(dir_path: &str) -> std::io::Result<()> {
//         fs::create_dir_all(dir_path)?;
//         let file_path = format!("{}/PKGBUILD", dir_path);
//         let mut file = File::create(file_path)?;
//
//         let content = r#"
// pkgname=test-malware
// pkgver=1.0.0
// pkgrel=1
// arch=('any')
// source=("https://github.com/archlinux/yay")
// sha256sums=('SKIP')
//
// prepare() {
//     curl -s https://www.wikipedia.org > /dev/null
// }
// "#;
//         file.write_all(content.as_bytes())?;
//         Ok(())
//     }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_sniffer_detects_unauthorized_domain() {
        const IMAGE: &str = "archlinux:latest";

        // let test_dir = "/tmp/aur_test_malware";

        // setup_malicious_pkgbuild(test_dir).expect("Could not setup malware");
        //
        // let pkgbuild_path = format!("{}/PKGBUILD", test_dir);
        let mut allowed_domains = HashSet::new();

        allowed_domains.insert("aur.archlinux.org".to_string());
        allowed_domains.insert("archlinux.org".to_string());
        allowed_domains.insert("github.com".to_string());
        allowed_domains.insert("codeload.github.com".to_string());
        allowed_domains.insert("raw.githubusercontent.com".to_string());
        allowed_domains.insert("gitlab.com".to_string());
        allowed_domains.insert("bitbucket.org".to_string());
        allowed_domains.insert("codeberg.org".to_string());

        let (kill_tx, mut kill_rx) = mpsc::channel::<String>(100);

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
        command::run_command_in_container(&docker, &id, "root", "/", vec!["pacman", "-Syu", "--noconfirm"]).await.unwrap();
        command::run_command_in_container(&docker, &id, "root", "/", vec!["pacman", "-S", "--noconfirm", "git", "base-devel"]).await.unwrap();
        command::run_command_in_container(&docker, &id, "root", "/", vec!["useradd", "-mG", "wheel", "builder"]).await.unwrap();
        command::run_command_in_container(&docker, &id, "root", "/",vec!["sh", "-c", "echo 'builder ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers"]).await.unwrap();
        command::run_command_in_container(&docker, &id, "builder", "/home/builder",vec!["mkdir", "aur_fake"]).await.unwrap();
        command::run_command_in_container(&docker, &id, "builder", "/home/builder/aur_fake",vec!["sh", "-c", &cat_content]).await.unwrap();

        let inspect = docker.inspect_container(&id, None).await.unwrap();

        let container_ip = inspect.network_settings.unwrap().networks.unwrap().get("bridge").unwrap().ip_address.clone().unwrap();
        let is_quiet = false;

        let ip_clone = container_ip.clone();
        let sniffer_handle = tokio::task::spawn_blocking(move || {
            sniffer::run_sniffer(&ip_clone, interface, allowed_domains, kill_tx, &is_quiet).unwrap();
        });

        let test_result = tokio::select! {
            Some(_) = kill_rx.recv() => {
                true
            }
            _ = command::run_command_in_container(&docker, &id, "builder", "/home/builder/aur_fake", vec!["makepkg", "-is", "--noconfirm"]) => {
                false
            }
        };

        let _ = docker.remove_container(&id, Some(bollard::query_parameters::RemoveContainerOptions { force: true, ..Default::default() })).await;
        sniffer_handle.abort();
        // let _ = fs::remove_dir_all(test_dir);

        assert!(test_result, "Sniffer doesn't detect connection to wikipedia.org!");
    }
}
