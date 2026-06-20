FROM archlinux:latest

RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm git base-devel && \
    useradd -mG wheel builder && \
    sh -c "echo 'builder ALL=(ALL:ALL) NOPASSWD: ALL' >> /etc/sudoers"

