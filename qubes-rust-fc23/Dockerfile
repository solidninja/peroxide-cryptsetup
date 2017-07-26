FROM fedora:23

# Install RPM build system
RUN dnf -y upgrade
RUN dnf -y install @"Minimal Install" @buildsys-build yum-utils rpm-sign gnupg

# Install rust (latest stable)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
