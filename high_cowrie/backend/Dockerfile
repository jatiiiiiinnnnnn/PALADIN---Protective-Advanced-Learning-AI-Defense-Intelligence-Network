# high_cowrie/backend/Dockerfile
FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sudo curl wget procps net-tools iproute2 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create a low-privilege attacker user
RUN useradd -m -s /bin/bash pwnme && echo "pwnme:Password123!" | chpasswd && adduser pwnme sudo

RUN mkdir -p /var/run/sshd
# allow SSH logins for non-root; keep root disabled
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
