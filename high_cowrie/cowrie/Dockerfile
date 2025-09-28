# high_cowrie/cowrie/Dockerfile - V2: Simplified and Robust

# Use a standard Debian base, as Cowrie requires many native libraries
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies (Python, Git, build tools, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev git build-essential \
    libssl-dev libffi-dev libpython3-dev libgmp-dev libsasl2-dev \
    libldap2-dev libpcap-dev wget ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated user, clone repository, and install requirements
RUN useradd -m -s /bin/bash cowrie
WORKDIR /home/cowrie
RUN git clone https://github.com/cowrie/cowrie.git /home/cowrie/cowrie
WORKDIR /home/cowrie/cowrie
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# --- CRITICAL: Copy Configs and Set Permissions ---
# ASSUMPTION: You have placed cowrie.cfg and userdb.txt in high_cowrie/cowrie/etc/
COPY etc/cowrie.cfg etc/
COPY etc/userdb.txt etc/
RUN chown -R cowrie:cowrie /home/cowrie
USER cowrie

# Set Cowrie Home environment
ENV COWRIE_HOME=/home/cowrie/cowrie
EXPOSE 2222 2323

# Final CMD: Run Cowrie using the repository's native start script with the system python
CMD ["/usr/bin/python3", "bin/cowrie", "start", "--nodaemon"]