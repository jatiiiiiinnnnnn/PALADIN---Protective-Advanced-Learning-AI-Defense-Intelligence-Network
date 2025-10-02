# Use a standard Debian base that we control completely.
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install all necessary dependencies including virtualenv
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev python3-venv git build-essential \
    libssl-dev libffi-dev libpython3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create the user first
RUN useradd -m -s /bin/bash cowrie

# Switch to cowrie user and set up everything
USER cowrie
WORKDIR /home/cowrie

# Clone Cowrie repository
RUN git clone https://github.com/cowrie/cowrie.git

# Move into the cowrie directory
WORKDIR /home/cowrie/cowrie

# Create virtual environment and install dependencies
RUN python3 -m venv cowrie-env && \
    . cowrie-env/bin/activate && \
    pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install -e . && \
    python -c "import twisted.plugin; list(twisted.plugin.getPlugins(twisted.plugin.IPlugin))"

# Create the shared logs directory (as cowrie user)
USER root
RUN mkdir -p /shared_logs && chown -R cowrie:cowrie /shared_logs
USER cowrie

# Copy our custom configuration
COPY --chown=cowrie:cowrie etc/cowrie.cfg etc/cowrie.cfg

# Switch to root to create and set permissions for shared logs
USER root

# Create the shared logs directory and set proper ownership
# CRITICAL: Remove any existing file and create fresh directory structure
RUN rm -f /shared_logs/cowrie.json && \
    mkdir -p /shared_logs && \
    chown -R cowrie:cowrie /shared_logs && \
    chmod -R 755 /shared_logs

# Switch back to cowrie user
USER cowrie

# Create a startup script that properly initializes Cowrie
RUN echo '#!/bin/bash\n\
cd /home/cowrie/cowrie\n\
export PYTHONPATH=/home/cowrie/cowrie/src:$PYTHONPATH\n\
exec /home/cowrie/cowrie/cowrie-env/bin/python -m twisted cowrie' > /home/cowrie/start.sh && \
    chmod +x /home/cowrie/start.sh

# Set the default command - run our startup script
CMD ["/bin/bash", "/home/cowrie/start.sh"]