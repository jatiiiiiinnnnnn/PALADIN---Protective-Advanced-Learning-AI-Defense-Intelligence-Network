# Use the official, standard Filebeat image as a base
FROM docker.elastic.co/beats/filebeat:8.4.1

# Copy your custom configuration file into the container
COPY filebeat.yml /usr/share/filebeat/filebeat.yml

# Set the user to root to avoid permission issues when reading the config
USER root

RUN chmod go-w /usr/share/filebeat/filebeat.yml

# Run Filebeat as the default command
CMD ["-e", "-c", "/usr/share/filebeat/filebeat.yml"]