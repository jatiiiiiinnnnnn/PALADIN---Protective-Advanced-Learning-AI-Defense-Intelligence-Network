# Use a lightweight Python base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy all the honeypot scripts into the container
COPY *.py ./

# This Dockerfile is generic. The command to run the specific
# script (e.g., http.py or ftp.py) will be provided in the docker-compose.yml file.