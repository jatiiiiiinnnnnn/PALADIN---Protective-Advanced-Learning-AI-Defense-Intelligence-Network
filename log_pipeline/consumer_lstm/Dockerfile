# Use a heavier Python image that supports TensorFlow
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required by TensorFlow and Scikit-Learn
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy your requirements first (for Docker caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your code and model files (.h5, .pkl)
COPY . .

# Run the live script
CMD ["python", "consumer_lstm.py"]