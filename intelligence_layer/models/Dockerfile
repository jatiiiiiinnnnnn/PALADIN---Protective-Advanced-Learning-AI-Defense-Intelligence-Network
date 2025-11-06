# Replace python:3.10-slim with TensorFlow image
FROM tensorflow/tensorflow:2.14.0

WORKDIR /app

# Copy requirements if needed
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all files
COPY . .

# Command to run tests
CMD ["python", "test_models.py"]
