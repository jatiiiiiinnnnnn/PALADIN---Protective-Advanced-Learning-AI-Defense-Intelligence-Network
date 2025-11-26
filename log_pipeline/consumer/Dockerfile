FROM python:3.9-slim

FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application files
COPY consumer.py .
COPY train_model.py .

# Copy training scripts and ensemble
COPY training/ ./training/

# Copy models directories (will be populated during training)
COPY models/ ./models/
RUN mkdir -p ./models/supervised ./models/unsupervised

# Create data directory
RUN mkdir -p /app/data/cic_ids_2017/raw /app/data/cic_ids_2017/processed

CMD ["python", "consumer.py"]