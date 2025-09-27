FROM python:3.9-slim

# --- ADD THIS LINE ---
# This tells Python not to buffer print statements.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY consumer.py .

CMD ["python", "consumer.py"]