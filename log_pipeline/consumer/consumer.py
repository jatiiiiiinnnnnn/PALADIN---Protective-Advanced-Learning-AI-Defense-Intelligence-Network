import redis
import json
import sys
import time

REDIS_HOST = 'redis'
QUEUE_NAME = 'honeypot-logs'

def main():
    print("[*] Consumer script started.")
    
    # Connect to Redis with retry logic
    r = None
    while not r:
        try:
            print(f"[*] Attempting to connect to Redis at '{REDIS_HOST}'...")
            r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
            r.ping()  # Test connection
            print("[*] Redis connection successful!")
        except redis.ConnectionError:
            print("[🔥] Connection failed. Retrying in 5 seconds...")
            time.sleep(5)

    print(f"[*] Waiting for logs on queue '{QUEUE_NAME}'. To exit press CTRL+C")
    
    try:
        while True:
            # Pop from the Redis list (blocking pop with timeout)
            message = r.blpop(QUEUE_NAME, timeout=1) # type: ignore
            if message:
                print("\n [✅] Received Log:")
                try:
                    log_data = json.loads(message[1]) # type: ignore
                    print(json.dumps(log_data, indent=2))
                except Exception as e:
                    print(f"  [!] Error processing message: {e}")
                    print(f"  Raw message: {message[1]}") # type: ignore
                print("-" * 40)
                
    except KeyboardInterrupt:
        print("\n[👋] Stopping consumer.")
        sys.exit(0)
    except Exception as e:
        print(f"[🔥] An unexpected error occurred: {type(e).__name__} - {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()