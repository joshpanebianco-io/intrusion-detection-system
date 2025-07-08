# utils/logger.py
import logging
from datetime import datetime

logging.basicConfig(
    filename='alerts.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def alert(message):
    timestamp = datetime.now().strftime('%H:%M:%S')
    full_message = f"[{timestamp}] {message}"
    print(f"\033[91m{full_message}\033[0m")  # Red terminal text
    logging.info(message)
