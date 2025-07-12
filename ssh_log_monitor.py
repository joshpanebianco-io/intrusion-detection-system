import time
import re

LOG_FILE = "/var/log/auth.log"
ALERT_LOG = "ssh_login_alerts.log"  # Log file in current directory
SUCCESS_PATTERN = re.compile(r'Accepted password for (\w+) from ([\d\.]+)')

def monitor_ssh_log():
    with open(LOG_FILE, "r") as f, open(ALERT_LOG, "a") as alert_file:
        f.seek(0, 2)  # Go to end of auth.log

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            match = SUCCESS_PATTERN.search(line)
            if match:
                user, ip = match.groups()
                alert_msg = f"[ALERT] SSH LOGIN SUCCESS: User '{user}' logged in from IP {ip}\n"
                alert_file.write(alert_msg)
                alert_file.flush()  # Ensure it's written immediately
                print(alert_msg, end='')  # Optional: still print to console

if __name__ == "__main__":
    monitor_ssh_log()