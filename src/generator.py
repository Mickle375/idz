import random
from faker import Faker

fake = Faker()


def generate_syslog(filename, count=1000):
    processes = ["sshd", "sudo", "cron", "kernel"]
    messages = [
        "Failed password for root",
        "Accepted password for",
        "Failed password for admin",
        "COMMAND=/bin/bash",
        "session opened for user"
    ]

    with open(filename, 'w') as f:
        for _ in range(count):
            timestamp = fake.date_time_this_month().strftime("%b %d %H:%M:%S")
            host = "server"
            process = random.choice(processes)
            msg_base = random.choice(messages)

            ip = fake.ipv4()
            line = f"{timestamp} {host} {process}[{random.randint(1000, 9999)}]: {msg_base} from {ip}\n"
            f.write(line)


generate_syslog("data/syslog.log")
print("Файл data/syslog.log успешно создан!")