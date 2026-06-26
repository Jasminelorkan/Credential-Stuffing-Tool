import random
from datetime import datetime,timedelta

method= "POST"
endpoints = ["GET /home", "GET /about", "GET /dashboard", "POST /login", "GET /products"]
status= 401
log_lines=[]

# === 500 Normal Traffic Lines ===
for i in range(500):
    start = datetime(2023, 10, 10, 13, 0, 0) 
    offset = timedelta(seconds=random.randint(0, 3600))
    timestamp= start + offset
    endpoint = random.choice(endpoints)
    ip= f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
    if endpoint == "POST /login":
        status = random.choice([401, 401, 401, 401, 200])  
    else:
        status = 200
    line = f'{ip} - - {timestamp.strftime("%Y-%m-%d %H:%M:%S")} "{endpoint} HTTP/1.1" {status} 512'
    log_lines.append(line)

# === 180 Attack Lines ===
for i in range(180):
    start = datetime(2023, 10, 10, 13, 0, 0) 
    offset = timedelta(seconds=random.randint(0, 600))
    timestamp= start + offset
    status = random.choices([401, 200], weights=[97, 3])[0]
    ip= f'91.108.{random.randint(1, 255)}.{random.randint(1, 255)}'
    line = f'{ip} - - {timestamp.strftime("%Y-%m-%d %H:%M:%S")} "POST /login HTTP/1.1" {status} 512'
    log_lines.append(line)

log_lines.sort()
 

with open("access.log","w")as file:
    for line in log_lines:
        file.write(line+"\n")


print(f"Generated {len(log_lines)} log lines")        

