# Credential Stuffing Detection Engine
# Detects distributed low-and-slow login attacks through behavioral fingerprinting
# Signals: failure rate, IP subnet clustering, burst detection

from datetime import datetime,timedelta


total_logins=0
failed_logins=0
login_times = []
subnet_count = {}  # subnet -> list of unique IPs
alerts=[]

# === SIGNAL 1: Login Failure Rate ===
with open("access.log","r")as file:  
    for line in file:
        if "POST /login" in line:
            total_logins+=1
            if "401" in line:
                failed_logins+=1

    failure_rate = (failed_logins / total_logins) * 100

alerts.append(f"Login failure rate: {round(failure_rate, 2)}%")
if failure_rate > 80:
    alerts.append("ALERT: High login failure rate detected - possible credential stuffing")

# === SIGNAL 2: IP Subnet Clustering ===
with open("access.log","r") as file:
    for line in file:
        if "POST /login" in line:
            ip = line.split()[0]
            subnet = ".".join(ip.split(".")[:2])
            if subnet not in subnet_count:
                subnet_count[subnet] = set()
            subnet_count[subnet].add(ip)

for subnet, ips in subnet_count.items():
    if len(ips) > 10:
        alerts.append(f"ALERT: {len(ips)} IPs from subnet {subnet}.x.x hitting /login - possible distributed attack")    


# === SIGNAL 3: Burst Detection ===
with open("access.log", "r") as file:
    for line in file:
        if "POST /login" in line:
            parts = line.split()
            timestamp_str = parts[3] + " " + parts[4]  
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            login_times.append(timestamp)
login_times.sort()
alerts.append(f"Total login attempts: {len(login_times)}")
alerts.append(f"First attempt: {login_times[0]}")
alerts.append(f"Last attempt: {login_times[-1]}")


window = timedelta(minutes=10)

for i, current_time in enumerate(login_times):
    count = 0
    for j in range(i, len(login_times)):
        if login_times[j] - current_time <= window:
            count += 1
        else:
            break
    if count > 50:
        alerts.append(f"ALERT: {count} login attempts between {current_time} and {current_time + window} - possible burst attack")
        break


# === REPORT GENERATION ===
with open("report.txt", "w") as f:
    f.write("==========================================\n")
    f.write("CREDENTIAL STUFFING DETECTION REPORT\n")
    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("==========================================\n\n")
    f.write("SUMMARY\n")
    f.write("-------\n")
    f.write(f"Total login attempts: {total_logins}\n")
    f.write(f"Login failure rate: {round(failure_rate, 2)}%\n")
    f.write(f"First attempt: {login_times[0]}\n")
    f.write(f"Last attempt: {login_times[-1]}\n\n")
    f.write("ALERTS\n")
    f.write("------\n")
    for alert in alerts:
        if "ALERT" in alert:
            f.write(f"{alert}\n")
    f.write("\nRECOMMENDATION\n")
    f.write("--------------\n")
    f.write("Block suspicious subnets immediately.\n")
    f.write("Review all successful logins (200 status) for unauthorized access.\n")
    f.write("Enable rate limiting on /login endpoint.\n")
    f.write("==========================================\n")

print("Report saved to report.txt")    