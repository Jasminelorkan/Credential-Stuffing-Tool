## Credential Stuffing Detection Engine

## What This Does

Traditional security tools flag too many logins from the same IP. But credential stuffing attacks use hundreds of different IPs from the same subnet, each trying only once or twice — so no single IP looks suspicious. And these IPs are hard to detect and traditional tools cannot detect this easily. This tool detects that pattern  made similar subnet and IPs in the log lines by analyzing failure login rates and burst detection . It generates an actionable report with alerts and recommendations.

## Why I Built This

Most beginner cyber security projects detect obvious attacks which has same IP, same payload, same pattern. I wanted to build something where each individual request looks innocent and now the tool has to detect the failed attempts pattern. Credential stuffing is exactly that kind of attack, and I wanted to prove I could think beyond the obvious.

## Detection Signals

- **Signal 1 — Login Failure Rate:**
    
    Calculates the percentage of failed login attempts. 
    
- **Signal 2 — IP Subnet Clustering:**
    
    Since attackers use same subnet but different IPs , this IP subnet is clustered to analyze which subnet it being used. 
    
- **Signal 3 — Burst Detection:**
    
    It calculates the number of login attempts made by the IPs within a 10 minute window.  
    

## How To Run

- Run log_generator.py to generate access.logs .
- access.logs contains 500 normal traffic log lines and 180 attack log lines.
- Run detector.py for Login Failure Rate, IP Subnet Clustering and Burst Detection.
- After the above operations, report.txt file will be generated.

## Sample Output
```
# =================================
CREDENTIAL STUFFING DETECTION REPORT
...
# =================================

Generated: 2026-06-24 18:26:11

# SUMMARY

Total login attempts: 280
Login failure rate: 91.79%
First attempt: 2023-10-10 13:00:00
Last attempt: 2023-10-10 13:58:12

# ALERTS

ALERT: High login failure rate detected - possible credential stuffing
ALERT: 180 IPs from subnet 91.108.x.x hitting /login - possible distributed attack
ALERT: 201 login attempts between 2023-10-10 13:00:00 and 2023-10-10 13:10:00 - possible burst attack

# RECOMMENDATION

Block suspicious subnets immediately.
Review all successful logins (200 status) for unauthorized access.
Enable rate limiting on /login endpoint.
```
## Tools Used

- Python 3
- Python Libraries - random and datetime
- VS Code


Veronica/and-mylinkedin-id
