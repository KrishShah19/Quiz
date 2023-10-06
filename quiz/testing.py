import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email configuration
smtp_server = 'smtp.gmail.com'
smtp_port = 587  # or the appropriate port for your SMTP server
smtp_username = 'krishshah1904@gmail.com'
smtp_password = 'onuvovnigdodciqr'
sender_email = 'krishshah1904@gmail.com'
recipient_email = 'krish@yodaplus.com'

# Create a message
message = MIMEMultipart()
message['From'] = sender_email
message['To'] = recipient_email
message['Subject'] = 'Test Email'
message.attach(MIMEText('This is a test email.', 'plain'))

# Connect to the SMTP server and send the email
try:
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)
    server.sendmail(sender_email, recipient_email, message.as_string())
    server.quit()
    print('Email sent successfully!')
except Exception as e:
    print(f'Error sending email: {e}')
