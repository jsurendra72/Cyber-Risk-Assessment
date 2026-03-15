import smtplib
from email.mime.text import MIMEText

def send_alert(target,time,score,vulns):

    sender = "yourgmail@gmail.com"
    password = "your_16_digit_app_password"
    receiver = "yourgmail@gmail.com"

    subject = "Security Alert"

    body = f"""
Target : {target}
Scan Time : {time}
Risk Score : {score}

High Risk Vulnerabilities:
"""

    for v in vulns:

        body += f"""
Name : {v['name']}
Severity : {v['severity']}
Score : {v['score']}
"""

    msg = MIMEText(body)

    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = receiver

    try:

        print("Connecting to Gmail server...")

        server = smtplib.SMTP("smtp.gmail.com",587)

        server.starttls()

        print("Logging in...")

        server.login(sender,password)

        print("Sending email...")

        server.sendmail(sender,receiver,msg.as_string())

        server.quit()

        print("Email sent successfully")

    except Exception as e:

        print("EMAIL FAILED")
        print(e)