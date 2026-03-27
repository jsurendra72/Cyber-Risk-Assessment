import smtplib

from email.mime.text import MIMEText

from email.mime.multipart import MIMEMultipart


def send_email(sender,password,receiver,data):

    if data.empty:

        return

    body="HIGH RISK ALERT\n\n"

    for _,row in data.iterrows():

        body+=f"""
Host : {row['host']}
Port : {row['port']}
Service : {row['service']}
Risk : {row['risk_score']}
"""

    msg=MIMEMultipart()

    msg['From']=sender

    msg['To']=receiver

    msg['Subject']="Cyber Risk Alert"

    msg.attach(MIMEText(body,'plain'))

    server=smtplib.SMTP_SSL(

    'smtp.gmail.com',

    465

    )

    server.login(sender,password)

    server.send_message(msg)

    server.quit()