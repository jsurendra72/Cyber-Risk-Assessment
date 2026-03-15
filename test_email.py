from email_alert import send_alert

v=[{"name":"Test","severity":"High","score":10}]

send_alert("testsite","now",20,v)