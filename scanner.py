import requests
import datetime
import json
from email_alert import send_alert

target=input("Enter test website URL: ")

scan_time=str(datetime.datetime.now())

vulnerabilities=[]

def add_vulnerability(name,severity,score,solution):

    vulnerabilities.append({

        "name":name,
        "severity":severity,
        "score":score,
        "solution":solution

    })

try:

    response=requests.get(target,timeout=10)

    headers=response.headers

    # 1 HTTPS check
    if "https" not in target:

        add_vulnerability(

        "HTTPS Not Used",
        "High",
        8,
        "Install SSL certificate"

        )

    # 2 Security headers

    if "X-Frame-Options" not in headers:

        add_vulnerability(

        "Clickjacking Protection Missing",
        "Medium",
        5,
        "Add X-Frame-Options header"

        )

    # 3 CSP

    if "Content-Security-Policy" not in headers:

        add_vulnerability(

        "Content Security Policy Missing",
        "High",
        7,
        "Add CSP header"

        )

    # 4 Server info disclosure

    if "Server" in headers:

        add_vulnerability(

        "Server Version Disclosure",
        "Low",
        3,
        "Hide server banner"

        )

    # 5 HSTS

    if "Strict-Transport-Security" not in headers:

        add_vulnerability(

        "HSTS Missing",
        "Medium",
        6,
        "Enable HSTS"

        )

    # 6 Basic XSS test

    test=target+"?test=<script>alert(1)</script>"

    r=requests.get(test)

    if "<script>alert(1)</script>" in r.text:

        add_vulnerability(

        "Possible XSS",
        "Critical",
        10,
        "Sanitize inputs"

        )

    # 7 Basic SQL injection test

    test2=target+"'"

    r2=requests.get(test2)

    errors=["sql","mysql","syntax"]

    if any(e in r2.text.lower() for e in errors):

        add_vulnerability(

        "Possible SQL Injection",
        "Critical",
        10,
        "Use parameterized queries"

        )

except:

    print("Invalid URL or connection failed")

# Risk score
total_score=sum(v["score"] for v in vulnerabilities)

# Risk level

if total_score>25:

    risk="Critical"

elif total_score>15:

    risk="High"

elif total_score>8:

    risk="Medium"

else:

    risk="Low"

print("\nSCAN RESULTS\n")

for v in vulnerabilities:

    print(v["name"],v["severity"],v["score"])

print("\nOverall Risk Score:",total_score)

print("Overall Risk Level:",risk)

# Save results

results={

"target":target,
"time":scan_time,
"risk_score":total_score,
"risk_level":risk,
"vulnerabilities":vulnerabilities

}

with open("results.json","w") as f:

    json.dump(results,f,indent=4)

# Auto email trigger

high=[v for v in vulnerabilities if v["severity"] in ["High","Critical"]]

if high:

    send_alert(target,scan_time,total_score,high)

print("\nScan Completed")