# ==============================
# CYBER RISK SCANNER ENGINE
# ==============================

# ---------- IMPORTS ----------
import subprocess
import os
import time
import datetime
import pandas as pd
import xml.etree.ElementTree as ET
from dotenv import load_dotenv

from risk_engine import calculate_risk,severity_level
from email_alert import send_email
from report_generator import generate_report

# ---------- ENV ----------
load_dotenv()

EMAIL_SENDER=os.getenv("GMAIL_SENDER")

EMAIL_PASSWORD=os.getenv("GMAIL_PASSWORD")

EMAIL_RECEIVER=os.getenv("GMAIL_RECIPIENT")

# ---------- SCAN DIRECTORY ----------
SCAN_DIR="scan_results"

os.makedirs(SCAN_DIR,exist_ok=True)

# ---------- SCAN FUNCTION ----------
def run_scan(target):

    print("\n==============================")

    print("Scanning :",target)

    print("==============================")

    file_name=f"{SCAN_DIR}/{target.replace('.','_')}.xml"

    try:

        result=subprocess.run(

        [

        "nmap",
        "-Pn",
        "-sV",
        "-T4",
        "-oX",
        file_name,
        target

        ],

        capture_output=True,

        text=True

        )

        if result.returncode==0:

            print("✅ Scan completed")

        else:

            print("❌ Scan error")

    except Exception as e:

        print("Error :",e)

    return file_name


# ---------- MULTI SCAN ----------
def multi_scan(targets):

    files=[]

    start=time.time()

    for target in targets:

        xml=run_scan(target)

        files.append(xml)

    end=time.time()

    print("\nScan Finished")

    print("Targets :",len(targets))

    print("Time :",round(end-start,2),"seconds")

    return files


# ---------- PARSE XML ----------
def parse_xml(xml_files):

    rows=[]

    for xml in xml_files:

        try:

            tree=ET.parse(xml)

            root=tree.getroot()

            for host in root.findall("host"):

                ip=host.find("address").get("addr")

                for port in host.findall(".//port"):

                    service=port.find("service")

                    rows.append({

                    "host":ip,

                    "port":port.get("portid"),

                    "service":

                    service.get("name")

                    if service is not None

                    else "unknown"

                    })

        except:

            pass

    return rows


# ---------- MAIN ----------
if __name__=="__main__":

    print("="*50)

    print("CYBER RISK SCANNER")

    print("="*50)

    targets=[

    "scanme.nmap.org",

    "testphp.vulnweb.com"

    ]

    xml_files=multi_scan(targets)

    data=parse_xml(xml_files)

    df=pd.DataFrame(data)

    if df.empty:

        print("No ports found")

        exit()

    # ---------- RISK ----------
    df["vt_hits"]=0

    df["risk_score"]=df.apply(

    lambda row: calculate_risk(

    row["service"],

    row["vt_hits"]

    ),

    axis=1

    )

    df["severity"]=df["risk_score"].apply(severity_level)

    print("\nRISK RESULTS")

    print(df)

    # ---------- EMAIL ----------
    high=df[df["severity"]=="HIGH"]

    send_email(

    EMAIL_SENDER,

    EMAIL_PASSWORD,

    EMAIL_RECEIVER,

    high

    )

    # ---------- REPORT ----------
    generate_report(df)

    print("\nSCAN COMPLETED")

    print("="*50)