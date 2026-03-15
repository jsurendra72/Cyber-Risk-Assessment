import streamlit as st
import subprocess
import xml.etree.ElementTree as ET
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ---------- PAGE ----------
st.set_page_config(
    page_title="CyberScan Pro",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CyberScan Pro")
st.caption("Professional Network Reconnaissance & Threat Intelligence Dashboard")
st.divider()

# ---------- SESSION ----------
if "df" not in st.session_state:
    st.session_state.df=None

if "scan_time" not in st.session_state:
    st.session_state.scan_time=None

# ---------- SIDEBAR ----------
st.sidebar.title("🛡️ CyberScan Pro")
st.sidebar.divider()

st.sidebar.subheader("⚙️ Configuration")

api_key_input = st.sidebar.text_input(
    "VirusTotal API Key",
    type="password"
)

if not api_key_input:

    try:
        with open("API_KEY.txt","r") as f:
            VT_API_KEY=f.read().strip()

        st.sidebar.success("API key loaded from file")

    except:
        VT_API_KEY=None
        st.sidebar.warning("Enter API key")

else:

    VT_API_KEY=api_key_input
    st.sidebar.success("API key ready")

st.sidebar.divider()

# ---------- TARGETS ----------
st.sidebar.subheader("🎯 Scan Targets")

targets_input=st.sidebar.text_area(

"One target per line",

value="scanme.nmap.org\ntestphp.vulnweb.com"

)

targets=[

t.strip()

for t in targets_input.split("\n")

if t.strip()

]

scan_button=st.sidebar.button(

"🚀 Run Full Scan",

use_container_width=True

)

st.sidebar.divider()

# ---------- EMAIL ----------
st.sidebar.subheader("📧 Email Alerts")

sender_email=st.sidebar.text_input("Sender Gmail")

app_password=st.sidebar.text_input(

"Gmail App Password",

type="password"

)

recipient_email=st.sidebar.text_input("Recipient Email")

st.sidebar.divider()

# ---------- SCAN DIR ----------
SCAN_DIR="scan_results"

os.makedirs(SCAN_DIR,exist_ok=True)

HIGH_RISK_SERVICES={

"ftp":3,
"telnet":4,
"ssh":1,
"smtp":2,
"rdp":4,
"vnc":3

}

# ---------- FUNCTIONS ----------

def run_nmap_scan(target):

    xml_file=f"{SCAN_DIR}/{target.replace('.','_')}.xml"

    try:

        subprocess.run([

        "nmap",
        "-Pn",
        "-sV",
        "-oX",
        xml_file,
        target

        ],capture_output=True,text=True)

    except Exception as e:

        st.error(e)

    return xml_file


def parse_nmap_xml(xml):

    rows=[]

    try:

        root=ET.parse(xml).getroot()

        for host in root.findall("host"):

            ip=host.find("address").get("addr")

            for port in host.findall(".//port"):

                svc=port.find("service")

                rows.append({

                "ip":ip,

                "port":port.get("portid"),

                "service":

                svc.get("name")

                if svc is not None

                else "unknown"

                })

    except:

        pass

    return rows


def check_virustotal(ip,key):

    try:

        r=requests.get(

        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",

        headers={"x-apikey":key},

        timeout=15

        )

        if r.status_code==200:

            data=r.json()

            return data["data"]["attributes"]["last_analysis_stats"]["malicious"]

        return 0

    except:

        return 0


def calculate_risk(row):

    return(

    1+

    HIGH_RISK_SERVICES.get(

    row["service"],0

    )+

    row["malicious_reports"]

    )


def classify(score):

    if score<=2:

        return "Low"

    elif score<=5:

        return "Medium"

    else:

        return "High"


def send_alert_email(

sender,

password,

recipient,

high_df,

scan_time

):

    body="CyberScan High Risk Alert\n\n"

    body+=f"Scan time : {scan_time}\n\n"

    for _,row in high_df.iterrows():

        body+=f"""

Host : {row['ip']}
Port : {row['port']}
Service : {row['service']}
Risk : {row['risk_score']}
VT hits : {row['malicious_reports']}

"""

    msg=MIMEMultipart()

    msg["From"]=sender

    msg["To"]=recipient

    msg["Subject"]="CyberScan Alert"

    msg.attach(MIMEText(body,"plain"))

    try:

        server=smtplib.SMTP(

        "smtp.gmail.com",

        587

        )

        server.starttls()

        server.login(

        sender,

        password

        )

        server.send_message(msg)

        server.quit()

        return True

    except Exception as e:

        return str(e)

# ---------- RUN SCAN ----------

if scan_button:

    if not VT_API_KEY:

        st.error("Enter VirusTotal key")

    else:

        rows=[]

        progress=st.progress(0)

        for i,target in enumerate(targets):

            data=parse_nmap_xml(

            run_nmap_scan(target)

            )

            rows.extend(data)

            progress.progress(

            (i+1)/len(targets)

            )

        df=pd.DataFrame(rows)

        if df.empty:

            st.error("No ports found")

            st.stop()

        ips=df["ip"].unique()

        vt={}

        for ip in ips:

            vt[ip]=check_virustotal(

            ip,

            VT_API_KEY

            )

            time.sleep(15)

        df["malicious_reports"]=df["ip"].map(vt)

        df["risk_score"]=df.apply(

        calculate_risk,

        axis=1

        )

        df["severity"]=df["risk_score"].apply(classify)

        st.session_state.df=df

        st.session_state.scan_time=time.strftime(

        "%Y-%m-%d %H:%M:%S"

        )

        st.success("Scan complete")

# ---------- DATA ----------

if st.session_state.df is None:

    st.info("Run scan to see results")

    df=pd.DataFrame({

    "ip":["192.168.1.1"],

    "port":["22"],

    "service":["ssh"],

    "malicious_reports":[0]

    })

    df["risk_score"]=df.apply(calculate_risk,axis=1)

    df["severity"]=df["risk_score"].apply(classify)

else:

    df=st.session_state.df

    st.caption(

    f"Last scan : {st.session_state.scan_time}"

    )

# ---------- FILTERS ----------

st.sidebar.subheader("Filters")

ip_filter=st.sidebar.selectbox(

"IP",

["All"]+

sorted(df["ip"].unique())

)

sev_filter=st.sidebar.multiselect(

"Severity",

["Low","Medium","High"],

default=["Low","Medium","High"]

)

filtered=df.copy()

if ip_filter!="All":

    filtered=filtered[

    filtered["ip"]==ip_filter

    ]

if sev_filter:

    filtered=filtered[

    filtered["severity"].isin(sev_filter)

    ]

# ---------- METRICS ----------

st.subheader("📊 Metrics")

c1,c2,c3,c4=st.columns(4)

c1.metric(

"Hosts",

df["ip"].nunique()

)

c2.metric(

"Open Ports",

len(df)

)

c3.metric(

"Services",

df["service"].nunique()

)

c4.metric(

"Max Risk",

int(df["risk_score"].max())

)

# ---------- TABLE ----------

st.subheader("Scan Results")

st.dataframe(filtered)

# ---------- CHARTS ----------

st.subheader("Charts")

col1,col2=st.columns(2)

with col1:

    ports=df.groupby("ip")["port"].count().reset_index()

    ports.columns=["IP","Open Ports"]

    fig=px.bar(

    ports,

    x="IP",

    y="Open Ports"

    )

    st.plotly_chart(fig,use_container_width=True)

with col2:

    sev=df["severity"].value_counts().reset_index()

    sev.columns=["Severity","Count"]

    fig2=px.pie(

    sev,

    names="Severity",

    values="Count"

    )

    st.plotly_chart(fig2,use_container_width=True)

# ---------- EMAIL ----------

st.subheader("📧 Email Alert")

high=df[

df["severity"]=="High"

]

if st.button("Send Alert"):

    if sender_email and app_password and recipient_email:

        result=send_alert_email(

        sender_email,

        app_password,

        recipient_email,

        high,

        st.session_state.scan_time

        )

        if result==True:

            st.success("Email sent")

        else:

            st.error(result)

    else:

        st.error("Configure email")

# ---------- EXPORT ----------

st.subheader("Export")

st.download_button(

"Download CSV",

df.to_csv(index=False),

file_name="scan.csv"

)