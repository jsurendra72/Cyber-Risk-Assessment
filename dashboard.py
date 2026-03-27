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
from report_generator import generate_report
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ---------- PAGE ----------

st.set_page_config(
    page_title="CyberScan Pro",
    page_icon="🛡️",
    layout="wide"
)

# ---------- CYBER THEME ----------

st.markdown("""
<style>

.stApp{
background-color:#0E1117;
color:white;
}

[data-testid="metric-container"]{
background-color:#151A24;
border-radius:10px;
padding:15px;
border:1px solid #00FFA6;
}

h1{
color:#00FFA6;
}

</style>
""",unsafe_allow_html=True)

st.title("🛡️ CyberScan Pro")

st.markdown("""
### Network Threat Intelligence Console

Professional vulnerability detection and risk scoring platform.
""")

st.divider()

# ---------- SESSION ----------

if "df" not in st.session_state:
    st.session_state.df=None

if "scan_time" not in st.session_state:
    st.session_state.scan_time=None

# ---------- SIDEBAR ----------

st.sidebar.title("🛡️ CyberScan Pro")

st.sidebar.divider()

st.sidebar.subheader("Configuration")

api_key_input=st.sidebar.text_input(
"VirusTotal API Key",
type="password"
)

if not api_key_input:

    try:

        with open("API_KEY.txt") as f:

            VT_API_KEY=f.read().strip()

        st.sidebar.success("API key loaded")

    except:

        VT_API_KEY=None

        st.sidebar.warning("Enter API key")

else:

    VT_API_KEY=api_key_input

    st.sidebar.success("API Ready")

st.sidebar.divider()

# ---------- TARGETS ----------

st.sidebar.subheader("Scan Targets")

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

"Run Full Scan",

use_container_width=True

)

# ---------- EMAIL ----------

st.sidebar.divider()

st.sidebar.subheader("Email Alerts")

sender_email=st.sidebar.text_input("Sender Gmail")

app_password=st.sidebar.text_input(

"Gmail App Password",

type="password"

)

recipient_email=st.sidebar.text_input(

"Recipient Email"

)

# ---------- DIRECTORY ----------

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

    subprocess.run([

    "nmap",
    "-Pn",
    "-sV",
    "-oX",
    xml_file,
    target

    ],capture_output=True)

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

# ---------- EMAIL FUNCTION ----------

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

        progress=st.progress(0,text="Scanning Network...")

        for i,target in enumerate(targets):

            data=parse_nmap_xml(

            run_nmap_scan(target)

            )

            rows.extend(data)

            percent=int((i+1)/len(targets)*100)

            progress.progress(

            percent,

            text=f"Scanning {target}"

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

# ---------- THREAT SUMMARY ----------

st.subheader("Threat Summary")

high_count=len(df[df["severity"]=="High"])

med_count=len(df[df["severity"]=="Medium"])

low_count=len(df[df["severity"]=="Low"])

a,b,c=st.columns(3)

a.error(f"High Risk : {high_count}")

b.warning(f"Medium Risk : {med_count}")

c.success(f"Low Risk : {low_count}")

# ---------- METRICS ----------

st.subheader("Metrics")

c1,c2,c3,c4=st.columns(4)

c1.metric("Hosts",df["ip"].nunique())

c2.metric("Open Ports",len(df))

c3.metric("Services",df["service"].nunique())

c4.metric("Max Risk",int(df["risk_score"].max()))

# ---------- TABLE ----------

st.subheader("Scan Results")

def color_risk(val):

    if val=="High":

        return 'background-color:red'

    if val=="Medium":

        return 'background-color:orange'

    if val=="Low":

        return 'background-color:green'

styled=df.style.applymap(

color_risk,

subset=["severity"]

)

st.dataframe(styled)

# ---------- CHARTS ----------

st.divider()
st.subheader("Threat Analytics Dashboard")

col1,col2=st.columns(2)

with col1:

    ports=df.groupby("ip")["port"].count().reset_index()

    ports.columns=["IP","Open Ports"]

    fig=px.bar(

    ports,

    x="IP",

    y="Open Ports",

    color="Open Ports",

    title="Open Ports per Host",

    color_continuous_scale="reds"

    )

    st.plotly_chart(fig,use_container_width=True)

with col2:

    sev=df["severity"].value_counts().reset_index()

    sev.columns=["Severity","Count"]

    fig2=px.pie(

    sev,

    names="Severity",

    values="Count",

    title="Risk Severity Distribution",

    color="Severity",

    color_discrete_map={

    "Low":"green",

    "Medium":"orange",

    "High":"red"

    }

    )

    st.plotly_chart(fig2,use_container_width=True)


# ---------- EXTRA PROFESSIONAL CHARTS ----------

col3,col4=st.columns(2)

with col3:

    services=df["service"].value_counts().reset_index()

    services.columns=["Service","Count"]

    fig3=px.bar(

    services,

    x="Service",

    y="Count",

    title="Service Distribution",

    color="Count",

    color_continuous_scale="blues"

    )

    st.plotly_chart(fig3,use_container_width=True)


with col4:

    fig4=px.histogram(

    df,

    x="risk_score",

    nbins=10,

    title="Risk Score Distribution",

    color_discrete_sequence=["red"]

    )

    st.plotly_chart(fig4,use_container_width=True)


# ---------- VIRUSTOTAL THREAT CHART ----------

st.subheader("Threat Intelligence")

vt=df.groupby("ip")["malicious_reports"].sum().reset_index()

fig5=px.bar(

vt,

x="ip",

y="malicious_reports",

title="VirusTotal Threat Reports",

color="malicious_reports",

color_continuous_scale="oranges"

)

st.plotly_chart(fig5,use_container_width=True)
# ---------- RISK GAUGE ----------

st.subheader("Risk Meter")

avg=int(df["risk_score"].mean())

fig=go.Figure(go.Indicator(

mode="gauge+number",

value=avg,

title={'text':"Average Risk"},

gauge={

'axis':{'range':[0,10]},

'bar':{'color':"red"},

'steps':[

{'range':[0,3],'color':"green"},

{'range':[3,6],'color':"orange"},

{'range':[6,10],'color':"red"}

]

}

))

st.plotly_chart(fig,use_container_width=True)

# ---------- EMAIL ----------

st.subheader("Email Alert")

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