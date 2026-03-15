from fpdf import FPDF
import datetime

def generate_pdf(high_risk_df):

    filename = "scan_results/security_report.pdf"

    pdf = FPDF()

    pdf.add_page()

    pdf.set_font("Arial", size=12)

    pdf.cell(200,10,"CYBERSCAN PRO SECURITY REPORT",ln=True)

    pdf.cell(200,10,str(datetime.datetime.now()),ln=True)

    pdf.cell(200,10,"",ln=True)

    pdf.cell(200,10,
        f"High Risk Hosts : {len(high_risk_df)}",
        ln=True
    )

    pdf.cell(200,10,
        f"Affected IPs : {high_risk_df['ip'].nunique()}",
        ln=True
    )

    pdf.cell(200,10,"",ln=True)

    pdf.cell(200,10,"HIGH RISK HOSTS",ln=True)

    for _,row in high_risk_df.iterrows():

        text = f"{row['ip']}  Port:{row['port']}  Service:{row['service']}"

        pdf.cell(200,10,text,ln=True)

    pdf.output(filename)

    return filename