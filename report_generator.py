import datetime

def generate_report(df):

    file="scan_report.csv"

    df.to_csv(file,index=False)

    summary=f"""

SCAN REPORT
Time : {datetime.datetime.now()}

Hosts : {df['host'].nunique()}

Ports : {len(df)}

High : {len(df[df['severity']=="HIGH"])}

Medium : {len(df[df['severity']=="MEDIUM"])}

Low : {len(df[df['severity']=="LOW"])}

"""

    with open("summary.txt","w") as f:

        f.write(summary)

    return file