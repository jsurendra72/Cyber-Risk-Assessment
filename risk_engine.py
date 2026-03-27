HIGH_RISK_SERVICES={

"ftp":4,
"telnet":5,
"smb":4,
"rdp":5,
"mysql":3,
"smtp":2,
"vnc":4

}

def calculate_risk(service,vt_hits):

    base=1

    service_score=HIGH_RISK_SERVICES.get(service,0)

    risk=base+service_score+vt_hits

    return risk


def severity_level(score):

    if score<=2:

        return "LOW"

    elif score<=5:

        return "MEDIUM"

    else:

        return "HIGH"