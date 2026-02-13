vulnerabilities_sorted = sorted(
    vulnerabilities,
    key=lambda x: calculate_risk(x),
    reverse=True
)

for vuln in vulnerabilities_sorted:
    risk = calculate_risk(vuln)
    print(vuln["name"], "Risk Score:", risk)