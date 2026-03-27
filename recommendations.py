def get_recommendation(service, port):

    service=str(service).lower()
    port=str(port)

    recommendations={

    "telnet":"Disable Telnet. Use SSH instead.",

    "ftp":"Use SFTP or FTPS instead of FTP.",

    "ssh":"Use key authentication and disable root login.",

    "http":"Use HTTPS with TLS encryption.",

    "smtp":"Configure spam filtering and authentication.",

    "rdp":"Restrict RDP access using firewall.",

    "vnc":"Use strong passwords and VPN access.",

    "mysql":"Restrict remote database access.",

    "postgres":"Allow only trusted IP connections.",

    "http-proxy":"Check proxy security configuration."

    }

    if service in recommendations:

        return recommendations[service]

    if port=="23":

        return "Close Telnet port immediately."

    if port=="21":

        return "FTP port exposed. Consider secure alternatives."

    if port=="3389":

        return "RDP exposed. Restrict access."

    if port=="445":

        return "SMB exposed. Possible ransomware risk."

    return "Monitor service and apply security patches."