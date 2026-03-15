def get_recommendation(service, port):

    service = str(service).lower()

    if service == "telnet" or port == "23":
        return "Disable Telnet. Use SSH instead."

    if service == "ftp" or port == "21":
        return "Use SFTP instead of FTP."

    if service == "ssh":
        return "Ensure strong passwords and disable root login."

    if service == "http":
        return "Consider HTTPS encryption."

    if service == "http-proxy":
        return "Check proxy configuration."

    return "Monitor this service regularly."