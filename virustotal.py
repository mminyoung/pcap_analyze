import webbrowser

def open_web(ip):
    url = "https://www.virustotal.com/gui/ip-address/" + ip + "/summary"
    webbrowser.open(url)
