import requests
import os

def check_virustotal(url):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return None
    
    try:
        headers = {"x-apikey": api_key}
        # Mengirim URL untuk dianalisis
        response = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
        if response.status_code == 200:
            return {"status": "Analysis Started", "source": "VirusTotal"}
        return None
    except:
        return None
