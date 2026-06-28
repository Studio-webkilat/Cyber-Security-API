import requests

def perform_scan(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        score = 0
        vulnerabilities = []
        
        if 'Strict-Transport-Security' in headers:
            score += 50
        else:
            vulnerabilities.append("Strict-Transport-Security header missing")
            
        if 'X-Frame-Options' in headers:
            score += 50
        else:
            vulnerabilities.append("X-Frame-Options header missing")
            
        return {
            "score": score, 
            "vulnerabilities": vulnerabilities,
            "target": url
        }
        
    except requests.exceptions.RequestException:
        return {
            "score": 0, 
            "vulnerabilities": ["Gagal mengakses website target, pastikan URL benar dan diawali dengan http/https"],
            "target": url
        }
