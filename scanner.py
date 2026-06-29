import requests
from virustotal import check_virustotal

def perform_scan(url):
    try:
        response = requests.get(url, timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        score = 0
        vulnerabilities = []
        
        security_headers = {
            'content-security-policy': 'CSP (Mencegah XSS & Data Injection)',
            'strict-transport-security': 'HSTS (Memaksa koneksi HTTPS)',
            'x-content-type-options': 'X-Content-Type-Options (Mencegah MIME-sniffing)',
            'x-xss-protection': 'X-XSS-Protection (Proteksi XSS bawaan browser)',
            'x-frame-options': 'X-Frame-Options (Mencegah Clickjacking)'
        }
        
        for header, description in security_headers.items():
            if header in headers:
                score += 20
            else:
                vulnerabilities.append(f"{description} tidak ditemukan.")
        
        if 'set-cookie' in headers:
            cookie = headers['set-cookie'].lower()
            if 'httponly' not in cookie:
                vulnerabilities.append("Cookie: Atribut 'HttpOnly' hilang (Risiko XSS).")
            if 'secure' not in cookie:
                vulnerabilities.append("Cookie: Atribut 'Secure' hilang (Risiko enkripsi).")
        else:
            vulnerabilities.append("Cookie: Tidak ada cookie sesi terdeteksi.")

        if 'permissions-policy' not in headers:
            vulnerabilities.append("Permissions-Policy hilang (Website tidak membatasi fitur browser).")
        else:
            score += 10
            
        vt_data = check_virustotal(url)
        if vt_data:
            vulnerabilities.append("Data keamanan eksternal dari VirusTotal telah diproses.")
            
        return {
            "score": min(score, 100),
            "vulnerabilities": vulnerabilities,
            "target": url
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "score": 0,
            "vulnerabilities": [f"Gagal mengakses target: {str(e)}"],
            "target": url
        }
