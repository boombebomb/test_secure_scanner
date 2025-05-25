import socket
import threading
import requests
import argparse
import json
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse
import sys
import os

class CyberSecureScanner:
    def __init__(self, target, threads=100):
        """
        เริ่มต้นคลาส Scanner
        
        Args:
            target (str): เป้าหมายที่จะscan (IP หรือ hostname)
            threads (int): จำนวน threads ที่ใช้ในการscan
        """
        self.target = target
        self.threads = threads
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': [],        # รายการ ports ที่เปิดอยู่
            'web_directories': [],   # รายการ web directories ที่พบ
            'services': [],          # รายการ services ที่ตรวจพบ
            'vulnerabilities': [],   # รายการช่องโหว่ที่พบ
            'os_detection': {},      # ผลการตรวจสอบ Operating System
            'ssl_info': []          # ข้อมูล SSL/TLS
        }
        self.lock = threading.Lock()  # ล็อคสำหรับ thread safety
        
    def banner(self):
        """แสดง banner ของเครื่องมือ"""
        print("""
========================================================================
                  Cyber Security Scanner Test                 
                    เครื่องมือประเมินความปลอดภัยขั้นสูง                           
========================================================================
        """)
        
    def resolve_target(self):
        """
        แปลง hostname เป็น IP address ถ้าจำเป็น
        
        Returns:
            str: IP address หรือ None ถ้าแปลงไม่สำเร็จ
        """
        if not self.target.replace('.', '').replace(':', '').isdigit():
            try:
                resolved_ip = socket.gethostbyname(self.target)
                print(f"[*] แปลง {self.target} เป็น {resolved_ip}")
                return resolved_ip
            except socket.gaierror:
                print(f"[!] ไม่สามารถแปลง hostname: {self.target}")
                return None
        return self.target

    def scan_port(self, ip, port):
        """
        scan port เดียว
        
        Args:
            ip (str): IP address ที่จะscan
            port (int): หมายเลข port ที่จะตรวจสอบ
        """
        try:
            # สร้าง socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # ตั้งเวลา timeout 1 วินาที
            result = sock.connect_ex((ip, port))
            
            if result == 0:  # ถ้าเชื่อมต่อสำเร็จ (port เปิดอยู่)
                # พยายาม grab banner จาก service
                banner = self.grab_banner(ip, port)
                
                # ป้องกัน race condition ด้วย lock
                with self.lock:
                    port_info = {
                        'port': port,
                        'status': 'open',
                        'service': self.identify_service(port),
                        'banner': banner
                    }
                    self.results['open_ports'].append(port_info)
                    print(f"[+] Port {port}: เปิดอยู่ - {port_info['service']}")
                    
            sock.close()
        except Exception:
            pass  # ไม่แสดง error สำหรับ ports ที่ปิดอยู่

    def grab_banner(self, ip, port):
        """
        พยายาม grab banner จาก service
        
        Args:
            ip (str): IP address
            port (int): หมายเลข port
            
        Returns:
            str: Banner text หรือ None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # ส่ง HTTP request สำหรับ web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else None
        except:
            return None

    def identify_service(self, port):
        """
        ระบุ service จากหมายเลข port
        
        Args:
            port (int): หมายเลข port
            
        Returns:
            str: ชื่อ service
        """
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL',
            1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB',
            135: 'MS-RPC', 139: 'NetBIOS', 445: 'SMB', 161: 'SNMP',
            389: 'LDAP', 636: 'LDAPS', 1521: 'Oracle', 5984: 'CouchDB'
        }
        return common_ports.get(port, 'ไม่ทราบ')

    def check_ssl_security(self, host, port=443):
        """
        ตรวจสอบความปลอดภัย SSL/TLS
        
        Args:
            host (str): hostname
            port (int): port number (default 443)
            
        Returns:
            tuple: (ssl_info, vulnerabilities)
        """
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    ssl_info = {
                        'version': version,
                        'cipher_suite': cipher[0] if cipher else 'ไม่ทราบ',
                        'key_size': cipher[2] if cipher else 0,
                        'cert_subject': dict(x[0] for x in cert.get('subject', [])),
                        'cert_issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'cert_expires': cert.get('notAfter', 'ไม่ทราบ'),
                        'san_names': [x[1] for x in cert.get('subjectAltName', [])]
                    }
                    
                    # ตรวจสอบช่องโหว่ SSL/TLS
                    vulnerabilities = []
                    
                    # ตรวจสอบเวอร์ชัน SSL/TLS ที่เก่า
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            'type': 'เวอร์ชัน SSL/TLS ที่อ่อนแอ',
                            'description': f'ใช้ {version} ที่ล้าสมัย',
                            'severity': 'สูง' if version.startswith('SSL') else 'ปานกลาง',
                            'port': port
                        })
                    
                    # ตรวจสอบความแข็งแรงของ cipher
                    if ssl_info['key_size'] < 128:
                        vulnerabilities.append({
                            'type': 'Cipher ที่อ่อนแอ',
                            'description': f'ขนาดกุญแจเข้ารหัสอ่อนแอ: {ssl_info["key_size"]} bits',
                            'severity': 'สูง',
                            'port': port
                        })
                    
                    self.results['ssl_info'].append(ssl_info)
                    return ssl_info, vulnerabilities
                    
        except Exception as e:
            return None, []

    def os_detection(self, ip):
        """
        ตรวจหา Operating System โดยใช้เทคนิคต่างๆ
        
        Args:
            ip (str): IP address ที่จะตรวจสอบ
            
        Returns:
            dict: ผลการตรวจสอบ OS
        """
        print(f"\n[*] กำลังตรวจหา Operating System ของ {ip}")
        print("-" * 50)
        
        os_hints = {
            'os_type': 'ไม่ทราบ',
            'confidence': 0,
            'evidence': []
        }
        
        try:
            # การตรวจสอบแบบ TTL-based
            import subprocess
            import platform
            
            # เลือกคำสั่ง ping ตาม OS ของเครื่องที่รัน script
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ping', '-n', '1', ip], 
                                      capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', '1', ip], 
                                      capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                # แยกค่า TTL จาก output
                if 'ttl=' in output:
                    ttl_line = [line for line in output.split('\n') if 'ttl=' in line]
                    if ttl_line:
                        ttl = ttl_line[0].split('ttl=')[1].split()[0]
                        ttl_value = int(ttl)
                        
                        # การตรวจสอบ OS จากค่า TTL
                        if ttl_value <= 64:
                            if ttl_value > 30:
                                os_hints['os_type'] = 'Linux/Unix'
                                os_hints['confidence'] = 70
                            else:
                                os_hints['os_type'] = 'Unix-like ไม่ทราบแน่ชัด'
                                os_hints['confidence'] = 40
                        elif ttl_value <= 128:
                            os_hints['os_type'] = 'Windows'
                            os_hints['confidence'] = 65
                        elif ttl_value <= 255:
                            os_hints['os_type'] = 'อุปกรณ์เครือข่าย/Router'
                            os_hints['confidence'] = 50
                        
                        os_hints['evidence'].append(f"TTL: {ttl_value}")
                        print(f"[+] TTL: {ttl_value} -> น่าจะเป็น {os_hints['os_type']}")
        
        except Exception as e:
            print(f"[-] การตรวจสอบด้วย Ping ล้มเหลว: {str(e)}")
        
        # การตรวจสอบ OS จาก ports ที่เปิดอยู่
        for port_info in self.results['open_ports']:
            port = port_info['port']
            banner = port_info.get('banner', '')
            
            # Ports เฉพาะของ Windows
            if port in [135, 139, 445, 3389]:
                if 'windows' not in os_hints['os_type'].lower():
                    os_hints['os_type'] = 'Windows'
                    os_hints['confidence'] = max(os_hints['confidence'], 80)
                os_hints['evidence'].append(f"พบ Windows port {port}")
                print(f"[+] Port {port} -> บ่งชี้ Windows")
            
            # การตรวจสอบเวอร์ชัน SSH
            elif port == 22 and banner:
                if 'openssh' in banner.lower():
                    if 'ubuntu' in banner.lower():
                        os_hints['os_type'] = 'Ubuntu Linux'
                        os_hints['confidence'] = 85
                        os_hints['evidence'].append("พบ OpenSSH Ubuntu banner")
                    elif 'debian' in banner.lower():
                        os_hints['os_type'] = 'Debian Linux'
                        os_hints['confidence'] = 85
                        os_hints['evidence'].append("พบ OpenSSH Debian banner")
                    else:
                        os_hints['os_type'] = 'Linux/Unix'
                        os_hints['confidence'] = max(os_hints['confidence'], 75)
                        os_hints['evidence'].append("พบ OpenSSH")
                print(f"[+] SSH Banner -> {os_hints['os_type']}")
            
            # การตรวจสอบ web server
            elif port in [80, 443, 8080] and banner:
                if 'iis' in banner.lower():
                    os_hints['os_type'] = 'Windows (IIS)'
                    os_hints['confidence'] = max(os_hints['confidence'], 80)
                    os_hints['evidence'].append("พบ IIS web server")
                elif 'apache' in banner.lower():
                    if 'ubuntu' in banner.lower():
                        os_hints['os_type'] = 'Ubuntu Linux'
                        os_hints['confidence'] = 80
                    elif 'debian' in banner.lower():
                        os_hints['os_type'] = 'Debian Linux'
                        os_hints['confidence'] = 80
                    else:
                        os_hints['os_type'] = 'Linux/Unix'
                        os_hints['confidence'] = max(os_hints['confidence'], 70)
                    os_hints['evidence'].append("พบ Apache web server")
        
        self.results['os_detection'] = os_hints
        print(f"[*] ผลการตรวจหา OS: {os_hints['os_type']} (ความมั่นใจ: {os_hints['confidence']}%)")
        return os_hints

    def port_scan(self, start_port=1, end_port=1000):
        """
        ทำการscan ports ในช่วงที่กำหนด
        
        Args:
            start_port (int): port เริ่มต้น
            end_port (int): port สุดท้าย
            
        Returns:
            bool: True ถ้าscanสำเร็จ
        """
        print(f"\n[*] เริ่มscan ports ของ {self.target}")
        print(f"[*] scan ports {start_port}-{end_port}")
        print("-" * 50)
        
        # แปลง hostname เป็น IP
        ip = self.resolve_target()
        if not ip:
            return False
            
        # สร้าง threads สำหรับการscan
        threads = []
        for port in range(start_port, end_port + 1):
            # จำกัดจำนวน threads ที่ทำงานพร้อมกัน
            while len(threads) >= self.threads:
                threads = [t for t in threads if t.is_alive()]
                
            t = threading.Thread(target=self.scan_port, args=(ip, port))
            t.start()
            threads.append(t)
        
        # รอให้ threads ทั้งหมดทำงานเสร็จ
        for t in threads:
            t.join()
            
        print(f"[*] การscan ports เสร็จสิ้น - พบ {len(self.results['open_ports'])} ports ที่เปิดอยู่")
        return True

    def check_web_path(self, base_url, path):
        """
        ตรวจสอบว่า web path มีอยู่หรือไม่
        
        Args:
            base_url (str): URL พื้นฐาน
            path (str): path ที่จะตรวจสอบ
        """
        try:
            url = urljoin(base_url, path)
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; Cyber Secure Scanner)'
            }
            
            response = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
            
            # ถือว่าน่าสนใจถ้าได้ status codes เหล่านี้
            if response.status_code in [200, 301, 302, 403]:
                with self.lock:
                    path_info = {
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content),
                        'title': self.extract_title(response.text) if response.status_code == 200 else None
                    }
                    self.results['web_directories'].append(path_info)
                    print(f"[+] {url} - {response.status_code} ({len(response.content)} bytes)")
                    
        except requests.RequestException:
            pass  # ไม่แสดง error สำหรับ connection ที่ล้มเหลว

    def extract_title(self, html):
        """
        ดึงชื่อหน้าเว็บจาก HTML
        
        Args:
            html (str): HTML content
            
        Returns:
            str: ชื่อหน้าเว็บหรือ None
        """
        try:
            start = html.lower().find('<title>') + 7
            end = html.lower().find('</title>')
            if start > 6 and end > start:
                return html[start:end].strip()
        except:
            pass
        return None

    def web_scan(self):
        """ทำการscan web directories"""
        # ตรวจสอบว่ามี web services หรือไม่
        web_ports = [p for p in self.results['open_ports'] 
                    if p['port'] in [80, 443, 8080, 8443]]
        
        if not web_ports:
            print("[*] ไม่พบ web services ข้าม web scan")
            return
            
        for port_info in web_ports:
            # เลือก protocol ตาม port
            protocol = 'https' if port_info['port'] in [443, 8443] else 'http'
            base_url = f"{protocol}://{self.target}:{port_info['port']}"
            
            print(f"\n[*] เริ่มscan web directories ที่ {base_url}")
            print("-" * 50)
            
            # รายการ paths ที่จะตรวจสอบ
            paths = [
                '/', '/admin', '/administrator', '/login', '/panel',
                '/wp-admin', '/phpmyadmin', '/config', '/backup',
                '/robots.txt', '/sitemap.xml', '/.env', '/api',
                '/uploads', '/files', '/test', '/dev', '/hidden'
            ]
            
            # สร้าง threads สำหรับตรวจสอบ paths
            threads = []
            for path in paths:
                while len(threads) >= 50:  # ใช้ threads น้อยกว่าสำหรับ web requests
                    threads = [t for t in threads if t.is_alive()]
                    
                t = threading.Thread(target=self.check_web_path, args=(base_url, path))
                t.start()
                threads.append(t)
            
            # รอให้ threads ทั้งหมดเสร็จ
            for t in threads:
                t.join()
                
        print(f"[*] การscan web เสร็จสิ้น - พบ {len(self.results['web_directories'])} paths ที่น่าสนใจ")

    def vulnerability_check(self):
        """การประเมินช่องโหว่ขั้นสูง"""
        print(f"\n[*] กำลังทำการประเมินช่องโหว่ขั้นสูง")
        print("-" * 50)
        
        # ตรวจสอบ protocols ที่ไม่ปลอดภัย
        for port_info in self.results['open_ports']:
            port = port_info['port']
            service = port_info['service']
            banner = port_info.get('banner', '')
            
            # ช่องโหว่วิกฤต
            if port == 23:  # Telnet
                vuln = {
                    'type': 'Protocol ที่ไม่ปลอดภัย',
                    'description': 'พบ Telnet service - ใช้การสื่อสารแบบไม่เข้ารหัส',
                    'severity': 'วิกฤต',
                    'port': port,
                    'recommendation': 'เปลี่ยนเป็น SSH (port 22) แทน'
                }
                self.results['vulnerabilities'].append(vuln)
                print(f"[!] วิกฤต: พบ Telnet service ที่ไม่ปลอดภัยที่ port {port}")
                
            elif port == 21:  # FTP
                if 'vsftpd 2.3.4' in banner.lower():
                    vuln = {
                        'type': 'ช่องโหว่ที่ทราบแล้ว',
                        'description': 'vsftpd 2.3.4 - Backdoor Command Execution (CVE-2011-2523)',
                        'severity': 'วิกฤต',
                        'port': port,
                        'cve': 'CVE-2011-2523'
                    }
                    self.results['vulnerabilities'].append(vuln)
                    print(f"[!] วิกฤต: ช่องโหว่ vsftpd backdoor ที่ port {port}")
                else:
                    vuln = {
                        'type': 'Protocol ที่อาจไม่ปลอดภัย',
                        'description': 'พบ FTP service - อาจใช้การสื่อสารแบบไม่เข้ารหัส',
                        'severity': 'ปานกลาง',
                        'port': port,
                        'recommendation': 'ใช้ SFTP หรือ FTPS แทน'
                    }
                    self.results['vulnerabilities'].append(vuln)
                    print(f"[!] ปานกลาง: พบ FTP service ที่ port {port}")
            
            elif port == 139 or port == 445:  # SMB
                vuln = {
                    'type': 'การแชร์ไฟล์เครือข่าย',
                    'description': f'พบ SMB service ที่ port {port} - อาจมีการเปิดเผยข้อมูล',
                    'severity': 'ปานกลาง',
                    'port': port,
                    'recommendation': 'ตรวจสอบการควบคุมการเข้าถึงและ patches ล่าสุด'
                }
                self.results['vulnerabilities'].append(vuln)
                print(f"[!] ปานกลาง: พบ SMB service ที่ port {port}")
            
            elif port == 3389:  # RDP
                vuln = {
                    'type': 'Remote Access Service',
                    'description': 'พบ RDP service - เป้าหมายสำหรับการโจมตี brute force',
                    'severity': 'ปานกลาง',
                    'port': port,
                    'recommendation': 'ใช้ VPN, เปลี่ยน port เริ่มต้น, เปิด NLA'
                }
                self.results['vulnerabilities'].append(vuln)
                print(f"[!] ปานกลาง: พบ RDP service ที่ port {port}")
            
            elif port == 161:  # SNMP
                vuln = {
                    'type': 'การจัดการเครือข่าย',
                    'description': 'พบ SNMP service - อาจเปิดเผยข้อมูลระบบ',
                    'severity': 'ต่ำ',
                    'port': port,
                    'recommendation': 'ใช้ SNMPv3 พร้อม authentication'
                }
                self.results['vulnerabilities'].append(vuln)
                print(f"[!] ต่ำ: พบ SNMP service ที่ port {port}")
            
            # ตรวจสอบ HTTPS services
            elif port in [443, 8443]:
                ssl_info, ssl_vulns = self.check_ssl_security(self.resolve_target(), port)
                self.results['vulnerabilities'].extend(ssl_vulns)
                for ssl_vuln in ssl_vulns:
                    severity_color = {'วิกฤต': 'วิกฤต', 'สูง': 'สูง', 'ปานกลาง': 'ปานกลาง', 'ต่ำ': 'ต่ำ'}
                    print(f"[!] {severity_color.get(ssl_vuln['severity'], 'INFO')}: {ssl_vuln['description']}")
        
        # ตรวจสอบช่องโหว่ web application
        sensitive_paths = ['/phpmyadmin', '/wp-admin', '/admin', '/administrator']
        for web_path in self.results['web_directories']:
            url = web_path['url'].lower()
            status = web_path['status']
            
            # ตรวจสอบ admin interfaces ที่เปิดให้เข้าถึงได้
            if any(path in url for path in sensitive_paths) and status == 200:
                vuln = {
                    'type': 'Admin Interface ที่เปิดให้เข้าถึงได้',
                    'description': f'สามารถเข้าถึง admin interface: {web_path["url"]}',
                    'severity': 'ปานกลาง',
                    'url': web_path['url'],
                    'recommendation': 'จำกัดการเข้าถึงด้วย IP หรือใช้ authentication ที่แข็งแรง'
                }
                self.results['vulnerabilities'].append(vuln)
                print(f"[!] ปานกลาง: พบ admin interface ที่ {web_path['url']}")
            
            # ตรวจสอบไฟล์ configuration ที่เปิดให้เข้าถึงได้
            if '.env' in url and status in [200, 403]:
                severity = 'วิกฤต' if status == 200 else 'ต่ำ'
                vuln = {
                    'type': 'การเปิดเผยไฟล์ Configuration',
                    'description': f'พบไฟล์ Environment: {web_path["url"]} (Status: {status})',
                    'severity': severity,
                    'url': web_path['url'],
                    'recommendation': 'ลบหรือป้องกันไฟล์ configuration อย่างเหมาะสม'
                }
                self.results['vulnerabilities'].append(vuln)
                severity_text = 'วิกฤต' if status == 200 else 'ต่ำ'
                print(f"[!] {severity_text}: พบไฟล์ Environment ที่ {web_path['url']}")
        
        print(f"[*] การประเมินช่องโหว่ขั้นสูงเสร็จสิ้น - พบ {len(self.results['vulnerabilities'])} ปัญหา")

    def generate_html_report(self, output_file='scan_report.html'):
        """สร้างรายงาน HTML ขั้นสูง"""
        # นับจำนวนช่องโหว่ตามระดับความรุนแรง
        vuln_counts = {'วิกฤต': 0, 'สูง': 0, 'ปานกลาง': 0, 'ต่ำ': 0}
        for vuln in self.results['vulnerabilities']:
            severity = vuln.get('severity', 'ต่ำ')
            vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
        
        html_content = '''<!DOCTYPE html>
<html lang="th">
<head>
    <title>CyberSecurity Scan Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Sarabun', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white; 
            padding: 30px; 
            text-align: center;
        }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 5px 0; opacity: 0.9; }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-top: 4px solid;
        }
        .summary-card.ports { border-top-color: #3498db; }
        .summary-card.web { border-top-color: #2ecc71; }
        .summary-card.vulns { border-top-color: #e74c3c; }
        .summary-card.os { border-top-color: #f39c12; }
        
        .summary-card h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .summary-card .number { font-size: 2em; font-weight: bold; }
        
        .section { 
            margin: 0; 
            padding: 30px; 
            border-bottom: 1px solid #eee;
        }
        .section:last-child { border-bottom: none; }
        .section h2 { 
            color: #2c3e50; 
            border-bottom: 2px solid #3498db; 
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        th, td { 
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #eee; 
        }
        th { 
            background: #34495e; 
            color: white;
            font-weight: 600;
        }
        tr:hover { background: #f8f9fa; }
        
        .vuln-item {
            background: white;
            margin: 15px 0;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .vuln-item.วิกฤต { border-left-color: #8b0000; }
        .vuln-item.สูง { border-left-color: #e74c3c; }
        .vuln-item.ปานกลาง { border-left-color: #f39c12; }
        .vuln-item.ต่ำ { border-left-color: #27ae60; }
        
        .vuln-severity {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            margin-right: 10px;
            text-transform: uppercase;
            font-size: 0.8em;
        }
        .วิกฤต { background: #8b0000; }
        .สูง { background: #e74c3c; }
        .ปานกลาง { background: #f39c12; }
        .ต่ำ { background: #27ae60; }
        
        .os-detection {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-style: italic;
        }
        
        .status-ok { color: #27ae60; font-weight: bold; }
        .status-redirect { color: #f39c12; font-weight: bold; }
        .status-forbidden { color: #e74c3c; font-weight: bold; }
        
        @media (max-width: 768px) {
            .summary-grid { grid-template-columns: 1fr; }
            .container { margin: 10px; }
            body { padding: 10px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Cyber Security Scanner</h1>
            <p><strong>เป้าหมาย:</strong> ''' + self.results['target'] + '''</p>
            <p><strong>วันที่ Scan:</strong> ''' + self.results['timestamp'] + '''</p>
            <p>รายงานการประเมินความปลอดภัยขั้นสูง</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card ports">
                <h3>🔓 Ports ที่เปิดอยู่</h3>
                <div class="number">''' + str(len(self.results['open_ports'])) + '''</div>
            </div>
            <div class="summary-card web">
                <h3>🌐 Web Paths</h3>
                <div class="number">''' + str(len(self.results['web_directories'])) + '''</div>
            </div>
            <div class="summary-card vulns">
                <h3>⚠️ ช่องโหว่</h3>
                <div class="number">''' + str(len(self.results['vulnerabilities'])) + '''</div>
            </div>
            <div class="summary-card os">
                <h3>💻 การตรวจหา OS</h3>
                <div class="number">''' + str(self.results['os_detection'].get('confidence', 0)) + '''%</div>
            </div>
        </div>'''
        
        # ส่วนการตรวจหา OS
        if self.results['os_detection'].get('os_type') != 'ไม่ทราบ':
            html_content += '''
        <div class="section">
            <h2>💻 การตรวจหา Operating System</h2>
            <div class="os-detection">
                <h3>OS ที่ตรวจพบ: ''' + self.results['os_detection']['os_type'] + '''</h3>
                <p><strong>ความมั่นใจ:</strong> ''' + str(self.results['os_detection']['confidence']) + '''%</p>
                <p><strong>หลักฐาน:</strong></p>
                <ul>'''
            for evidence in self.results['os_detection'].get('evidence', []):
                html_content += f"<li>{evidence}</li>"
            html_content += '''
                </ul>
            </div>
        </div>'''
        
        # ส่วน Open Ports
        html_content += '''
        <div class="section">
            <h2>🔓 Ports และ Services ที่เปิดอยู่</h2>
            <table>
                <tr><th>Port</th><th>Service</th><th>Banner</th></tr>'''
        
        for port in self.results['open_ports']:
            banner = port['banner'] or 'ไม่มีข้อมูล'
            if len(banner) > 100:
                banner = banner[:100] + "..."
            html_content += f"<tr><td><strong>{port['port']}</strong></td><td>{port['service']}</td><td><code>{banner}</code></td></tr>"
        
        html_content += '''
            </table>
        </div>'''
        
        # ส่วน Web Directories
        if self.results['web_directories']:
            html_content += '''
        <div class="section">
            <h2>🌐 การตรวจสอบ Web Directories</h2>
            <table>
                <tr><th>URL</th><th>Status</th><th>ขนาด</th><th>ชื่อหน้า</th></tr>'''
            
            for web in self.results['web_directories']:
                status_class = 'status-ok' if web['status'] == 200 else 'status-redirect' if web['status'] in [301, 302] else 'status-forbidden'
                html_content += f'<tr><td><a href="{web["url"]}" target="_blank">{web["url"]}</a></td><td class="{status_class}">{web["status"]}</td><td>{web["size"]} bytes</td><td>{web["title"] or "ไม่มีข้อมูล"}</td></tr>'
            
            html_content += '''
            </table>
        </div>'''
        
        # ส่วนข้อมูล SSL
        if self.results['ssl_info']:
            html_content += '''
        <div class="section">
            <h2>🔒 ข้อมูล SSL/TLS</h2>'''
            for ssl_info in self.results['ssl_info']:
                html_content += f'''
            <div style="background: #f8f9fa; border-radius: 8px; padding: 15px; margin: 10px 0;">
                <h4>รายละเอียด SSL Certificate</h4>
                <p><strong>TLS Version:</strong> {ssl_info['version']}</p>
                <p><strong>Cipher Suite:</strong> {ssl_info['cipher_suite']}</p>
                <p><strong>ขนาด Key:</strong> {ssl_info['key_size']} bits</p>
                <p><strong>วันหมดอายุ:</strong> {ssl_info['cert_expires']}</p>
                <p><strong>Subject:</strong> {ssl_info['cert_subject'].get('commonName', 'ไม่มีข้อมูล')}</p>
                <p><strong>Issuer:</strong> {ssl_info['cert_issuer'].get('organizationName', 'ไม่มีข้อมูล')}</p>
            </div>'''
            html_content += '''
        </div>'''
        
        # ส่วนช่องโหว่
        html_content += '''
        <div class="section">
            <h2>⚠️ ช่องโหว่ด้านความปลอดภัย</h2>'''
        
        if not self.results['vulnerabilities']:
            html_content += "<p class='status-ok'>🎉 ไม่พบช่องโหว่!</p>"
        else:
            # จัดกลุ่มช่องโหว่ตามระดับความรุนแรง
            for severity in ['วิกฤต', 'สูง', 'ปานกลาง', 'ต่ำ']:
                severity_vulns = [v for v in self.results['vulnerabilities'] if v.get('severity') == severity]
                if severity_vulns:
                    html_content += f"<h3>ช่องโหว่ระดับ{severity} ({len(severity_vulns)} รายการ)</h3>"
                    for vuln in severity_vulns:
                        html_content += f'''
                <div class="vuln-item {severity}">
                    <div class="vuln-severity {severity}">{severity}</div>
                    <strong>{vuln['type']}</strong>
                    <p>{vuln['description']}</p>'''
                        if 'recommendation' in vuln:
                            html_content += f"<p><strong>คำแนะนำ:</strong> {vuln['recommendation']}</p>"
                        if 'cve' in vuln:
                            html_content += f"<p><strong>CVE:</strong> <a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln['cve']}' target='_blank'>{vuln['cve']}</a></p>"
                        if 'port' in vuln:
                            html_content += f"<p><strong>Port:</strong> {vuln['port']}</p>"
                        if 'url' in vuln:
                            html_content += f"<p><strong>URL:</strong> <a href='{vuln['url']}' target='_blank'>{vuln['url']}</a></p>"
                        html_content += '''
                </div>'''
        
        html_content += '''
        </div>
    </div>
</body>
</html>'''
        
        # บันทึกรายงาน HTML
        with open(output_file, 'w', encoding='utf-8') as f:  
            f.write(html_content)
        print(f"[*] บันทึกรายงาน HTML ขั้นสูงเรียบร้อยแล้วที่ {output_file}")

    def run_full_scan(self, port_range="1-1000"):
        """
        เรียกใช้การ Scan ความปลอดภัยแบบสมบูรณ์
        
        Args:
            port_range (str): ช่วง ports ที่จะscan (เช่น "1-1000")
            
        Returns:
            bool: True ถ้าscanสำเร็จ
        """
        self.banner()
        
        # แยกช่วง ports
        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
        else:
            start_port = end_port = int(port_range)
        
        # เริ่มการscan
        if self.port_scan(start_port, end_port):
            # ทำการตรวจหา OS หลังจากscan ports เสร็จ
            ip = self.resolve_target()
            if ip:
                self.os_detection(ip)
            
            # ทำการscan web และตรวจสอบช่องโหว่
            self.web_scan()
            self.vulnerability_check()
            self.generate_html_report()
            
            # บันทึกผลลัพธ์เป็น JSON
            with open('scan_results.json', 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"[*] บันทึกผลลัพธ์ JSON เรียบร้อยแล้วที่ scan_results.json")
            
            # แสดงสรุปผลลัพธ์
            self.print_summary()
            print(f"\n การscanเสร็จสมบูรณ์!")
            return True
        return False
    
    def print_summary(self):
        """แสดงสรุปผลการscan"""
        print(f"\n" + "="*60)
        print(f"                    สรุปผลการscan")
        print(f"="*60)
        print(f"เป้าหมาย: {self.results['target']}")
        print(f"เวลาscan: {self.results['timestamp']}")
        print(f"Ports ที่เปิดอยู่: {len(self.results['open_ports'])}")
        print(f"Web Directories: {len(self.results['web_directories'])}")
        print(f"ช่องโหว่: {len(self.results['vulnerabilities'])}")
        
        if self.results['os_detection'].get('os_type') != 'ไม่ทราบ':
            print(f"การตรวจหา OS: {self.results['os_detection']['os_type']} (ความมั่นใจ: {self.results['os_detection']['confidence']}%)")
        
        # สรุปช่องโหว่ตามระดับความรุนแรง
        vuln_counts = {'วิกฤต': 0, 'สูง': 0, 'ปานกลาง': 0, 'ต่ำ': 0}
        for vuln in self.results['vulnerabilities']:
            severity = vuln.get('severity', 'ต่ำ')
            vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
        
        if any(vuln_counts.values()):
            print(f"\nจำแนกช่องโหว่:")
            for severity, count in vuln_counts.items():
                if count > 0:
                    print(f"  {severity}: {count} รายการ")
        
        print(f"="*60)

def main():
    """ฟังก์ชันหลักของโปรแกรม"""
    # ตั้งค่า command line arguments
    parser = argparse.ArgumentParser(description='Cyber Security Scanner - ตัวอย่างเครื่องมือscanความปลอดภัย')
    parser.add_argument('target', help='targetที่จะscan (IP address หรือ hostname)')
    parser.add_argument('-p', '--ports', default='1-1000', 
                       help='ช่วง ports ที่จะscan (เริ่มต้น: 1-1000)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='จำนวน threads ที่ใช้ (เริ่มต้น: 100)')
    parser.add_argument('-o', '--output', default='scan_report.html',
                       help='ไฟล์รายงาน HTML ที่จะสร้าง')
    
    args = parser.parse_args()
    
    # สร้างและเรียกใช้ scanner
    scanner = CyberSecureScanner(args.target, args.threads)
    scanner.run_full_scan(args.ports)

if __name__ == "__main__":
    main()