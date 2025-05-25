# 🛡️ Cyber Security Scanner

เครื่องมือสแกนความปลอดภัยเครือข่ายและเว็บแอปพลิเคชันขั้นสูง พัฒนาด้วย Python 

## ✨ คุณสมบัติ

### 🔍 Network Security Scanning
- **Multi-threaded Port Scanning** - สแกน ports แบบพร้อมกัน เร็วและมีประสิทธิภาพ
- **Service Detection** - ระบุ services และ grab banners อัตโนมัติ
- **OS Detection** - ตรวจหา Operating System ด้วย TTL analysis และ port fingerprinting

### 🌐 Web Application Testing
- **Directory Enumeration** - ค้นหา hidden directories และ sensitive files
- **SSL/TLS Security Assessment** - ตรวจสอบ certificate และ cipher strength
- **Admin Interface Detection** - ระบุ admin panels ที่เสี่ยง

### ⚠️ Vulnerability Assessment
- **CVE Detection** - ตรวจหาช่องโหว่ที่ทราบแล้ว (เช่น vsftpd backdoor)
- **Insecure Protocol Detection** - ระบุ protocols ที่ไม่ปลอดภัย (Telnet, FTP, etc.)
- **Configuration File Exposure** - ตรวจสอบไฟล์ .env และ config ที่เปิดให้เข้าถึงได้

### 📊 Professional Reporting
- **HTML Report** - รายงานแบบ interactive พร้อม responsive design
- **JSON Export** - ข้อมูลแบบ structured สำหรับการวิเคราะห์เพิ่มเติม
- **Thai Language Support** - รองรับภาษาไทยครบถ้วน

## 🚀 การติดตั้ง

### ความต้องการของระบบ
- Python 3.7 หรือใหม่กว่า
- pip package manager

### วิธีการติดตั้ง

1. **Clone repository**
```bash
git clone https://github.com/yourusername/cyber-secure-scanner.git
cd cyber-secure-scanner
```

2. **ติดตั้ง dependencies**
```bash
pip install -r requirements.txt
```

3. **ทดสอบการทำงาน**
```bash
python cyber_secure_scanner.py --help
```

### Dependencies
```
requests>=2.25.0
```

## 📖 การใช้งาน

### การใช้งานพื้นฐาน

```bash
# สแกนเป้าหมายพื้นฐาน
python cyber_secure_scanner.py google.com

# สแกนช่วง ports เฉพาะ
python cyber_secure_scanner.py 192.168.1.1 -p 1-1000

# ใช้ threads มากขึ้นเพื่อความเร็ว
python cyber_secure_scanner.py target.com -p 1-5000 -t 200
```

### ตัวเลือกทั้งหมด

```bash
python cyber_secure_scanner.py [TARGET] [OPTIONS]

Arguments:
  TARGET                เป้าหมายที่จะสแกน (IP address หรือ hostname)

Options:
  -p, --ports RANGE     ช่วง ports ที่จะสแกน (เริ่มต้น: 1-1000)
  -t, --threads NUM     จำนวน threads (เริ่มต้น: 100)
  -o, --output FILE     ไฟล์รายงาน HTML (เริ่มต้น: scan_report.html)
  -h, --help           แสดงความช่วยเหลือ
```

### ตัวอย่างการใช้งานขั้นสูง

```bash
# สแกน ports เฉพาะ
python cyber_secure_scanner.py target.com -p 22,80,443,3389

# สแกนแบบรวดเร็ว
python cyber_secure_scanner.py scanme.nmap.org -p 1-1000 -t 500

# บันทึกรายงานเป็นชื่อกำหนดเอง
python cyber_secure_scanner.py company.com -o security_audit_2025.html
```

## 📊 ตัวอย่างผลลัพธ์

### Terminal Output
```
========================================================================
                   Cyber  Security Scanner Test                   
                    เครื่องมือประเมินความปลอดภัยขั้นสูง                           
========================================================================

[*] แปลง google.com เป็น 142.250.191.14
[*] เริ่มสแกน ports ของ google.com
[*] สแกน ports 1-1000
--------------------------------------------------
[+] Port 80: เปิดอยู่ - HTTP
[+] Port 443: เปิดอยู่ - HTTPS
[*] การสแกน ports เสร็จสิ้น - พบ 2 ports ที่เปิดอยู่

[*] กำลังตรวจหา Operating System ของ 142.250.191.14
--------------------------------------------------
[+] TTL: 64 -> น่าจะเป็น Linux/Unix
[*] ผลการตรวจหา OS: Linux/Unix (ความมั่นใจ: 70%)
```

### HTML Report Preview
- 📊 Dashboard แบบ cards แสดงสถิติโดยรวม
- 💻 ผลการตรวจหา Operating System พร้อมหลักฐาน
- 🔓 ตาราง Ports และ Services ที่พบ
- 🌐 รายการ Web Directories ที่ตรวจสอบ
- 🔒 ข้อมูล SSL/TLS Certificate (ถ้ามี)
- ⚠️ รายการช่องโหว่จัดกลุ่มตามความรุนแรง

### JSON Output
```json
{
  "target": "google.com",
  "timestamp": "2025-01-28T10:30:45",
  "open_ports": [
    {
      "port": 80,
      "status": "open",
      "service": "HTTP",
      "banner": "HTTP/1.0 200 OK..."
    }
  ],
  "vulnerabilities": [],
  "os_detection": {
    "os_type": "Linux/Unix",
    "confidence": 70,
    "evidence": ["TTL: 64"]
  }
}
```

## 🔧 คุณสมบัติขั้นสูง

### OS Detection Techniques
- **TTL Analysis** - วิเคราะห์ค่า Time-To-Live
- **Port Fingerprinting** - ตรวจสอบ ports เฉพาะของแต่ละ OS
- **Banner Analysis** - วิเคราะห์ service banners
- **Service Stack Detection** - ตรวจสอบ technology stack

### Vulnerability Detection
- **Known CVEs** - ตรวจหา CVE-2011-2523 (vsftpd backdoor)
- **Insecure Protocols** - Telnet, unencrypted FTP
- **Weak SSL/TLS** - เวอร์ชันเก่า, weak ciphers
- **Exposed Interfaces** - Admin panels, config files
- **Information Disclosure** - .env files, backup files

### Performance Optimization
- **Multi-threading** - สแกนหลาย ports พร้อมกัน
- **Thread Pool Management** - จำกัดจำนวน threads เพื่อป้องกัน resource exhaustion
- **Timeout Controls** - ควบคุมเวลา connection timeout
- **Memory Efficient** - ใช้ memory อย่างมีประสิทธิภาพ


