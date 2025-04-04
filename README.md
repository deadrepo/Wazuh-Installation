# Wazuh-Installation Ubuntu
[Wazuh Installation] Guide on Installing Wazuh on Ubuntu

# Install Wazuh
curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

# Check password for Dashboard etc
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt

# Run below url
https://<WAZUH_DASHBOARD_IP_ADDRESS>

# Check your IP
ifconifg

#Agent installation



## 🔍 Security Events Detected by Wazuh

Wazuh is a powerful open-source SIEM solution capable of detecting a wide variety of security events beyond simple SSH failures. Here’s an overview of the event types it can monitor and alert on:

### 🔐 Authentication & Access Monitoring
- Failed and successful login attempts (SSH, RDP, web, etc.)
- Brute-force attacks
- Account lockouts
- Privilege escalation (e.g., `sudo`, `su`)
- User/group creation and permission changes

### 📁 System & File Monitoring
- File integrity changes (via FIM)
- Unauthorized modifications to system files
- Crontab or startup script changes
- File and directory permission alterations

### 📦 Software & Package Auditing
- Software installations and removals
- Detection of vulnerable packages
- Usage of suspicious tools (e.g., `nmap`, `netcat`)

### 🛠️ Rootkit & Malware Detection
- Suspicious kernel modules
- Hidden processes or files
- Known IOCs (Indicators of Compromise)
- Unusual ports or network connections

### 🌐 Network Activity Detection
- Port scanning
- Outbound connections to blacklisted IPs/domains
- Network anomalies

### 🌐 Web & Application Security
- Web server attack detection (e.g., SQLi, XSS)
- Integration with ModSecurity/WAF
- Application logs (Apache, Nginx, MySQL, etc.)

### 📋 Compliance & Policy Violations
- CIS benchmark violations
- Unauthorized configuration changes
- Compliance reporting (PCI-DSS, GDPR, HIPAA)

### 🧠 Behavioral Analysis
- Unusual login times or geolocations
- Lateral movement detection
- Execution of suspicious scripts or binaries

> Note: Detection capabilities depend on agent configuration and integrations with threat intelligence sources.

---

