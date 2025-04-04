---

# 📦 Wazuh Installation on Ubuntu

This is a quick-start guide for installing **Wazuh** on Ubuntu and understanding the types of security events it can detect.

---

## 🚀 Install Wazuh (Manager, Dashboard & Filebeat)

Run the following command to download and install Wazuh:

curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

This installs:
- Wazuh Manager
- Wazuh Dashboard
- Filebeat (for forwarding logs to Elasticsearch)

---

## 🔑 Retrieve Dashboard Credentials

After installation, extract the credentials needed to log into the Wazuh Dashboard:

sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt

---

## 📊 Access the Wazuh Dashboard

Once Wazuh is installed and running, access the dashboard by opening this URL in your browser:

https://<WAZUH_DASHBOARD_IP_ADDRESS>

> Replace `<WAZUH_DASHBOARD_IP_ADDRESS>` with your server’s IP address.

---

## 🌐 Check Your IP Address

To find your system's IP address:

ifconfig

> If `ifconfig` is not available, install it with:

sudo apt install net-tools

---

## 🤖 Wazuh Agent Installation

To install a Wazuh agent on a client machine:

curl -sO https://packages.wazuh.com/4.x/apt/install.sh && sudo bash ./install.sh

Connect the agent to the Wazuh manager:

sudo /var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP>

Enable and start the agent:

sudo systemctl enable wazuh-agent  
sudo systemctl start wazuh-agent

> Replace `<WAZUH_MANAGER_IP>` with the IP address of your Wazuh manager.

---

## 🔍 Security Events Detected by Wazuh

Wazuh is a powerful open-source SIEM solution capable of detecting a wide variety of security events. Here’s an overview of what it can monitor and alert on:

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

> Note: Detection capabilities depend on agent configuration and integration with external threat intelligence sources.

---

## 📚 References

- Official Wazuh Documentation: https://documentation.wazuh.com/
- Wazuh GitHub: https://github.com/wazuh/wazuh
- Wazuh Community: https://wazuh.com/community/

---
