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

