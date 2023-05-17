# ubuntu-wsl2-systemd-script
* This script is to enable systemd support on current Ubuntu WSL2 images from the Windows Store.
* NOTE: May only need to do this for WSL2 on Windows 10. I have not verified if this is not needed on Windows 11.

# Usage
You need `wget` to be installed for the commands below to work. Use
```
sudo apt-get -y install wget
```

Run the script and commands
```
cd /tmp/ && \
wget https://raw.githubusercontent.com/ZacksHomeLab/ZacksHomeLab/main/scripts/WSL2/ubuntu-systemd/enter-systemd-namespace && \
wget https://raw.githubusercontent.com/ZacksHomeLab/ZacksHomeLab/main/scripts/WSL2/ubuntu-systemd/start-systemd-namespace && \
wget https://raw.githubusercontent.com/ZacksHomeLab/ZacksHomeLab/main/scripts/WSL2/ubuntu-systemd/wsl2-ubuntu-systemd.sh && \
bash wsl2-ubuntu-systemd.sh
```
