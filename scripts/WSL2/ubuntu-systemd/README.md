# ubuntu-wsl2-systemd-script
* This script is to enable systemd support on current Ubuntu WSL2 images from the Windows Store.

# Usage
You need `wget` to be installed for the commands below to work. Use
```
sudo apt-get -y install wget
```

Run the script and commands
```
wget -o /tmp/wsl2-ubuntu-systemd.sh 
```

```
cd /tmp/ && \
bash wsl2-ubuntu-systemd.sh
# Enter your password and wait until the script has finished
```