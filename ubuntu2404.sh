#!/bin/bash
##
# AUTHOR: rewks
# LAST UPDATED: 07/10/2024
# DESCRIPTION: Handles basic installation and configuration of a newly installed Ubuntu 24.04
##
git_username="rewks"
git_email="46387812+rewks@users.noreply.github.com"

# Remove all things CUPS and Avahi
unwanted_services=(
    cups.service
    cups-browsed.service
    cups.path
    cups.socket
    snap.cups.cupsd.service
    snap.cups.cups-browsed.service
    avahi-daemon
    avahi-daemon.socket
)

for service in "${unwanted_services[@]}"; do
    sudo systemctl stop "$service"
    sudo systemctl disable "$service"
done

sudo apt purge cups avahi-daemon --autoremove
sudo snap remove cups
sudo rm -rf /etc/cups /etc/cupshelpers /etc/printcap /usr/share/cups /usr/share/hplip /run/avahi-daemon

# Update repo lists and upgrade packages
sudo apt update
sudo apt upgrade -y

# Install core system or service packages
system_packages=(
    curl
    openssh-server
    smbclient
)

sudo apt install "${system_packages[@]}" -y

# Install docker
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Install language / dev packages
dev_packages=(
    make
    gcc
    python3-pip
    python3-venv
    pipx
    ruby-dev
    php-cli
    dotnet-sdk-8.0
    openjdk-21-jdk
)

sudo apt install "${dev_packages[@]}" -y
pipx ensurepath

# Install golang
wget https://go.dev/dl/go1.23.1.linux-amd64.tar.gz -O /tmp/go1.23.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go1.23.1.linux-amd64.tar.gz
sudo rm /tmp/go1.23.1.linux-amd64.tar.gz

# Install vs code
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list > /dev/null
rm -f packages.microsoft.gpg
sudo apt update
sudo apt install code -y

# Install utility packages
utility_packages=(
    terminator
    xclip
    lsd
    fd-find
    bat
    ripgrep
    vim
    jq
    git
    whois
    flameshot
    cifs-utils
    p7zip-full
    libreoffice-calc
)

sudo apt install "${utility_packages[@]}" -y

# Configure git profile
git config --global user.name $git_username
git config --global user.email $git_email

# Download lsd config files
mkdir -p $HOME/.config/lsd
curl -s https://raw.githubusercontent.com/rewks/ubuntu2404-setup/refs/heads/main/lsd_config.yaml -o $HOME/.config/lsd/config.yaml
curl -s https://raw.githubusercontent.com/rewks/ubuntu2404-setup/refs/heads/main/lsd_colors.yaml -o $HOME/.config/lsd/colors.yaml

# Download and install Iosevka nerd font
wget https://github.com/ryanoasis/nerd-fonts/releases/download/v3.2.1/IosevkaTerm.zip -O /tmp/IosevkaTerm.zip
sudo mkdir -p /usr/share/fonts/iosevka
sudo unzip /tmp/IosevkaTerm.zip -d /usr/share/fonts/iosevka/
rm /tmp/IosevkaTerm.zip
sudo fc-cache -f -v

# Download terminator config file
mkdir -p $HOME/.config/terminator
curl -s https://raw.githubusercontent.com/rewks/ubuntu2404-setup/refs/heads/main/terminator_config -o $HOME/.config/terminator/config

# Install neovim
wget https://github.com/neovim/neovim/releases/download/v0.10.1/nvim-linux64.tar.gz -O /tmp/nvim-linux64.tar.gz
sudo tar xzvf /tmp/nvim-linux64.tar.gz -C /usr/share/
sudo ln -s /usr/share/nvim-linux64/bin/nvim /usr/local/bin/nvim
rm /tmp/nvim-linux64.tar.gz

# Install NvChad and download config files
git clone https://github.com/NvChad/starter $HOME/.config/nvim  && rm -rf $HOME/.config/nvim/.git # Need to run nvim and then type :MasonInstallAll
curl -s https://raw.githubusercontent.com/rewks/ubuntu2404-setup/refs/heads/main/nvim_chadrc.lua -o $HOME/.config/nvim/lua/chadrc.lua
curl -s https://raw.githubusercontent.com/rewks/ubuntu2404-setup/refs/heads/main/nvim_mappings.lua -o $HOME/.config/nvim/lua/mappings.lua
echo 'vim.opt.clipboard = "unnamedplus"' >> $HOME/.config/nvim/init.lua

# Install DevOps tools: terraform, ansible and aws cli
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform -y

pipx install --include-deps ansible

curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip /tmp/awscliv2.zip -d /tmp
sudo /tmp/aws/install
rm -rf /tmp/aws /tmp/awscliv2.zip

# Install networking/security/ctf packages
security_packages=(
    nmap
    arp-scan
    mysql-client
    wireshark
    proxychains4
    netcat-traditional
    snmp
    snmp-mibs-downloader
    sslscan
)

sudo apt install "${security_packages[@]}" -y
sudo usermod -aG wireshark $(whoami)
sudo rm /etc/alternatives/nc
sudo ln -s /usr/bin/nc.traditional /etc/alternatives/nc

pipx install impacket
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install bbot

gem install --user-install winrm
gem install --user-install winrm-fs
gem install --user-install rex-text
gem install --user-install evil-winrm
gem install --user-install wpscan

# Download standalone scripts/tools
declare -A scripts=(
  ["sort_domains.py"]="https://gist.githubusercontent.com/rewks/ad01f1ecacc68f16a8369da3cf36dd3a/raw/d1f0b0537107fdf5db5d816c7edb373680bd4fac/sort_domains.py"
  ["ip_expander.py"]="https://gist.githubusercontent.com/rewks/342e0c845687def1b7695c25c628feea/raw/8c3a168be8f7f9cde6f0ae1ced0810e5adb534e8/ip_expander.py"
  ["crt_search.py"]="https://gist.githubusercontent.com/rewks/f157d2f5e7fe6e1ec64c1026692612d0/raw/fdc86357fd0e59649ebeae71fd041662e2a85e22/crt_search.py"
  ["rsg"]="https://gist.githubusercontent.com/rewks/215d1cd2b68e1a07646a8c3eab3a3d51/raw/3cde967e49d7943f593c82a8d1813d428349434e/rsg.sh"
  ["windapsearch"]="https://github.com/ropnop/go-windapsearch/releases/download/v0.3.0/windapsearch-linux-amd64"
)

for filename in "${!scripts[@]}"; do
  sudo wget "${scripts[$filename]}" -O "/usr/local/bin/$filename"
  sudo chmod +x "/usr/local/bin/$filename"
done

# Install golang tools
/usr/local/go/bin/go install github.com/sensepost/gowitness@latest
/usr/local/go/bin/go install github.com/projectdiscovery/httpx/cmd/httpx@latest
/usr/local/go/bin/go install github.com/ffuf/ffuf/v2@latest
/usr/local/go/bin/go install github.com/ropnop/kerbrute@latest
/usr/local/go/bin/go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Download and build nbtscan (unixwiz version)
mkdir -p /tmp/nbtscan
wget http://www.unixwiz.net/tools/nbtscan-source-1.0.35.tgz -O /tmp/nbtscan-source-1.0.35.tgz
tar -xzf /tmp/nbtscan-source-1.0.35.tgz -C /tmp/nbtscan/
cd /tmp/nbtscan
make
sudo mv nbtscan /usr/local/bin/nbtscan
cd -
rm -rf /tmp/nbtscan /tmp/nbtscan-source-1.0.35.tgz

# Download and install onesixtyone
git clone https://github.com/trailofbits/onesixtyone.git /tmp/onesixtyone
cd /tmp/onesixtyone
gcc -o onesixtyone onesixtyone.c
sudo mv onesixtyone /usr/local/bin/onesixtyone
cd -
rm -rf /tmp/onesixtyone

sudo chown root:$(whoami) /opt
sudo chmod 774 /opt

# Download and configure Responder
git clone https://github.com/lgandx/Responder.git /opt/Responder
sed -Ei 's/^(DNS[[:space:]]*= )On/\1Off/' /opt/Responder/Responder.conf
sed -i 's/^Challenge = Random/Challenge = 1122334455667788/' /opt/Responder/Responder.conf
sed -i 's/= certs/= \/opt\/Responder\/certs/g' /opt/Responder/Responder.conf
sed -i 's/certs/\/opt\/Responder\/certs/g' /opt/Responder/certs/gen-self-signed-cert.sh
/opt/Responder/certs/gen-self-signed-cert.sh

# Create python virtual environments for individual tools
mkdir -p $HOME/.venvs

python3 -m venv $HOME/.venvs/mitm6
source $HOME/.venvs/mitm6/bin/activate
pip install mitm6
deactivate

python3 -m venv $HOME/.venvs/sqlmap
source $HOME/.venvs/sqlmap/bin/activate
pip install sqlmap
deactivate

python3 -m venv $HOME/.venvs/coercer
source $HOME/.venvs/coercer/bin/activate
pip install coercer
deactivate

python3 -m venv $HOME/.venvs/certipy
source $HOME/.venvs/certipy/bin/activate
pip install certipy-ad
deactivate

python3 -m venv $HOME/.venvs/ssh-audit
source $HOME/.venvs/ssh-audit/bin/activate
pip install ssh-audit
deactivate

git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
python3 -m venv $HOME/.venvs/enum4linux
source $HOME/.venvs/enum4linux/bin/activate
pip install -r /opt/enum4linux-ng/requirements.txt
ln -s /opt/enum4linux-ng/enum4linux-ng.py $HOME/.venvs/enum4linux/bin/enum4linux
deactivate

git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool
chmod +x /opt/jwt_tool/jwt_tool.py
python3 -m venv $HOME/.venvs/jwt_tool
source $HOME/.venvs/jwt_tool/bin/activate
pip install -r /opt/jwt_tool/requirements.txt
ln -s /opt/jwt_tool/jwt_tool.py $HOME/.venvs/jwt_tool/bin/jwt_tool
deactivate

# Install metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
chmod 755 /tmp/msfinstall
sudo /tmp/msfinstall
rm /tmp/msfinstall

# Download seclists, unzip rockyou
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
tar xzvf /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /opt/SecLists/Passwords/

# Gather commonly used postex tools
mkdir -p $HOME/tools/linux
mkdir -p $HOME/tools/windows/sysinternals

cp /usr/bin/nc.traditional $HOME/tools/linux/nc

curl -s https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py -o $HOME/tools/linux/suid3num.py
chmod 755 $HOME/tools/linux/suid3num.py

pspy_url=$(curl -s https://api.github.com/repos/DominicBreuker/pspy/releases | jq -r '.[0].assets[] | select(.name == "pspy64") | .browser_download_url')
curl -L -s -o $HOME/tools/linux/pspy64 $pspy_url
chmod 755 $HOME/tools/linux/pspy64

curl -s https://download.sysinternals.com/files/SysinternalsSuite.zip -o $HOME/tools/windows/SysinternalsSuite.zip
unzip $HOME/tools/windows/SysinternalsSuite.zip -d $HOME/tools/windows/sysinternals/

declare -A files=(
  ["linpeas.sh"]="$HOME/tools/linux/linpeas.sh"
  ["winPEAS.bat"]="$HOME/tools/windows/winPEAS.bat"
  ["winPEASx64.exe"]="$HOME/tools/windows/winPEASx64.exe"
  ["winPEASx86.exe"]="$HOME/tools/windows/winPEASx86.exe"
)
peas_releases=$(curl -s https://api.github.com/repos/peass-ng/PEASS-ng/releases)
for file in "${!files[@]}"; do
  peas_url=$(echo $peas_releases | jq -r --arg file $file '.[0].assets[] | select(.name == $file) | .browser_download_url')
  curl -L -s -o ${files[$file]} $peas_url
done
chmod 755 $HOME/tools/linux/linpeas.sh

# Install RE/pwn tools
pwn_packages=(
  gdbserver
)

sudo apt install "${pwn_packages[@]}" -y

latest_gef=$(curl -s https://api.github.com/repos/hugsy/gef/tags | jq -r '.[0].name')
curl -s https://raw.githubusercontent.com/hugsy/gef/$latest_gef/gef.py -o /opt/gef.py
echo 'set disassembly-flavor intel' >> $HOME/.gdbinit
echo 'source /opt/gef.py' >> $HOME/.gdbinit

python3 -m venv $HOME/.venvs/pwn
source $HOME/.venvs/pwn/bin/activate
pip install pwntools
pip install capstone
pip install filebytes
pip install keystone-engine
pip install ropper
pip uninstall ROPgadget -y
pip install ROPgadget
deactivate

latest_ghidra=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases | jq -r '.[0].["assets"][0]["browser_download_url"]')
wget $latest_ghidra -O /opt/ghidra.zip 
unzip /opt/ghidra.zip -d /opt/
rm /opt/ghidra.zip

# Add aliases and path update to .bashrc
cat <<EOF >> $HOME/.bashrc
alias vi='nvim'
alias ls='lsd'
alias fd='fdfind'
alias cat='batcat -P'
alias responder='sudo python3 /opt/Responder/Responder.py'
alias ffuf='ffuf -c -ic'
alias gdb='gdb -q'
alias pattern_create='/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb'
alias pattern_offset='/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb'
alias ghidra='/opt/$(ls -1 /opt | grep ghidra)/ghidraRun'

export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin:\$HOME/.local/share/gem/ruby/3.2.0/bin
EOF

# Script finished, instructions for manual stuff
echo -e "\e[1;31mIMPORTANT:\e[0m"
echo "- Manual interaction needed to complete setup: run nvim and then type :MasonInstallAll"
echo "- "

