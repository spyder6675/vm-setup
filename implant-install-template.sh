#!/bin/bash

# implant_install_tools.sh
# This script assumes that the user is running as root.
# Designed for kali image implants

# Check if user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

# Initialize a variable to track the flag status
INSTALL_NESSUS=0

# Loop through all the arguments
for arg in "$@"
do
  case $arg in
    --install-nessus)
      INSTALL_NESSUS=1
      break # No need to continue loop if the flag is found
      ;;
    *)
      # Handle or ignore other arguments
      ;;
  esac
done

#####[ Colors ]######
RED='\033[1;38;5;196m'
ORANGE='\033[1;38;5;1m'
PURPLE='\033[1;38;5;92m'
BLUE='\033[1;38;5;32m'
GREEN='\033[1;92m'
BOLD='\033[1m'
RESET='\033[0m'

check_hardware_requirements() {
    ALL_GOOD=true

    echo -e "${PURPLE}[*]${RESET} Checking implant system requirements:\nCPU >= 4\tRAM >= 8 GB\n"

    NUM_CPUS=$(lscpu | grep 'CPU(s):' | head -n 1 | awk '{print $NF}')
    if (( "$NUM_CPUS" < 4 )); then
        ALL_GOOD=false
        echo -e "${RED}[-]${RESET}${BOLD} Implant has INSUFFICIENT CPUs! CPU(s): ${NUM_CPUS} REACH OUT TO CUSTOMER ${RESET}"
    else
        echo -e "${GREEN}[+]${RESET}${BOLD} CPU(s): ${NUM_CPUS} ${RESET}"
    fi

    TOTAL_RAM=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if (( "$TOTAL_RAM" < 8000000 )); then
        ALL_GOOD=false
        echo -e "${RED}[-]${RESET}${BOLD} Implant has INSUFFICIENT MEMORY.. Total Ram: ${TOTAL_RAM} kB. REACH OUT TO CUSTOMER ${RESET}"
    else
        echo -e "${GREEN}[+]${RESET}${BOLD} Total RAM: ${TOTAL_RAM} kB ${RESET}"
    fi

    if ! $ALL_GOOD ; then
        echo -e "${ORANGE}[!]${RESET}${BOLD} You must construct additional pylons ${RESET}"
    else
        echo -e "${BLUE}[+]${RESET}${BOLD} All systems good to go! ${RESET}"
    fi
}

install_apt_packages() {
    # apt packages
    # apt-get update -y && apt-get full-upgrade -y
    apt-get update -y
    apt-get install python3 -y
    apt-get install virtualenv -y
    apt-get install python3-distutils python3-virtualenv libssl-dev libffi-dev python-dev-is-python3 build-essential smbclient libpcap-dev -y
    apt-get install git make gcc -y
    apt-get install vim-nox htop ncat rlwrap golang feroxbuster silversearcher-ag testssl.sh nmap masscan proxychains4 -y
    apt-get install python3-venv -y
    apt-get install pipx -y
    apt-get install samba onesixtyone snmp-mibs-downloader -y
    apt-get install libkrb5-dev krb5-config -y
    # Install latest metasploit
    gem install bundler
    apt-get install metasploit-framework -y

    ### My adds
    apt install -y grc ipcalc ripgrep tmux screen sendemail libxml2-utils libxml2-dev libxslt1-dev
    apt install -y whatweb smbmap tftp-hpa telnet sqlmap rsh-client rsync inotify-tools dirsearch eyewitness
    apt install -y remmina remmina-plugin-rdp remmina-plugin-secret
    apt install -y dnstwist
    apt install -y httpx-toolkit
    apt install -y urlcrazy ntpsec
    apt install -y python3-venv
    apt install -y dnsrecon gedit 
    apt install -y jq
    # apt install -y syncthing
    apt install -y apt-transport-https


    # remove outdated packages
    apt-get autoremove -y

    # update snmp.conf
    sed -e '/mibs/ s/^#*/#/' -i /etc/snmp/snmp.conf
}

clone_git_repos() {
    # Repos
    # Needed for GoRecon Modules
    # [[ ! -d /opt/BloodHound.py ]] && git clone https://github.com/dirkjanm/bloodhound.py /opt/BloodHound.py
    # [[ ! -d /opt/CrackMapExec ]] && git clone https://github.com/byt3bl33d3r/CrackMapExec.git /opt/CrackMapExec
    # [[ ! -d /opt/SecLists ]] && git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
    # [[ ! -d /opt/TODO ]] &&  git clone TODO /opt/TODO
    # [[ ! -d /opt/testssl.sh ]] && git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
    [[ ! -d /opt/AADInternals ]] &&  git clone https://github.com/Gerenios/AADInternals.git /opt/AADInternals
    [[ ! -d /opt/ADCSync ]] && git clone https://github.com/JPG0mez/ADCSync.git /opt/ADCSync
    [[ ! -d /opt/BloodHound.py ]] && git clone https://github.com/fox-it/BloodHound.py.git /opt/BloodHound.py
    [[ ! -d /opt/BruteLoops ]] &&  git clone https://github.com/arch4ngel/BruteLoops.git /opt/BruteLoops
    [[ ! -d /opt/CeWL ]] && git clone https://github.com/digininja/CeWL.git /opt/CeWL
    [[ ! -d /opt/Certipy ]] && git clone https://github.com/ly4k/Certipy.git /opt/Certipy
    [[ ! -d /opt/Coercer ]] && git clone https://github.com/p0dalirius/Coercer.git /opt/Coercer
    [[ ! -d /opt/CredMaster ]] && git clone https://github.com/knavesec/CredMaster.git /opt/CredMaster
    [[ ! -d /opt/DPAT ]] &&  git clone https://github.com/clr2of8/DPAT.git /opt/DPAT
    [[ ! -d /opt/DomainPasswordSpray ]] &&  git clone https://github.com/dafthack/DomainPasswordSpray.git /opt/DomainPasswordSpray
    [[ ! -d /opt/DonPAPI ]] && git clone https://github.com/login-securite/DonPAPI.git /opt/DonPAPI
    [[ ! -d /opt/EyeWitness ]] && git clone https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness
    [[ ! -d /opt/Go365 ]] &&  git clone https://github.com/optiv/Go365.git /opt/Go365
    [[ ! -d /opt/KrbRelayUp ]] &&  git clone https://github.com/Dec0ne/KrbRelayUp.git /opt/KrbRelayUp
    [[ ! -d /opt/LdapRelayScan ]] &&  git clone https://github.com/zyn3rgy/LdapRelayScan.git /opt/LdapRelayScan
    [[ ! -d /opt/MFASweep ]] && git clone https://github.com/dafthack/MFASweep.git /opt/MFASweep
    [[ ! -d /opt/MSOLSpray ]] && git clone https://github.com/dafthack/MSOLSpray.git /opt/MSOLSpray
    [[ ! -d /opt/MailSniper ]] &&  git clone https://github.com/dafthack/MailSniper.git /opt/MailSniper
    [[ ! -d /opt/NetExec ]] && git clone https://github.com/Pennyw0rth/NetExec.git /opt/NetExec
    [[ ! -d /opt/PCredz ]] && git clone https://github.com/lgandx/PCredz.git /opt/PCredz
    [[ ! -d /opt/PKINITtools ]] && git clone https://github.com/dirkjanm/PKINITtools.git /opt/PKINITtools
    [[ ! -d /opt/PXEThief ]] && git clone https://github.com/MWR-CyberSec/PXEThief.git /opt/PXEThief
    [[ ! -d /opt/PetitPotam ]] && git clone https://github.com/topotam/PetitPotam.git /opt/PetitPotam
    [[ ! -d /opt/PlumHound ]] && git clone https://github.com/PlumHound/PlumHound.git /opt/PlumHound
    [[ ! -d /opt/PowerUpSQL ]] &&  git clone https://github.com/NetSPI/PowerUpSQL.git /opt/PowerUpSQL
    [[ ! -d /opt/Responder ]] && git clone https://github.com/lgandx/Responder.git /opt/Responder
    [[ ! -d /opt/SIGIT ]] &&  git clone https://github.com/termuxhackers-id/SIGIT.git /opt/SIGIT
    [[ ! -d /opt/SQLAutoPwn ]] &&  git clone https://github.com/Wh1t3Rh1n0/SQLAutoPwn.git /opt/SQLAutoPwn
    [[ ! -d /opt/Spray365 ]] &&  git clone https://github.com/MarkoH17/Spray365.git /opt/Spray365
    [[ ! -d /opt/SprayingToolkit ]] &&  git clone https://github.com/byt3bl33d3r/SprayingToolkit.git /opt/SprayingToolkit
    [[ ! -d /opt/WebclientServiceScanner ]] && git clone https://github.com/Hackndo/WebclientServiceScanner.git /opt/WebclientServiceScanner
    [[ ! -d /opt/certsync ]] && git clone https://github.com/zblurx/certsync.git /opt/certsync
    [[ ! -d /opt/ciscot7 ]] && git clone https://github.com/theevilbit/ciscot7.git /opt/ciscot7
    [[ ! -d /opt/dnstwist ]] && git clone https://github.com/elceef/dnstwist.git /opt/dnstwist
    [[ ! -d /opt/eavesarp ]] && git clone https://github.com/ImpostorKeanu/eavesarp.git /opt/eavesarp
    [[ ! -d /opt/enum4linux-ng ]] &&  git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
    [[ ! -d /opt/fireprox ]] && git clone https://github.com/ustayready/fireprox.git /opt/fireprox
    [[ ! -d /opt/gitleaks ]] && git clone https://github.com/gitleaks/gitleaks.git /opt/gitleaks
    [[ ! -d /opt/hardcidr ]] && git clone https://github.com/trustedsec/hardcidr.git /opt/hardcidr
    [[ ! -d /opt/impacket ]] && git clone https://github.com/fortra/impacket.git /opt/impacket
    [[ ! -d /opt/kerbrute ]] && git clone https://github.com/ropnop/kerbrute.git /opt/kerbrute
    [[ ! -d /opt/krbrelayx ]] && git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx
    [[ ! -d /opt/ldeep ]] && git clone https://github.com/franc-pentest/ldeep /opt/ldeep
    [[ ! -d /opt/malwoverview ]] && git clone https://github.com/alexandreborges/malwoverview.git /opt/malwoverview
    [[ ! -d /opt/masscan ]] && git clone https://github.com/robertdavidgraham/masscan.git /opt/masscan
    [[ ! -d /opt/mitm6 ]] && git clone https://github.com/dirkjanm/mitm6.git /opt/mitm6
    [[ ! -d /opt/o365spray ]] && git clone https://github.com/0xZDH/o365spray.git /opt/o365spray
    [[ ! -d /opt/parsuite ]] &&  git clone https://github.com/arch4ngel/parsuite.git /opt/parsuite
    [[ ! -d /opt/pre2k ]] && git clone https://github.com/garrettfoster13/pre2k.git /opt/pre2k
    [[ ! -d /opt/pyLAPS ]] && git clone https://github.com/p0dalirius/pyLAPS.git /opt/pyLAPS
    [[ ! -d /opt/rdp-sec-check ]] && git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git /opt/rdp-sec-check
    [[ ! -d /opt/sccmhunter ]] && git clone https://github.com/garrettfoster13/sccmhunter.git /opt/sccmhunter
    [[ ! -d /opt/ssh-audit ]] &&  git clone https://github.com/mr-pmillz/ssh-audit.git /opt/ssh-audit
    [[ ! -d /opt/testssl.sh ]] && git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
    [[ ! -d /opt/trufflehog ]] && git clone https://github.com/trufflesecurity/trufflehog.git /opt/trufflehog
    [[ ! -d /opt/usernamer ]] &&  git clone https://github.com/jseidl/usernamer.git /opt/usernamer
    [[ ! -d /tmp/testssl.sh ]] &&  git clone https://github.com/drwetter/testssl.sh.git /tmp/testssl.sh
    [[ ! -d /opt/sslscan ]] &&  git clone https://github.com/rbsec/sslscan.git /opt/sslscan
    [[ ! -d /opt/winshock-test ]] &&  git clone https://github.com/anexia-it/winshock-test.git /opt/winshock-test
    [[ ! -d /opt/ike-scan ]] &&  git clone https://github.com/royhills/ike-scan.git /opt/ike-scan
    [[ ! -d /opt/ikeforce ]] &&  git clone https://github.com/SpiderLabs/ikeforce.git /opt/ikeforce
    [[ ! -d /opt/wpscan ]] &&  git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
    [[ ! -d /opt/pymeta ]] &&  git clone https://github.com/m8r0wn/pymeta.git /opt/pymeta
    [[ ! -d /opt/ntlmv1-multi ]] &&  git clone https://github.com/evilmog/ntlmv1-multi.git /opt/ntlmv1-multi
    [[ ! -d /opt/SIET ]] &&  git clone https://github.com/frostbits-security/SIET.git /opt/SIET
    # Needed for GoRecon Modules
    [[ ! -d /tmp/testssl.sh ]] &&  git clone https://github.com/drwetter/testssl.sh.git /tmp/testssl.sh
    [[ ! -d /opt/enum4linux-ng ]] &&  git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
    [[ ! -d /opt/ssh-audit ]] &&  git clone https://github.com/mr-pmillz/ssh-audit.git /opt/ssh-audit
    ### pr_SystemDPAPIdump
    wget https://codeload.github.com/clavoillotte/impacket/zip/refs/heads/pr_SystemDPAPIdump -P /opt/pr_SystemDPAPIdump
    
}

configure_terminal() {

cat << 'EOF' >> "${HOME}/.screenrc"
termcapinfo * ti@:te@
caption always
caption string "%{kw}%-w%{wr}%n %t%{-}%+w"
startup_message off
defscrollback 1000000
EOF

# fix ~/.zshrc bind keys for HOME and END keys
sed -i -e 's/bindkey '\''\^\[\[H'\'' beginning-of-line/bindkey "\\e[1~" beginning-of-line/' \
-e 's/bindkey '\''\^\[\[F'\'' end-of-line/bindkey "\\e[4~" end-of-line/' ~/.zshrc || echo -e "[-] failed to update ~/.zshrc bind keys"

# setup GOPATH. Lots of confusion about GOPATH and GOMODULES
# see https://zchee.github.io/golang-wiki/GOPATH/ and https://maelvls.dev/go111module-everywhere/ for more info
# TL:DR
# GOPATH is still supported even though it has been replaced by Go modules and is technically deprecated since Go 1.16, BUT, you can still use GOPATH to specify where you want your go binaries installed.
[[ ! -d "${HOME}/go" ]] && mkdir "${HOME}/go"
if [[ -z "${GOPATH}" ]]; then
cat << 'EOF' >> "${HOME}/.zshrc"

# Add ~/go/bin to path
[[ ":$PATH:" != *":${HOME}/go/bin:"* ]] && export PATH="${PATH}:${HOME}/go/bin"
# Set GOPATH
if [[ -z "${GOPATH}" ]]; then export GOPATH="${HOME}/go"; fi
EOF
fi

[[ ":$PATH:" != *":${HOME}/go/bin:"* ]] && export PATH="${PATH}:${HOME}/go/bin"
# Set GOPATH
if [[ -z "${GOPATH}" ]]; then export GOPATH="${HOME}/go"; fi

}

install_go_tools() {
    # Install your favorite Go binaries
    # GO111MODULE=on go install github.com/mr-pmillz/gorecon/v2@latest Use the private version from our Gitlab
    GO111MODULE=on go install github.com/ropnop/kerbrute@latest
    GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    [[ -f "/usr/bin/httpx" ]] && mv /usr/bin/httpx /usr/bin/httpx.bak || echo "could not move /usr/bin/httpx to /usr/bin/httpx.bak"
    GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    GO111MODULE=on go install -v github.com/OJ/gobuster/v3@latest
    GO111MODULE=on go install github.com/lkarlslund/ldapnomnom@latest
    GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    [[ -f "${HOME}/go/bin/nuclei" ]] && nuclei -ut || echo "nuclei not in ${HOME}/go/bin/"
}

# ignore shellcheck warnings for source commands
# shellcheck source=/dev/null
install_with_virtualenv() {
    REPO_NAME="$1"
    PYENV="${HOME}/pyenv"
    if [ -d "/opt/${REPO_NAME}" ]; then
        cd "/opt/${REPO_NAME}" || exit 1
        virtualenv -p python3 "${PYENV}/${REPO_NAME}"
        . "${PYENV}/${REPO_NAME}/bin/activate"
        python3 -m pip install -U wheel setuptools
        # first, ensure that requirements.txt deps are installed.
        [[ -f requirements.txt ]] && python3 -m pip install -r requirements.txt
        # python3 setup.py install is deprecated in versions >= python3.9.X
        # python3 -m pip install . will handle the setup.py file for you.
        [[ -f setup.py || -f pyproject.toml ]] && python3 -m pip install .
        deactivate
        cd - &>/dev/null || exit 1
    else
        echo -e "${REPO_NAME} does not exist."
    fi
}

install_masscan() {
    [[ -d /opt/masscan ]] && cd /opt/masscan || exit 1
    make
    make install
}

install_with_pipx() {
    REPO_NAME="$1"
    if [ -d "/opt/${REPO_NAME}" ]; then
        cd "/opt/${REPO_NAME}" || exit 1
        pipx install .
        cd - &>/dev/null || exit 1
    else
        echo -e "${REPO_NAME} does not exist."
    fi
}

install_pipx() {
    # check if pipx is already installed. it should already be installed via apt-get from install_apt_packages function.
    PIPX_EXISTS=$(which pipx)
    if [ -z "$PIPX_EXISTS" ]; then
        # Get the Python 3 version
        python_version_output=$(python3 --version 2>&1)
        python_version=$(echo "$python_version_output" | awk '{print $2}' | cut -d '.' -f 1,2)

        if [ "$python_version" == "3.10" ] || [ "$python_version" == "3.11" ] || [ "$python_version" == "3.12" ]; then
            python3 -m pip install pipx --break-system-packages || apt-get update -y ; apt-get install pipx -y
            # pipx ensurepath adds $HOME/.local/bin to ~/.zshrc
            pipx ensurepath
        else
            python3 -m pip install pipx --user || apt-get update -y ; apt-get install pipx -y
            # pipx ensurepath adds $HOME/.local/bin to ~/.zshrc
            pipx ensurepath
        fi
    else
        pipx ensurepath
    fi
}

# Install NetExec latest
install_netexec() {
    if [ -e "$HOME"/.local/bin/netexec ]; then
        echo -e "[+] NetExec is already installed at ${HOME}/.local/bin/netexec"
        # Initialize CME database
        "$HOME"/.local/bin/netexec smb --help
    else
        echo -e "[+] installing latest version of NetExec via pipx"
        [[ -d /opt/NetExec ]] && cd /opt/NetExec && pipx install .

        if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
            export PATH="${PATH}:${HOME}/.local/bin"
        fi
        # Initialize CME database
        "$HOME"/.local/bin/netexec smb --help
    fi
}


install_eyewitness() {
    # Install EyeWitness
    # EyeWitness project was not initially created with python3 virtual environments in mind and handles dependency installs via setup.sh
    # Long story short, if you try to use a virtualenv for EyeWitness, it will just be ignored unless you modify setup.sh to support them because the setup.sh bash script is not virtualenv context aware.
    # TL:DR no need for virtualenv for EyeWitness.
    echo -e "Installing EyeWitness"
    [[ -d /opt/EyeWitness/Python/setup ]] && cd /opt/EyeWitness/Python/setup && bash setup.sh
    # EyeWitness Selenium Fix
    python3 -m pip install selenium==4.9.1 --break-system-packages
    cd - &>/dev/null || exit 1
}

install_ruby_tools() {
    # Install Evil-WinRM
    gem install evil-winrm
}

# Download and Install the latest debian10 Nessus amd64
download_and_install_latest_nessus() {
    NESSUS_LATEST_URL=$(curl -s https://www.tenable.com/downloads/api/v2/pages/nessus --header 'accept: application/json' | jq -r '.releases.latest' | jq -r '.[][].file_url' | grep 'Nessus-latest-debian10_amd64.deb')
    [[ ! -d "${HOME}/Downloads" ]] && mkdir "${HOME}/Downloads"
    cd "${HOME}/Downloads" && wget "$NESSUS_LATEST_URL" -O Nessus-latest-debian10_amd64.deb
    sudo dpkg -i Nessus-latest-debian10_amd64.deb
}

# Download the latest debian10 Nessus amd64
download_latest_nessus() {
    NESSUS_LATEST_URL=$(curl -s https://www.tenable.com/downloads/api/v2/pages/nessus --header 'accept: application/json' | jq -r '.releases.latest' | jq -r '.[][].file_url' | grep 'Nessus-latest-debian10_amd64.deb')
    [[ ! -d "${HOME}/executables" ]] && mkdir "${HOME}/executables"
    wget "$NESSUS_LATEST_URL" -O "${HOME}/executables/"Nessus-latest-debian10_amd64.deb
    # sudo dpkg -i Nessus-latest-debian10_amd64.deb
    # cd "${HOME}"
}

#############################
# MAIN ######################
#############################

main() {
    install_apt_packages
    clone_git_repos
    configure_terminal
    install_go_tools

    # create virtualenv dir.
    [[ ! -d "${HOME}/pyenv" ]] && mkdir "${HOME}/pyenv"

    # install_with_virtualenv Responder
    install_with_virtualenv impacket
    install_with_virtualenv BloodHound.py
    install_with_virtualenv Certipy
    install_with_virtualenv Coercer
    install_with_virtualenv mitm6
    install_with_virtualenv sccmhunter
    install_with_virtualenv PXEThief
    install_with_virtualenv pre2k
    install_with_virtualenv ldeep
    install_with_virtualenv CredMaster
    install_with_virtualenv PKINITtools
    install_with_virtualenv WebclientServiceScanner
    install_with_virtualenv fireprox
    install_with_virtualenv malwoverview
    install_with_virtualenv o365spray
    install_with_virtualenv parsuite
    install_with_virtualenv pyLAPS
    # install_with_virtualenv 
    # install_with_virtualenv 
    # install_with_virtualenv 


    install_pipx
    install_netexec
    install_with_pipx DonPAPI
    install_masscan

    install_ruby_tools
    install_eyewitness

    download_latest_nessus

    # Check if the $INSTALL_NESSUS flag was set
    if [ $INSTALL_NESSUS -eq 1 ]; then
        echo -e "[+] The --install-nessus flag is set. Running the installation function."
        download_and_install_latest_nessus
    fi

    # check implant system requirements
    check_hardware_requirements
}

main

####################
##### My adds ######
####################

### Tmux Settings
echo "set -g mouse on" >> ~/.tmux.conf

# wget EXEs
mkdir /root/tools
wget https://github.com/clymb3r/PowerShell/blob/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1 -P /root/tools
wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.146/Snaffler.exe -P /root/executables
wget https://github.com/hoardd/hoardd-client/releases/download/v0.6.0/hoardd-client_Linux_x86_64.tar.gz -P /root/tools
tar -xvf /root/executables/hoardd-client_Linux_x86_64.tar.gz -C /root/tools/
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -P /root/tools

# ADD 
wget https://raw.githubusercontent.com/immunityinc/bravestarr/master/bravestarr.py -P /root/tools


# Nmap Scripts
# mkdir /root/nmap-scripts
wget https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/scripts/http-apache-server-status.nse -P /usr/share/nmap/scripts
wget https://raw.githubusercontent.com/richlamdev/ssh-default-banners/master/ssh-os.nse -P /usr/share/nmap/scripts
wget https://raw.githubusercontent.com/RootUp/PersonalStuff/master/http-vuln-cve2020-3452.nse -P /usr/share/nmap/scripts
wget https://raw.githubusercontent.com/bongbongco/CVE-2012-1675/refs/heads/master/oracle-tns-poison.nse -P /usr/share/nmap/scripts
wget https://raw.githubusercontent.com/frostbits-security/SIET/refs/heads/master/cisco-siet.nse -P /usr/share/nmap/scripts
nmap --script-updatedb

# VPN IKE Wordlist
mkdir /root/tools/vpn-wordlists
wget https://raw.githubusercontent.com/spyder6675/vm-setup/main/vpnIDs.txt -P /root/tools/vpn-wordlists

### Unzip Rockyou ###
gzip -d /usr/share/wordlists/rockyou.txt.gz

### Create Files and Folders
# Alais file
cat << 'EOF' >> "${HOME}/.zshrc"

# zsh Aliases
if [ -f ~/.zsh_aliases ]; then
    . ~/.zsh_aliases
fi


EOF

#### 

echo -e "${BLUE}[+]${RESET}${BOLD} Tools installation script completed. ${RESET}"
echo -e "${BLUE}[+]${RESET}${BOLD} Remember to source your ~/.zshrc file for latest PATH values to take affect ${RESET}"
echo -e "source ~/.zshrc"

#### END ####