#!/usr/bin/env bash

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
USE_OPERATOR_PROXY=0
UPDATE_APT_SOURCES=0

# Loop through all the arguments
for arg in "$@"
do
  case $arg in
    --install-nessus)
      INSTALL_NESSUS=1
      ;;
    --use-proxy)
      USE_OPERATOR_PROXY=1
      ;;
    --update-apt-sources)
      UPDATE_APT_SOURCES=1
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

    echo -e "${PURPLE}[*]${RESET} Checking if implant system requirements meet the following criteria:\nCPU >= 4\tRAM >= 8 GB\tDisk Space >= 40GB\n"

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

    # Get total available disk space in kB
    TOTAL_AVAILABLE_DISKSPACE=$(df --total | grep 'total' | awk '{print $4}')

    if (( TOTAL_AVAILABLE_DISKSPACE < 40000000 )); then
        ALL_GOOD=false
        echo -e "${RED}[-]${RESET}${BOLD} Implant has INSUFFICIENT Disk space.. Available Storage: ${TOTAL_AVAILABLE_DISKSPACE} kB. REACH OUT TO CUSTOMER ${RESET}"
    else
        echo -e "${GREEN}[+]${RESET}${BOLD} Available Storage: ${TOTAL_AVAILABLE_DISKSPACE} kB. ${RESET}"
    fi

    if ! $ALL_GOOD ; then
        echo -e "${ORANGE}[!]${RESET}${BOLD} You must construct additional pylons ${RESET}"
        echo -e "${RED}[-]${RESET}${BOLD} Exiting with non-zero status code ${RESET}"
        exit 1
    else
        echo -e "${BLUE}[+]${RESET}${BOLD} All systems good to go! ${RESET}"
    fi
}

install_apt_packages() {
    # apt packages
    # apt-get update -y && apt-get full-upgrade -y

    if [ $UPDATE_APT_SOURCES -eq 1 ]; then
        # fix /etc/apt/sources.list default mirror that seems to be borked.
        sed -i 's|^deb http://http.kali.org/kali|#deb http://http.kali.org/kali\ndeb https://kali.download/kali|' /etc/apt/sources.list
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install python3 -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install virtualenv -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install python3-distutils-extra python3-virtualenv libssl-dev libffi-dev python-dev-is-python3 build-essential smbclient libpcap-dev -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install git make gcc -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install vim-nox htop ncat rlwrap golang jq feroxbuster silversearcher-ag testssl.sh nmap masscan proxychains4 maskprocessor -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install python3-venv -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install pipx -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install xz-utils -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install samba onesixtyone snmp-mibs-downloader -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install libkrb5-dev krb5-config -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install krb5-user ntpsec ntpsec-ntpdate -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    # RustHound dependencies
    apt-get install gcc-multilib libpq-dev -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64 -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    # Manspider dependencies
    apt-get install tesseract-ocr -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install antiword -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install libavcodec60 -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install libavfilter9 -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install libxml2-dev libxslt1-dev poppler-utils flac libmad0 libsox-fmt-mp3 sox libjpeg-dev swig libpulse-dev lame -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install ffmpeg -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install postgresql -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    # EyeWitness dependencies
    apt-get install wget -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    apt-get install cmake -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold" # this is the only one that's not default already installed on kali
    apt-get install firefox-esr -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"
    # PCredz Deps
    apt-get install libpcap-dev -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"

    if [ $USE_OPERATOR_PROXY -eq 1 ]; then
        echo -e "[+] using http://100.64.0.1:3128 to install ruby gem bundler dep for latest metasploit"
        gem install --http-proxy http://100.64.0.1:3128 bundler
    else
        gem install bundler
    fi
    # Install latest metasploit
    apt-get install metasploit-framework -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"

    # remove outdated packages
    apt-get autoremove -y -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"

    # update snmp.conf
    sed -e '/mibs/ s/^#*/#/' -i /etc/snmp/snmp.conf
}

clone_git_repos() {
    # Repos
    [[ ! -d /opt/EyeWitness ]] && git clone https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness
    [[ ! -d /opt/testssl.sh ]] && git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
    [[ ! -d /opt/Responder ]] && git clone https://github.com/lgandx/Responder.git /opt/Responder
    [[ ! -d /opt/impacket ]] && git clone https://github.com/fortra/impacket.git /opt/impacket
    [[ ! -d /opt/impacket ]] && git clone https://github.com/ThePorgs/impacket.git /opt/ThePorgs-impacket
    # Impacket Interactive Shadow Creds Fork
    [[ ! -d /opt/impacket-interactive-ldap-shadow-creds ]] && wget https://github.com/Tw1sm/impacket/archive/refs/heads/interactive-ldap-shadow-creds.zip -O /opt/interactive-ldap-shadow-creds.zip
    unzip /opt/interactive-ldap-shadow-creds.zip -d /opt/impacket-interactive-ldap-shadow-creds
    [[ ! -d /opt/pywhisker ]] && git clone https://github.com/ShutdownRepo/pywhisker.git /opt/pywhisker
    [[ ! -d /opt/PKINITtools ]] && git clone https://github.com/dirkjanm/PKINITtools.git /opt/PKINITtools
    [[ ! -d /opt/krbrelayx ]] && git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx
    [[ ! -d /opt/BloodHound.py ]] && git clone https://github.com/dirkjanm/bloodhound.py /opt/BloodHound.py
    [[ ! -d /opt/pyGPOAbuse ]] && git clone https://github.com/Hackndo/pyGPOAbuse.git /opt/pyGPOAbuse
    [[ ! -d /opt/GPOddity ]] && git clone https://github.com/synacktiv/GPOddity.git /opt/GPOddity
    [[ ! -d /opt/bloodyAD ]] && git clone https://github.com/CravateRouge/bloodyAD.git /opt/bloodyAD
    [[ ! -d /opt/Certipy ]] && git clone https://github.com/ly4k/Certipy.git /opt/Certipy
    [[ ! -d /opt/Coercer ]] && git clone https://github.com/p0dalirius/Coercer.git /opt/Coercer
    [[ ! -d /opt/PetitPotam ]] && git clone https://github.com/topotam/PetitPotam.git /opt/PetitPotam
    [[ ! -d /opt/mitm6 ]] && git clone https://github.com/dirkjanm/mitm6.git /opt/mitm6
    [[ ! -d /opt/webclientservicescanner ]] && git clone https://github.com/Hackndo/WebclientServiceScanner.git /opt/webclientservicescanner
    [[ ! -d /opt/PCredz ]] && git clone https://github.com/lgandx/PCredz.git /opt/PCredz
    [[ ! -d /opt/certsync ]] && git clone https://github.com/zblurx/certsync.git /opt/certsync
    [[ ! -d /opt/pyLAPS ]] && git clone https://github.com/p0dalirius/pyLAPS.git /opt/pyLAPS
    # [[ ! -d /opt/CrackMapExec ]] && git clone https://github.com/byt3bl33d3r/CrackMapExec.git /opt/CrackMapExec
    [[ ! -d /opt/NetExec ]] && git clone https://github.com/Pennyw0rth/NetExec.git /opt/NetExec
    [[ ! -d /opt/enum4linux-ng ]] && git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
    [[ ! -d /opt/DonPAPI ]] && git clone https://github.com/login-securite/DonPAPI.git /opt/DonPAPI
    [[ ! -d /opt/dploot ]] && git clone https://github.com/zblurx/dploot.git /opt/dploot
    [[ ! -d /opt/sccmhunter ]] && git clone https://github.com/garrettfoster13/sccmhunter.git /opt/sccmhunter
    [[ ! -d /opt/ccmpwn ]] && git clone https://github.com/mandiant/ccmpwn.git /opt/ccmpwn
    # [[ ! -d /opt/PXEThief ]] && git clone https://github.com/MWR-CyberSec/PXEThief.git /opt/PXEThief
    # PXEThief is Windows only. We want the Linux version
    [[ ! -d /opt/pxethiefy ]] && git clone https://github.com/csandker/pxethiefy.git /opt/pxethiefy
    [[ ! -d /opt/masscan ]] && git clone https://github.com/robertdavidgraham/masscan.git /opt/masscan
    [[ ! -d /opt/pre2k ]] && git clone https://github.com/garrettfoster13/pre2k.git /opt/pre2k
    [[ ! -d /opt/ldeep ]] && git clone https://github.com/franc-pentest/ldeep /opt/ldeep
    [[ ! -d /opt/RustHound ]] && git clone https://github.com/NH-RED-TEAM/RustHound.git /opt/RustHound
    [[ ! -d /opt/adidnsdump ]] && git clone https://github.com/dirkjanm/adidnsdump.git /opt/adidnsdump
    [[ ! -d /opt/MANSPIDER ]] && git clone https://github.com/blacklanternsecurity/MANSPIDER.git /opt/MANSPIDER
	
}



# Clone Git Repos 
# clone-git-repos - my_functions
clone-git-repos() {
	#
	# Needed for GoRecon Modules
	# [[ ! -d /opt/SIGIT ]] && git clone https://github.com/termuxhackers-id/SIGIT.git /opt/SIGIT # Git was removed
	# [[ ! -d /opt/SecLists ]] && git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
	# [[ ! -d /opt/TODO ]] && git clone TODO /opt/TODO
	# [[ ! -d /opt/TODO ]] && git clone TODO /opt/TODO
	[[ ! -d /opt/AADInternals ]] && git clone https://github.com/Gerenios/AADInternals.git /opt/AADInternals
	[[ ! -d /opt/ADCSync ]] && git clone https://github.com/JPG0mez/ADCSync.git /opt/ADCSync
	[[ ! -d /opt/Active-Directory-Spotlights ]] && git clone https://github.com/sse-secure-systems/Active-Directory-Spotlights.git /opt/Active-Directory-Spotlights
	[[ ! -d /opt/AutoRDPwn ]] && git clone https://github.com/JoelGMSec/AutoRDPwn.git /opt/AutoRDPwn
	[[ ! -d /opt/BloodHound.py ]] && git clone https://github.com/dirkjanm/bloodhound.py /opt/BloodHound.py
	[[ ! -d /opt/BruteLoops ]] && git clone https://github.com/arch4ngel/BruteLoops.git /opt/BruteLoops
	[[ ! -d /opt/CVE-2017-12542 ]] && git clone https://github.com/skelsec/CVE-2017-12542.git /opt/CVE-2017-12542
	[[ ! -d /opt/CeWL ]] && git clone https://github.com/digininja/CeWL.git /opt/CeWL
	[[ ! -d /opt/Certipy ]] && git clone https://github.com/ly4k/Certipy.git /opt/Certipy
	[[ ! -d /opt/Coercer ]] && git clone https://github.com/p0dalirius/Coercer.git /opt/Coercer
	[[ ! -d /opt/CredMaster ]] && git clone https://github.com/knavesec/CredMaster.git /opt/CredMaster
	[[ ! -d /opt/DPAT ]] && git clone https://github.com/clr2of8/DPAT.git /opt/DPAT
	[[ ! -d /opt/DomainPasswordSpray ]] && git clone https://github.com/dafthack/DomainPasswordSpray.git /opt/DomainPasswordSpray
	[[ ! -d /opt/DonPAPI ]] && git clone https://github.com/login-securite/DonPAPI.git /opt/DonPAPI
	[[ ! -d /opt/EyeWitness ]] && git clone https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness
	[[ ! -d /opt/GPOddity ]] && git clone https://github.com/synacktiv/GPOddity.git /opt/GPOddity
	[[ ! -d /opt/Go365 ]] && git clone https://github.com/optiv/Go365.git /opt/Go365
	[[ ! -d /opt/KrbRelayUp ]] && git clone https://github.com/Dec0ne/KrbRelayUp.git /opt/KrbRelayUp
	[[ ! -d /opt/LdapRelayScan ]] && git clone https://github.com/zyn3rgy/LdapRelayScan.git /opt/LdapRelayScan
	[[ ! -d /opt/MANSPIDER ]] && git clone https://github.com/blacklanternsecurity/MANSPIDER.git /opt/MANSPIDER
	[[ ! -d /opt/MFASweep ]] && git clone https://github.com/dafthack/MFASweep.git /opt/MFASweep
	[[ ! -d /opt/MSOLSpray ]] && git clone https://github.com/dafthack/MSOLSpray.git /opt/MSOLSpray
	[[ ! -d /opt/MailSniper ]] && git clone https://github.com/dafthack/MailSniper.git /opt/MailSniper
	[[ ! -d /opt/NetExec ]] && git clone https://github.com/Pennyw0rth/NetExec.git /opt/NetExec
	[[ ! -d /opt/PCredz ]] && git clone https://github.com/lgandx/PCredz.git /opt/PCredz
	[[ ! -d /opt/PKINITtools ]] && git clone https://github.com/dirkjanm/PKINITtools.git /opt/PKINITtools
	[[ ! -d /opt/PetitPotam ]] && git clone https://github.com/topotam/PetitPotam.git /opt/PetitPotam
	[[ ! -d /opt/PlumHound ]] && git clone https://github.com/PlumHound/PlumHound.git /opt/PlumHound
	[[ ! -d /opt/PowerUpSQL ]] && git clone https://github.com/NetSPI/PowerUpSQL.git /opt/PowerUpSQL
	[[ ! -d /opt/Responder ]] && git clone https://github.com/lgandx/Responder.git /opt/Responder
	[[ ! -d /opt/RustHound ]] && git clone https://github.com/NH-RED-TEAM/RustHound.git /opt/RustHound
	[[ ! -d /opt/SIET ]] && git clone https://github.com/frostbits-security/SIET.git /opt/SIET
	[[ ! -d /opt/SQLAutoPwn ]] && git clone https://github.com/Wh1t3Rh1n0/SQLAutoPwn.git /opt/SQLAutoPwn
	[[ ! -d /opt/SeeYouCM-Thief ]] && git clone https://github.com/trustedsec/SeeYouCM-Thief.git /opt/SeeYouCM-Thief
	[[ ! -d /opt/SnafflerParser ]] && git clone https://github.com/zh54321/SnafflerParser.git /opt/SnafflerParser
	[[ ! -d /opt/Spray365 ]] && git clone https://github.com/MarkoH17/Spray365.git /opt/Spray365
	[[ ! -d /opt/SprayingToolkit ]] && git clone https://github.com/byt3bl33d3r/SprayingToolkit.git /opt/SprayingToolkit
	[[ ! -d /opt/adidnsdump ]] && git clone https://github.com/dirkjanm/adidnsdump.git /opt/adidnsdump
	[[ ! -d /opt/bloodyAD ]] && git clone https://github.com/CravateRouge/bloodyAD.git /opt/bloodyAD
	[[ ! -d /opt/ccat ]] && git clone https://github.com/frostbits-security/ccat.git /opt/ccat
	[[ ! -d /opt/ccmpwn ]] && git clone https://github.com/mandiant/ccmpwn.git /opt/ccmpwn
	[[ ! -d /opt/certsync ]] && git clone https://github.com/zblurx/certsync.git /opt/certsync
	[[ ! -d /opt/ciscot7 ]] && git clone https://github.com/theevilbit/ciscot7.git /opt/ciscot7
	[[ ! -d /opt/dns-triage ]] && git clone https://github.com/Wh1t3Rh1n0/dns-triage.git /opt/dns-triage
	[[ ! -d /opt/dnstwist ]] && git clone https://github.com/elceef/dnstwist.git /opt/dnstwist
	[[ ! -d /opt/dploot ]] && git clone https://github.com/zblurx/dploot.git /opt/dploot
	[[ ! -d /opt/eavesarp-ng ]] && git clone https://github.com/ImpostorKeanu/eavesarp-ng.git /opt/eavesarp-ng
	[[ ! -d /opt/enum4linux-ng ]] && git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
	[[ ! -d /opt/evilrdp ]] && git clone https://github.com/skelsec/evilrdp.git /opt/evilrdp
	[[ ! -d /opt/fireprox ]] && git clone https://github.com/ustayready/fireprox.git /opt/fireprox
	[[ ! -d /opt/gitleaks ]] && git clone https://github.com/gitleaks/gitleaks.git /opt/gitleaks
	[[ ! -d /opt/hakrevdns ]] && git clone https://github.com/hakluke/hakrevdns.git /opt/hakrevdns
	[[ ! -d /opt/hardcidr ]] && git clone https://github.com/trustedsec/hardcidr.git /opt/hardcidr
	[[ ! -d /opt/ike-scan ]] && git clone https://github.com/royhills/ike-scan.git /opt/ike-scan
	[[ ! -d /opt/ikeforce ]] && git clone https://github.com/SpiderLabs/ikeforce.git /opt/ikeforce
	[[ ! -d /opt/impacket ]] && git clone https://github.com/ThePorgs/impacket.git /opt/ThePorgs-impacket
	[[ ! -d /opt/impacket ]] && git clone https://github.com/fortra/impacket.git /opt/impacket
	# Impacket Interactive Shadow Creds Fork
	[[ ! -d /opt/impacket-interactive-ldap-shadow-creds ]] && wget https://github.com/Tw1sm/impacket/archive/refs/heads/interactive-ldap-shadow-creds.zip -nc -O /opt/interactive-ldap-shadow-creds.zip;unzip /opt/interactive-ldap-shadow-creds.zip -d /opt/impacket-interactive-ldap-shadow-creds
	[[ ! -d /opt/kerbrute ]] && git clone https://github.com/ropnop/kerbrute.git /opt/kerbrute
	[[ ! -d /opt/krbrelayx ]] && git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx
	[[ ! -d /opt/ldeep ]] && git clone https://github.com/franc-pentest/ldeep /opt/ldeep
	[[ ! -d /opt/malwoverview ]] && git clone https://github.com/alexandreborges/malwoverview.git /opt/malwoverview
	[[ ! -d /opt/masscan ]] && git clone https://github.com/robertdavidgraham/masscan.git /opt/masscan
	[[ ! -d /opt/mitm6 ]] && git clone https://github.com/dirkjanm/mitm6.git /opt/mitm6
	[[ ! -d /opt/ntlmv1-multi ]] && git clone https://github.com/evilmog/ntlmv1-multi.git /opt/ntlmv1-multi
	[[ ! -d /opt/o365spray ]] && git clone https://github.com/0xZDH/o365spray.git /opt/o365spray
	[[ ! -d /opt/onedrive_user_enum ]] && git clone https://github.com/nyxgeek/onedrive_user_enum.git /opt/onedrive_user_enum
	[[ ! -d /opt/parsuite ]] && git clone https://github.com/arch4ngel/parsuite.git /opt/parsuite
	[[ ! -d /opt/pr_SystemDPAPIdump ]] && wget https://codeload.github.com/clavoillotte/impacket/zip/refs/heads/pr_SystemDPAPIdump -P /opt/pr_SystemDPAPIdump
	[[ ! -d /opt/pre2k ]] && git clone https://github.com/garrettfoster13/pre2k.git /opt/pre2k
	[[ ! -d /opt/pxethiefy ]] && git clone https://github.com/csandker/pxethiefy.git /opt/pxethiefy
	[[ ! -d /opt/pyGPOAbuse ]] && git clone https://github.com/Hackndo/pyGPOAbuse.git /opt/pyGPOAbuse
	[[ ! -d /opt/pyLAPS ]] && git clone https://github.com/p0dalirius/pyLAPS.git /opt/pyLAPS
	[[ ! -d /opt/pymeta ]] && git clone https://github.com/m8r0wn/pymeta.git /opt/pymeta
	[[ ! -d /opt/pywhisker ]] && git clone https://github.com/ShutdownRepo/pywhisker.git /opt/pywhisker
	[[ ! -d /opt/rdp-sec-check ]] && git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git /opt/rdp-sec-check
	[[ ! -d /opt/redis-rogue-server ]] && git clone https://github.com/n0b0dyCN/redis-rogue-server.git /opt/redis-rogue-server
	[[ ! -d /opt/sccmhunter ]] && git clone https://github.com/garrettfoster13/sccmhunter.git /opt/sccmhunter
	[[ ! -d /opt/ssh-audit ]] && git clone https://github.com/mr-pmillz/ssh-audit.git /opt/ssh-audit
	[[ ! -d /opt/sslscan ]] && git clone https://github.com/rbsec/sslscan.git /opt/sslscan
	[[ ! -d /opt/testssl.sh ]] && git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
	[[ ! -d /opt/trufflehog ]] && git clone https://github.com/trufflesecurity/trufflehog.git /opt/trufflehog
	[[ ! -d /opt/usernamer ]] && git clone https://github.com/jseidl/usernamer.git /opt/usernamer
	[[ ! -d /opt/WebclientServiceScanner ]] && git clone https://github.com/Hackndo/WebclientServiceScanner.git /opt/WebclientServiceScanner
	[[ ! -d /opt/winshock-test ]] && git clone https://github.com/anexia-it/winshock-test.git /opt/winshock-test
	[[ ! -d /opt/wpscan ]] && git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
	[[ ! -d /tmp/testssl.sh ]] && git clone https://github.com/drwetter/testssl.sh.git /tmp/testssl.sh



}



configure_terminal() {
rm "${HOME}/.screenrc"
cat << 'EOF' >> "${HOME}/.screenrc"
termcapinfo * ti@:te@
caption always
caption string "%{kw}%-w%{wr}%n %t%{-}%+w"
startup_message off
defscrollback 1000000
EOF

# Ensure that shell is set to /bin/zsh
# implants are now fixed to default to zsh shell.
# chsh -s /usr/bin/zsh || echo -e "[-] Failed to change shell to /usr/bin/zsh"

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
    GO111MODULE=on go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    [[ -f "${HOME}/go/bin/nuclei" ]] && nuclei -ut || echo "nuclei not in ${HOME}/go/bin/"
}

# ignore shellcheck warnings for source commands
# shellcheck source=/dev/null
install_with_virtualenv() {
    # create virtualenv dir if it doesn't exist
    [[ ! -d "${HOME}/pyenv" ]] && mkdir "${HOME}/pyenv"
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

# ignore shellcheck warnings for source commands
# shellcheck source=/dev/null
install_rust() {
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    # source cargo env in our current shell script env
    . "$HOME/.cargo/env"

# add ~/.cargo/bin to path in ~/.zshrc file so that path will persist
if [ -d "$HOME/.cargo/bin" ] ; then
cat << 'EOF' >> "${HOME}/.zshrc"

# Add ~/.cargo/bin to path
[[ ":$PATH:" != *":${HOME}/.cargo/bin:"* ]] && export PATH="${PATH}:${HOME}/.cargo/bin"
EOF
fi
    # add Rust Linux deps
    "${HOME}/.cargo/bin/rustup" toolchain install stable-x86_64-unknown-linux-gnu
    "${HOME}/.cargo/bin/rustup" target add x86_64-unknown-linux-gnu
    "${HOME}/.cargo/bin/rustup" update
    "${HOME}/.cargo/bin/rustup" default stable
}

install_rusthound() {
    [[ -d /opt/RustHound ]] && cd /opt/RustHound || exit 1
    # run cargo update to resolve funky error[E0282]: type annotations needed for `Box<_>`
    # https://github.com/NH-RED-TEAM/RustHound/issues/32
    "${HOME}/.cargo/bin/cargo" update -p time
    # install commands for v1/main branch
    # CFLAGS="-lrt"; LDFLAGS="-lrt"; RUSTFLAGS='-C target-feature=+crt-static'; cargo build --release --target x86_64-unknown-linux-gnu
    # [[ -f /opt/RustHound/target/x86_64-unknown-linux-gnu/release/rusthound ]] && cp target/x86_64-unknown-linux-gnu/release/rusthound "${HOME}/.cargo/bin/rusthound"
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
        else
            python3 -m pip install pipx --user || apt-get update -y ; apt-get install pipx -y
        fi
    fi
}

# Install NetExec latest
install_netexec() {
    if [ -d "/opt/NetExec" ]; then
        if [ -e "$HOME"/.local/bin/netexec ]; then
            echo -e "${BLUE}[+]${RESET}${BOLD} NetExec is already installed at ${HOME}/.local/bin/netexec ${RESET}"
            # Initialize NetExec database
            "${HOME}/.local/bin/netexec" smb --help
        else
            # move old /usr/bin/netexec to /usr/bin/netexec.old
            [[ -f /usr/bin/netexec ]] && mv /usr/bin/netexec /usr/bin/netexec.old
            # move old /usr/bin/nxcdb to /usr/bin/nxcdb.old
            [[ -f /usr/bin/nxcdb ]] && mv /usr/bin/nxcdb /usr/bin/nxcdb.old
            # move old /usr/bin/nxc to /usr/bin/nxc.old
            [[ -f /usr/bin/nxc ]] && mv /usr/bin/nxc /usr/bin/nxc.old
            echo -e "${BLUE}[+]${RESET}${BOLD} installing NetExec aardwolf dependency via pipx ${RESET}"
            [[ -d /opt/NetExec ]] && cd /opt/NetExec && pipx install git+https://github.com/skelsec/aardwolf
            echo -e "${BLUE}[+]${RESET}${BOLD} installing latest version of NetExec via pipx ${RESET}"
            [[ -d /opt/NetExec ]] && cd /opt/NetExec && pipx install .

            if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
                export PATH="${PATH}:${HOME}/.local/bin"
            fi
            # Initialize NetExec database
            "${HOME}/.local/bin/netexec" smb --help
        fi
    fi
}

add_pipx_bin_to_path() {
# pipx ensurepath doesn't seem to work in this script so we'll just manually add ~/.local/bin to our path in ~/.zshrc
# could be due to the shebang #'!'/usr/bin/env bash ...
# add ~/.local/bin to path in ~/.zshrc file so that pipx installed packages will persist in path
if [ -d "$HOME/.local/bin" ] ; then
cat << 'EOF' >> "${HOME}/.zshrc"

# Add ~/.local/bin to path
[[ ":$PATH:" != *":${HOME}/.local/bin:"* ]] && export PATH="${PATH}:${HOME}/.local/bin"
EOF
fi
}

# ignore shellcheck warnings for source commands
# shellcheck source=/dev/null
install_eyewitness() {
    echo -e "${BLUE}[+]${RESET}${BOLD} Installing EyeWitness ${RESET}"

    [[ ! -d "${HOME}/pyenv" ]] && mkdir "${HOME}/pyenv"
    PYENV="${HOME}/pyenv"
    if [ -d "/opt/EyeWitness" ]; then
        cd /opt/EyeWitness/Python/setup || exit 1
        virtualenv -p python3 "${PYENV}/EyeWitness"
        . "${PYENV}/EyeWitness/bin/activate"
        python3 -m pip install -U wheel setuptools
        # ensure that requirements.txt deps are installed.
        [[ -f /opt/EyeWitness/Python/setup/requirements.txt ]] && python3 -m pip install -r requirements.txt

        deactivate || echo -e "[-] could not deactivate virtualenv.."

        echo -e "${BLUE}[+]${RESET}${BOLD} Getting latest Gecko driver.. ${RESET}"
        # Get download links for latest geckodriver via GitHub API
        LATEST_GECKOS=$(curl -s https://api.github.com/repos/mozilla/geckodriver/releases/latest | jq '.assets[].browser_download_url' | tr -d \")
        GECKO_URL=$(echo "${LATEST_GECKOS}" | grep "linux64.tar.gz$")
        # Download, extract, and clean up latest driver tarball
        wget "${GECKO_URL}" -O geckodriver.tar.gz
        tar -xvf geckodriver.tar.gz -C /usr/bin
        rm geckodriver.tar.gz
        cd - &>/dev/null || exit 1
    fi
}

install_ruby_tools() {
    # Install Evil-WinRM
    gem install evil-winrm
}


# Download and Install the latest debian10 Nessus amd64
download_and_install_latest_nessus() {
    NESSUS_LATEST_URL=$(curl -s https://www.tenable.com/downloads/api/v2/pages/nessus --header 'accept: application/json' | jq -r '.releases.latest' | jq -r '.[][].file_url' | grep 'Nessus-latest-debian10_amd64.deb')
    [[ ! -d "${HOME}/tools" ]] && mkdir "${HOME}/tools"
    cd "${HOME}/tools" && wget "$NESSUS_LATEST_URL" -O Nessus-latest-debian10_amd64.deb
    sudo dpkg -i Nessus-latest-debian10_amd64.deb
}

# ignore shellcheck warnings for source commands
# shellcheck source=/dev/null
configure_openssl_dependency() {
    REPO_NAME="$1"
    PYENV="${HOME}/pyenv"
    if [ -d "/opt/${REPO_NAME}" ]; then
        cd "/opt/${REPO_NAME}" || exit 1
        . "${PYENV}/${REPO_NAME}/bin/activate"
        python3 -m pip uninstall -y pyOpenSSL
        python3 -m pip install pyOpenSSL==24.0.0
        deactivate
        cd - &>/dev/null || exit 1
    else
        echo -e "${REPO_NAME} does not exist."
    fi
}

# ignore shellcheck warnings for source commands
# shellcheck source=/dev/null
upgrade_pandas() {
    REPO_NAME="$1"
    PYENV="${HOME}/pyenv"
    if [ -d "/opt/${REPO_NAME}" ]; then
        cd "/opt/${REPO_NAME}" || exit 1
        . "${PYENV}/${REPO_NAME}/bin/activate"
        python3 -m pip install pandas --upgrade
        deactivate
        cd - &>/dev/null || exit 1
    else
        echo -e "${REPO_NAME} does not exist."
    fi
}


### My Functions ###

# Configure tmux
# configure_tmux  - my_functions
configure-tmux() {
rm "${HOME}/.tmux.conf"
cat << 'EOF' >> "${HOME}/.tmux.conf"
set -g mouse on
EOF
}

# Download Tools to root Dir
# download_tools - my_functions
download-tools() {
# [[ ! -d "${HOME}/tools/TODO" ]] && 
[[ ! -d "${HOME}/tools" ]] && mkdir "${HOME}/tools"
[[ ! -f "${HOME}/tools/Invoke-Mimikatz.ps1" ]] && wget https://github.com/clymb3r/PowerShell/blob/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1 -P /root/tools
[[ ! -f "${HOME}/tools/Snaffler.exe" ]] && wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.146/Snaffler.exe -P /root/tools
#
[[ ! -f "${HOME}/tools/hoardd-client_Linux_x86_64.tar.gz" ]] && wget https://github.com/hoardd/hoardd-client/releases/download/v0.6.0/hoardd-client_Linux_x86_64.tar.gz -P /root/tools
[[ ! -d "${HOME}/tools/hoardd-client" ]] && mkdir "${HOME}/tools/hoardd-client"
[[ ! -f "${HOME}/tools/hoardd-client/hoardd-client" ]] && tar -xvf /root/tools/hoardd-client_Linux_x86_64.tar.gz -C /root/tools/hoardd-client
#
[[ ! -f "${HOME}/tools/kerbrute_linux_amd64" ]] && wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -P /root/tools
[[ ! -f "${HOME}/tools/bravestarr.py" ]] && wget https://raw.githubusercontent.com/immunityinc/bravestarr/master/bravestarr.py -P /root/tools
[[ ! -f "${HOME}/tools/calculate-time.py" ]] && wget https://raw.githubusercontent.com/spyder6675/vm-setup/main/calculate-time.py -P /root/tools
# NTLMv1 wget the raw file 
[[ ! -f "${HOME}/tools/ct3_to_ntlm.c" ]] && wget https://github.com/hashcat/hashcat-utils/blob/master/src/ct3_to_ntlm.c -P /root/tools
# 
# VPN IKE Wordlist
[[ ! -d "${HOME}/tools/vpn-wordlists" ]] && mkdir "${HOME}/tools/vpn-wordlists"
[[ ! -f "${HOME}/tools/vpnIDs.txt" ]] && wget https://raw.githubusercontent.com/spyder6675/vm-setup/main/vpnIDs.txt -P /root/tools/vpn-wordlists

}


# Nmap Scripts
# download_nmap_scripts - my_functions
download-nmap-scripts() {
# [[ ! -f /usr/share/nmap/scripts ]] &&
#
[[ ! -f /usr/share/nmap/scripts/http-apache-server-status.nse ]] && wget https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/scripts/http-apache-server-status.nse -P /usr/share/nmap/scripts
[[ ! -f /usr/share/nmap/scripts/ssh-os.nse ]] && wget https://raw.githubusercontent.com/richlamdev/ssh-default-banners/master/ssh-os.nse -P /usr/share/nmap/scripts
[[ ! -f /usr/share/nmap/scripts/http-vuln-cve2020-3452.nse ]] && wget https://raw.githubusercontent.com/RootUp/PersonalStuff/master/http-vuln-cve2020-3452.nse -P /usr/share/nmap/scripts
[[ ! -f /usr/share/nmap/scripts/oracle-tns-poison.nse ]] && wget https://raw.githubusercontent.com/bongbongco/CVE-2012-1675/refs/heads/master/oracle-tns-poison.nse -P /usr/share/nmap/scripts
[[ ! -f /usr/share/nmap/scripts/cisco-siet.nse ]] && wget https://raw.githubusercontent.com/frostbits-security/SIET/refs/heads/master/cisco-siet.nse -P /usr/share/nmap/scripts
[[ ! -f /usr/share/nmap/scripts/ssh-hassh.nse ]] && wget https://raw.githubusercontent.com/0x4D31/hassh-utils/master/ssh-hassh.nse -P /usr/share/nmap/scripts
#
[[ ! -f /usr/share/nmap/scripts/cisco-wcl.nse ]] && wget https://raw.githubusercontent.com/spyder6675/vm-setup/main/cisco-wcl.nse -P /usr/share/nmap/scripts
[[ ! -f /usr/share/nmap/scripts/dell-idrac.nse ]] && wget https://raw.githubusercontent.com/spyder6675/vm-setup/main/dell-idrac.nse -P /usr/share/nmap/scripts

#
nmap --script-updatedb

}


### Unzip Rockyou ###
# rockyou_unzip - my_functions
rockyou-unzip() {

[[ ! -f /usr/share/wordlists/rockyou.txt ]] && gzip -d /usr/share/wordlists/rockyou.txt.gz

}


#############################
# MAIN ######################
#############################

main() {
    # Check if the $USE_OPERATOR_PROXY flag was set
    if [ $USE_OPERATOR_PROXY -eq 1 ]; then
        echo -e "${BLUE}[+]${RESET}${BOLD} The --use-operator-proxy flag is set ${RESET}"
        echo -e "${BLUE}[+]${RESET}${BOLD} exporting http_proxy and https_proxy env vars.. ${RESET}"
        export http_proxy="http://100.64.0.1:3128"
        export https_proxy="http://100.64.0.1:3128"
    fi

    # check implant system requirements
    # check_hardware_requirements

    install_apt_packages
    clone_git_repos
    clone-git-repos
    configure_terminal
    install_go_tools

    # create virtualenv dir.
    [[ ! -d "${HOME}/pyenv" ]] && mkdir "${HOME}/pyenv"

    install_with_virtualenv Responder
    install_with_virtualenv impacket
    install_with_virtualenv ThePorgs-impacket
    install_with_virtualenv impacket-interactive-ldap-shadow-creds
    configure_openssl_dependency impacket-interactive-ldap-shadow-creds
    install_with_virtualenv pywhisker
    configure_openssl_dependency pywhisker
    install_with_virtualenv PKINITtools
    configure_openssl_dependency PKINITtools
    install_with_virtualenv BloodHound.py
    install_with_virtualenv pyGPOAbuse
    install_with_virtualenv Certipy
    install_with_virtualenv Coercer
    install_with_virtualenv mitm6
    install_with_virtualenv webclientservicescanner
    install_with_virtualenv enum4linux-ng
    install_with_virtualenv sccmhunter
    upgrade_pandas sccmhunter
    install_with_virtualenv pxethiefy
    install_with_virtualenv pre2k
    configure_openssl_dependency pre2k
    install_with_virtualenv ldeep
    install_with_virtualenv adidnsdump

    install_pipx
    add_pipx_bin_to_path
    install_with_pipx bloodyAD
    install_with_pipx DonPAPI
    install_with_pipx GPOddity
    install_with_pipx dploot
    install_with_pipx MANSPIDER
    # add missing dependency to man-spider pipx package using pipx inject
    pipx inject man-spider pdf2txt || echo -e "${RED}[-]${RESET}${BOLD} Failed to install man-spider package dependency pdf2txt via pipx inject ${RESET}"

    install_masscan
    install_ruby_tools
    install_rust
    install_rusthound

    # NetExec requires rust to properly install the bleeding edge version. Ensure NetExec install happens after rust install...
    install_netexec

    # Install EyeWitness
    install_eyewitness

    # Check if the $INSTALL_NESSUS flag was set
    if [ $INSTALL_NESSUS -eq 1 ]; then
        echo -e "${BLUE}[+]${RESET}${BOLD} The --install-nessus flag is set. Running the installation function. ${RESET}"
        download_and_install_latest_nessus
    fi

	
	### My Additions ###
	
	configure-tmux
	download-tools
	download-nmap-scripts
	rockyou-unzip

}

main

echo -e "\n\n"
echo -e "${BLUE}[+]${RESET}${BOLD} Tools installation script completed. ${RESET}"
echo -e "${BLUE}[+]${RESET}${BOLD} Remember to source your ~/.zshrc file for latest PATH values to take affect ${RESET}"
echo -e "source ~/.zshrc"