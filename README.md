# Bug-Bounty
Tools for Bug Bounty

🐉 Kali Linux Bug Bounty Toolkit Installation

    💡 Prerequisites (do this first):

sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget python3 python3-pip golang make unzip jq
mkdir -p ~/tools && cd ~/tools

🔎 Passive Recon
Subfinder (Go)

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

Amass (APT)

sudo apt install -y amass

Assetfinder (Go)

go install github.com/tomnomnom/assetfinder@latest

🌐 Web Service Enumeration & Fuzzing
Nmap

sudo apt install -y nmap

Masscan

sudo apt install -y masscan

FFUF (Fuzz Faster U Fool) (Go)

go install github.com/ffuf/ffuf@latest

Gobuster (APT)

sudo apt install -y gobuster

Httpx (Go)

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

🧠 Param/URL Discovery
Waybackurls (Go)

go install github.com/tomnomnom/waybackurls@latest

Gau (GetAllURLs) (Go)

go install github.com/lc/gau/v2/cmd/gau@latest

LinkFinder (Python)

git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt
python3 linkfinder.py -h

GF (Grep Patterns) (Go + patterns)

go install github.com/tomnomnom/gf@latest
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

ParamSpider (Python)

git clone https://github.com/devanshbatham/paramspider.git
cd paramspider
pip3 install -r requirements.txt

Arjun (Python)

git clone https://github.com/s0md3v/Arjun.git
cd Arjun
pip3 install -r requirements.txt

🛡️ XSS/SQLi/Vuln Discovery
Dalfox (Go)

go install github.com/hahwul/dalfox/v2@latest

XSStrike (Python)

git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip3 install -r requirements.txt

SQLMap (APT)

sudo apt install -y sqlmap

🕵️‍♂️ LFI/RFI/Vuln Discovery
LFISuite (Python2)

git clone https://github.com/D35m0nd142/LFISuite.git

Fimap (Python2)

git clone https://github.com/kurobeats/fimap.git

Oralyzer (Python3)

git clone https://github.com/r0075h3ll/Oralyzer.git
cd Oralyzer
pip3 install -r requirements.txt

☠️ Exploitation Tools
Metasploit (msfconsole & msfvenom)

sudo apt install -y metasploit-framework

Gopherus

git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus
chmod +x gopherus.py

Interactsh Client (Go)

go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

📦 Tools for APIs, HTTP, and Buckets
Postman (GUI)

# Download .deb file from https://www.postman.com/downloads/
sudo dpkg -i postman-linux-x64*.deb
sudo apt --fix-broken install

Kiterunner (Go)

go install github.com/assetnote/kiterunner@latest

AWSBucketDump (Python3)

git clone https://github.com/jordanpotti/AWSBucketDump.git
cd AWSBucketDump
pip3 install -r requirements.txt

🔍 CMS and Firewall Fingerprinting
CMSeek (Python3)

git clone https://github.com/Tuhinshubhra/CMSeek.git
cd CMSeek
pip3 install -r requirements.txt

wafw00f (APT)

sudo apt install -y wafw00f

📁 Git Recon
GitDumper

git clone https://github.com/internetwache/GitTools.git
cd GitTools/Dumper

🖼️ Web Screenshot Tools
EyeWitness (Python3)

git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness
sudo ./setup.sh

Aquatone (Go)

go install github.com/michenriksen/aquatone@latest

✅ Final Touch: Add Go Binaries to PATH

If Go tools don't work after install:

echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc && source ~/.zshrc
# or if using bash:
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc
