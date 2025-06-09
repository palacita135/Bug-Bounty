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
def get_target():
    url = input("[?] Enter target domain (without http/https): ").strip()
    try:
        socket.gethostbyname(url)
        print(f"[✔] Domain resolved: {url}")
        return url
    except socket.gaierror:
        print("[✘] Invalid domain. Try again.")
        return get_target()

# === RECON ===
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

# === MAIN ===
def main():
    banner()
    target = get_target()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    outdir = os.path.join(TOOLS_DIR, f"{target}_{timestamp}")
    os.makedirs(outdir, exist_ok=True)

    recon_phase(target, outdir)

if __name__ == "__main__":
    main()
