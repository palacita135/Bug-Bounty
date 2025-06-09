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
from tqdm import tqdm

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
            for _ in tqdm(range(1), desc=task_name):
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

# === CTF MODE SHORTCUT ===
def ctf_mode(domain, outdir):
    print("[⚡] Running in CTF Mode — Only fast recon and vuln scan")
    recon_phase(domain, outdir)
    vuln_scan_phase(domain, outdir)

# === MAIN ===
def main():
    parser = argparse.ArgumentParser(description="DirtyHeroes Bug Bounty Toolkit")
    parser.add_argument("--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--fast", action="store_true", help="Skip heavy scans for faster execution")
    parser.add_argument("--recon-only", action="store_true", help="Only run recon phase")
    parser.add_argument("--vuln-only", action="store_true", help="Only run vulnerability scanning")
    parser.add_argument("--exploit-only", action="store_true", help="Only run exploitation phase")
    parser.add_argument("--skip-zip", action="store_true", help="Do not zip the result folder")
    parser.add_argument("--ctf-mode", action="store_true", help="Run in CTF mode (fast recon + vuln scan)")
    args = parser.parse_args()

    banner()
    target = get_target(args)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    outdir = os.path.join(TOOLS_DIR, f"{target}_{timestamp}")
    os.makedirs(outdir, exist_ok=True)

    if args.ctf_mode:
        ctf_mode(target, outdir)
    elif args.recon_only:
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
