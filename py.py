import os, time, multiprocessing, requests, hashlib, base58
from ecdsa import SigningKey, SECP256k1

# --- إعداداتك ---
TOKEN = "5921618897:AAGu6bp5gFtatio22y-XdWUSwAd0Lk6b1HY"
CHAT_ID = "227172927"
URL = "https://www.dropbox.com/scl/fi/kpagj5u15zjeo0q5kg31t/wallets.txt?rlkey=0yc47js2rv5hvb2plcf9nqcgp&st=ma7gqux2&dl=1"

def get_both_addresses(priv_bytes):
    # إنشاء المفتاح العام
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    
    # --- النوع الأول: Uncompressed (P2PK القديم) ---
    vk_uncomp = b'\x04' + vk.to_string()
    hash1 = hashlib.sha256(vk_uncomp).digest()
    ripem1 = hashlib.new('ripemd160', hash1).digest()
    vs1 = b'\x00' + ripem1
    check1 = hashlib.sha256(hashlib.sha256(vs1).digest()).digest()[:4]
    addr_uncomp = base58.b58encode(vs1 + check1).decode()
    
    # --- النوع الثاني: Compressed (Legacy العادي) ---
    vk_comp = vk.to_string("compressed")
    hash2 = hashlib.sha256(vk_comp).digest()
    ripem2 = hashlib.new('ripemd160', hash2).digest()
    vs2 = b'\x00' + ripem2
    check2 = hashlib.sha256(hashlib.sha256(vs2).digest()).digest()[:4]
    addr_comp = base58.b58encode(vs2 + check2).decode()
    
    return addr_uncomp, addr_comp

def send_to_telegram(msg):
    try:
        requests.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage", 
                      json={"chat_id": CHAT_ID, "text": msg}, timeout=10)
    except: pass

def worker(wallet_set, counter, shared_dict):
    while True:
        priv = os.urandom(32)
        # توليد وفحص العنوانين معاً من مفتاح واحد
        addr_uncomp, addr_comp = get_both_addresses(priv)
        
        shared_dict['last_hex'] = priv.hex()
        shared_dict['last_addr_uncomp'] = addr_uncomp
        shared_dict['last_addr_comp'] = addr_comp
        
        # البحث في القائمة
        if addr_uncomp in wallet_set or addr_comp in wallet_set:
            found_addr = addr_uncomp if addr_uncomp in wallet_set else addr_comp
            hit_msg = f"🚨 لقطة العمر (جوجل - شامل)!\nADDR: {found_addr}\nHEX: {priv.hex()}"
            send_to_telegram(hit_msg)
        
        with counter.get_lock():
            counter.value += 1

if __name__ == "__main__":
    if not os.path.exists("wallets.txt"):
        print("📥 Downloading Wallets to GitHub...")
        os.system(f'wget -q -O wallets.txt "{URL}"')

    with open("wallets.txt", 'r') as f:
        wallets = set(line.strip() for line in f if line.strip())

    count = multiprocessing.Value('L', 0)
    manager = multiprocessing.Manager()
    shared_dict = manager.dict()
    
    send_to_telegram("🚀 (جيتهب) بدأ الفحص الشامل للنوعين (Compressed & Uncompressed)")

    for _ in range(multiprocessing.cpu_count()):
        multiprocessing.Process(target=worker, args=(wallets, count, shared_dict)).start()

    last_count, last_report = 0, time.time()
    while True:
        time.sleep(1)
        curr = count.value
        now = time.time()
        speed = curr - last_count
        last_count = curr
        
        if now - last_report >= 300: # تقرير كل 5 دقائق
            report = (
                f"تقرير الأداء ([جيتهب])\n"
                f"السرعة: {speed:,.0f} keys/s\n"
                f"الإجمالي: {curr:,}\n"
                f"عينة مفحوصة (النوعين):\n"
                f"🟢 Uncomp: {shared_dict.get('last_addr_uncomp')}\n"
                f"🔵 Comp: {shared_dict.get('last_addr_comp')}\n"
                f"🔑 HEX: {shared_dict.get('last_hex')}"
            )
            send_to_telegram(report)
            last_report = now
