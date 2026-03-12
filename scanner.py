import os
import hashlib
import json
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

import psutil

try:
    import yara
except:
    yara = None

try:
    import pefile
except:
    pefile = None


SIGNATURE_DB = "signatures.json"
YARA_RULES = "rules.yar"
QUARANTINE_DIR = "quarantine"

lock = threading.Lock()


def load_signatures():
    with open(SIGNATURE_DB) as f:
        return json.load(f)


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)

    return h.hexdigest()


def check_hash(file_hash, db):
    for name, h in db["hashes"].items():
        if file_hash == h:
            return name
    return None


def check_strings(content, db):
    for name, sig in db["strings"].items():
        if sig in content:
            return name
    return None


def check_yara(filepath):
    if yara is None:
        return None

    try:
        rules = yara.compile(YARA_RULES)
        matches = rules.match(filepath)

        if matches:
            return matches[0].rule
    except:
        pass

    return None


def check_pe(filepath):
    if pefile is None:
        return None

    try:
        pe = pefile.PE(filepath)

        for section in pe.sections:
            entropy = section.get_entropy()

            if entropy > 7.5:
                return "HighEntropyPackedPE"
    except:
        pass

    return None


def quarantine(filepath):

    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)

    filename = os.path.basename(filepath)
    dest = os.path.join(QUARANTINE_DIR, filename)

    try:
        shutil.move(filepath, dest)
    except:
        pass


def scan_file(filepath, db):

    try:
        file_hash = sha256_file(filepath)

        result = check_hash(file_hash, db)
        if result:
            return result

        with open(filepath, "rb") as f:
            content = f.read().decode(errors="ignore")

        result = check_strings(content, db)
        if result:
            return result

        result = check_yara(filepath)
        if result:
            return result

        result = check_pe(filepath)
        if result:
            return result

    except:
        pass

    return None


def scan_directory(directory, db):

    files = []

    for root, dirs, filenames in os.walk(directory):
        for name in filenames:
            files.append(os.path.join(root, name))

    with ThreadPoolExecutor(max_workers=8) as executor:
        for path, result in zip(files, executor.map(lambda f: scan_file(f, db), files)):

            if result:
                with lock:
                    print(f"[!] Threat: {result}")
                    print(f"    File: {path}")

                quarantine(path)


def scan_processes(db):

    print("\nScanning processes...\n")

    for proc in psutil.process_iter(['pid', 'name', 'exe']):

        try:
            exe = proc.info['exe']

            if exe and os.path.exists(exe):

                file_hash = sha256_file(exe)

                if check_hash(file_hash, db):

                    print(f"[!] Malicious process detected")
                    print(proc.info)

        except:
            pass


def main():

    db = load_signatures()

    target = input("Directory to scan: ")

    print("\nStarting scan...\n")

    scan_directory(target, db)

    scan_processes(db)

    print("\nScan finished")


if __name__ == "__main__":
    main()