import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import os
import requests
import shutil
import lzma

class AndroidToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ADB Android Toolkit")
        self.root.geometry("600x500")

        self.create_widgets()

    def create_widgets(self):
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)

        buttons = [
            ("Load ROM", self.load_rom),
            ("Load SuperSU", self.load_supersu),
            ("Install Drozer", self.install_drozer),
            ("Load Gapps", self.load_gapps),
            ("Install Burp Cert", self.install_burp_cert),
            ("Start Frida-Server", self.start_frida),
        ]

        for (label, command) in buttons:
            tk.Button(btn_frame, text=label, width=20, command=command).pack(pady=5)

        self.output = scrolledtext.ScrolledText(self.root, height=15, width=70)
        self.output.pack(pady=10)

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def run_cmd(self, cmd, shell=False):
        try:
            result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
            self.log(result.stdout)
            if result.stderr:
                self.log(result.stderr)
        except Exception as e:
            self.log(f"Errore: {e}")

    def choose_file(self, filetypes):
        return filedialog.askopenfilename(filetypes=filetypes)

    def load_rom(self):
        path = self.choose_file([("ZIP files", "*.zip")])
        if path:
            self.log(f"Pushing ROM: {path}")
            self.run_cmd(["adb", "push", path, "/sdcard/"])

    def load_supersu(self):
        path = self.choose_file([("ZIP files", "*.zip")])
        if path:
            self.log(f"Pushing SuperSU: {path}")
            self.run_cmd(["adb", "push", path, "/sdcard/"])

    def install_drozer(self):
        tmp_dir = "/tmp/DrozerTmp"
        os.makedirs(tmp_dir, exist_ok=True)
        apk_path = os.path.join(tmp_dir, "drozer.apk")
        url = "https://github.com/mwrlabs/drozer/releases/download/2.3.4/drozer-agent-2.3.4.apk"
        self.log("Scaricando Drozer...")
        r = requests.get(url)
        with open(apk_path, "wb") as f:
            f.write(r.content)
        self.run_cmd(["adb", "install", apk_path])
        shutil.rmtree(tmp_dir)

    def load_gapps(self):
        path = self.choose_file([("ZIP files", "*.zip")])
        if path:
            self.log(f"Pushing Gapps: {path}")
            self.run_cmd(["adb", "push", path, "/sdcard/"])

    def install_burp_cert(self):
        cert_path = self.choose_file([("CER files", "*.cer")])
        if not cert_path:
            return
        self.log("Converting certificate...")
        self.run_cmd(["openssl", "x509", "-inform", "DER", "-in", cert_path, "-out", "cacert.pem"])
        result = subprocess.run(["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", "cacert.pem"], capture_output=True, text=True)
        codecer = result.stdout.strip().splitlines()[0]
        new_name = f"{codecer}.0"
        os.rename("cacert.pem", new_name)
        self.run_cmd(["adb", "root"])
        self.run_cmd(["adb", "remount"])
        self.run_cmd(["adb", "push", new_name, "/sdcard/"])
        self.run_cmd(["adb", "shell", f"mv /sdcard/{new_name} /system/etc/security/cacerts/"])
        self.run_cmd(["adb", "shell", f"chmod 644 /system/etc/security/cacerts/{new_name}"])
        os.remove(new_name)

    def get_device_arch(self):
        result = subprocess.run(["adb", "shell", "getprop", "ro.product.cpu.abi"], capture_output=True, text=True)
        abi = result.stdout.strip()
        return {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "x86": "x86",
            "x86_64": "x86_64"
        }.get(abi, None)

    def start_frida(self):
        arch = self.get_device_arch()
        if not arch:
            self.log("Architettura non supportata.")
            return
        self.log(f"Architettura: {arch}")
        version = requests.get("https://api.github.com/repos/frida/frida/releases/latest").json()["tag_name"]
        self.log(f"Ultima versione Frida: {version}")
        filename = f"frida-server-{version}-android-{arch}.xz"
        url = f"https://github.com/frida/frida/releases/download/{version}/{filename}"
        r = requests.get(url, stream=True)
        with open(filename, "wb") as f:
            shutil.copyfileobj(r.raw, f)
        output_file = filename.replace(".xz", "")
        with lzma.open(filename) as xz_file, open(output_file, 'wb') as out_f:
            shutil.copyfileobj(xz_file, out_f)
        os.remove(filename)
        self.run_cmd(["adb", "root"])
        self.run_cmd(["adb", "push", output_file, "/data/local/tmp/"])
        self.run_cmd(["adb", "shell", f"chmod 755 /data/local/tmp/{output_file}"])
        self.run_cmd(["adb", "shell", f"/data/local/tmp/{output_file} &"], shell=True)
        os.remove(output_file)

if __name__ == "__main__":
    root = tk.Tk()
    app = AndroidToolkitApp(root)
    root.mainloop()
