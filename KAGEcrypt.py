#!/usr/bin/env python3
"""
KAGEcrypt Production-Ready
Développé par GUY KOUAKOU (KAGEH@CK3R)

Caractéristiques :
  - Interface graphique (Tkinter) et CLI
  - Vérification MFA via TOTP (pyotp) avec configuration persistante
  - Choix entre Fernet et AES-GCM pour le chiffrement
  - Dérivation de clé sécurisée via Argon2 (argon2-cffi)
  - Compression optionnelle des fichiers
  - Traitement parallèle avec reporting de progression et annulation
  - Logging complet (fichier et affichage en temps réel dans l'interface)
  - Stubs pour mises à jour automatiques et synchronisation cloud
"""

import os, sys, json, base64, logging, threading, zlib, time, argparse, concurrent.futures
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
import pyotp

# Nom du fichier de configuration
CONFIG_FILE = "kagecrypt_config.json"

# Paramètres pour Argon2
TIME_COST = 2
MEMORY_COST = 65536   # en kibibytes (64 MB)
PARALLELISM = 2
HASH_LEN = 32
SALT_SIZE = 16

# Extensions supportées pour le chiffrement (pour fichiers non déjà cryptés)
SUPPORTED_EXTENSIONS = [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf"]

# --- Configuration du logging ---
logger = logging.getLogger("KAGEcrypt")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
file_handler = logging.FileHandler("kagecrypt.log", encoding="utf-8")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Handler pour afficher les logs dans l'interface
class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
    def emit(self, record):
        msg = self.format(record) + "\n"
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg)
            self.text_widget.configure(state='disabled')
            self.text_widget.yview(tk.END)
        self.text_widget.after(0, append)

# --- Gestion de la configuration (notamment pour le MFA) ---
class Config:
    def __init__(self, filename=CONFIG_FILE):
        self.filename = filename
        self.data = {}
        self.load()
    def load(self):
        if os.path.exists(self.filename):
            with open(self.filename, "r") as f:
                self.data = json.load(f)
        else:
            self.data = {}
        if "mfa_secret" not in self.data:
            self.data["mfa_secret"] = pyotp.random_base32()
            self.save()
    def save(self):
        with open(self.filename, "w") as f:
            json.dump(self.data, f, indent=2)
    def get_mfa_secret(self):
        return self.data.get("mfa_secret")

config = Config()

# --- Vérification MFA via TOTP ---
def verify_mfa(code):
    totp = pyotp.TOTP(config.get_mfa_secret())
    return totp.verify(code)

# --- Stub pour vérification des mises à jour ---
def check_for_updates():
    logger.info("Vérification des mises à jour...")
    # Ici, vous connecteriez à un serveur de mise à jour
    logger.info("Aucune mise à jour disponible.")
    return False

# --- Stub pour synchronisation cloud ---
def cloud_sync(filepath):
    logger.info(f"Synchronisation cloud pour {filepath} (fonctionnalité non implémentée).")
    return False

# --- Dérivation de clé via Argon2 ---
def derive_key(password, salt):
    try:
        key = hash_secret_raw(
            password.encode(),
            salt,
            time_cost=TIME_COST,
            memory_cost=MEMORY_COST,
            parallelism=PARALLELISM,
            hash_len=HASH_LEN,
            type=Type.I
        )
        return key  # clé brute (bytes)
    except Exception as e:
        logger.error(f"Erreur dans la dérivation de clé: {e}")
        raise

# --- Chiffrement d'un fichier avec choix d'algorithme ---
def encrypt_file(filepath, password, compress=False, algo="fernet"):
    if filepath.endswith(".kage"):
        logger.info(f"Fichier déjà crypté: {filepath}")
        return False
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        comp_flag = b'\x01' if compress else b'\x00'
        if compress:
            data = zlib.compress(data)
            logger.info(f"Compression effectuée sur {filepath}")
        salt = os.urandom(SALT_SIZE)
        key_raw = derive_key(password, salt)
        if algo == "fernet":
            # Pour Fernet, la clé doit être en base64 url-safe sur 32 octets
            key = base64.urlsafe_b64encode(key_raw)
            cipher = Fernet(key)
            encrypted = cipher.encrypt(data)
            algo_marker = b'\x01'
        elif algo == "aesgcm":
            cipher = AESGCM(key_raw)
            nonce = os.urandom(12)  # nonce de 96 bits
            encrypted = nonce + cipher.encrypt(nonce, data, None)
            algo_marker = b'\x02'
        else:
            logger.error(f"Algorithme inconnu: {algo}")
            return False
        new_filepath = filepath + ".kage"
        with open(new_filepath, "wb") as f:
            # Structure : comp_flag (1 octet) | salt (SALT_SIZE) | algo_marker (1 octet) | données chiffrées
            f.write(comp_flag + salt + algo_marker + encrypted)
        os.remove(filepath)
        logger.info(f"Cryptage réussi: {filepath} -> {new_filepath}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors du cryptage de {filepath}: {e}")
        return False

# --- Déchiffrement d'un fichier ---
def decrypt_file(filepath, password):
    if not filepath.endswith(".kage"):
        logger.info(f"Fichier non crypté: {filepath}")
        return False
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        comp_flag = data[0:1]
        salt = data[1:1+SALT_SIZE]
        algo_marker = data[1+SALT_SIZE:1+SALT_SIZE+1]
        encrypted = data[1+SALT_SIZE+1:]
        key_raw = derive_key(password, salt)
        if algo_marker == b'\x01':  # Fernet
            key = base64.urlsafe_b64encode(key_raw)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted)
        elif algo_marker == b'\x02':  # AESGCM
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            cipher = AESGCM(key_raw)
            decrypted = cipher.decrypt(nonce, ciphertext, None)
        else:
            logger.error("Algorithme inconnu dans le fichier crypté.")
            return False
        if comp_flag == b'\x01':
            decrypted = zlib.decompress(decrypted)
            logger.info(f"Décompression effectuée sur {filepath}")
        original_filepath = filepath[:-5]
        with open(original_filepath, "wb") as f:
            f.write(decrypted)
        os.remove(filepath)
        logger.info(f"Décryptage réussi: {filepath} -> {original_filepath}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors du décryptage de {filepath}: {e}")
        return False

# --- Traitement de répertoire avec reporting de progression et parallélisme ---
def count_files(directory, condition):
    count = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            if condition(path):
                count += 1
    return count

def encrypt_directory(directory, password, compress=False, algo="fernet", cancel_callback=lambda: False, progress_callback=lambda n: None):
    files = []
    for root, dirs, filenames in os.walk(directory):
        for f in filenames:
            path = os.path.join(root, f)
            if any(path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                files.append(path)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for path in files:
            if cancel_callback():
                logger.info("Opération annulée par l'utilisateur.")
                return False
            futures.append(executor.submit(encrypt_file, path, password, compress, algo))
        for future in concurrent.futures.as_completed(futures):
            progress_callback(1)
    return True

def decrypt_directory(directory, password, cancel_callback=lambda: False, progress_callback=lambda n: None):
    files = []
    for root, dirs, filenames in os.walk(directory):
        for f in filenames:
            path = os.path.join(root, f)
            if path.endswith(".kage"):
                files.append(path)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for path in files:
            if cancel_callback():
                logger.info("Opération annulée par l'utilisateur.")
                return False
            futures.append(executor.submit(decrypt_file, path, password))
        for future in concurrent.futures.as_completed(futures):
            progress_callback(1)
    return True

def secure_wipe(var):
    """
    Tentative naïve de suppression sécurisée de données sensibles.
    En Python, les chaînes sont immuables, donc cette méthode reste limitée.
    """
    if isinstance(var, bytearray):
        for i in range(len(var)):
            var[i] = 0

# --- Interface en ligne de commande (CLI) ---
def main_cli():
    parser = argparse.ArgumentParser(description="KAGEcrypt Production-Ready CLI")
    parser.add_argument("operation", choices=["encrypt", "decrypt"], help="Opération à effectuer")
    parser.add_argument("path", help="Chemin du fichier ou répertoire")
    parser.add_argument("--password", required=True, help="Mot de passe")
    parser.add_argument("--compress", action="store_true", help="Activer la compression")
    parser.add_argument("--algo", choices=["fernet", "aesgcm"], default="fernet", help="Algorithme de chiffrement")
    parser.add_argument("--mfa", required=True, help="Code MFA (TOTP)")
    args = parser.parse_args()
    
    if not verify_mfa(args.mfa):
        print("Vérification MFA échouée.")
        sys.exit(1)
    
    check_for_updates()
    start_time = time.time()
    if os.path.isfile(args.path):
        if args.operation == "encrypt":
            result = encrypt_file(args.path, args.password, args.compress, args.algo)
        else:
            result = decrypt_file(args.path, args.password)
    elif os.path.isdir(args.path):
        if args.operation == "encrypt":
            result = encrypt_directory(args.path, args.password, args.compress, args.algo,
                                        cancel_callback=lambda: False,
                                        progress_callback=lambda n: None)
        else:
            result = decrypt_directory(args.path, args.password,
                                        cancel_callback=lambda: False,
                                        progress_callback=lambda n: None)
    else:
        print("Chemin invalide")
        sys.exit(1)
    elapsed = time.time() - start_time
    if result:
        print(f"Opération terminée avec succès en {elapsed:.2f} secondes.")
        cloud_sync(args.path)
    else:
        print("L'opération a échoué.")
    sys.exit(0)

# --- Interface graphique (Tkinter) ---
class KAGEcryptApp:
    def __init__(self, master):
        self.master = master
        master.title("KAGEcrypt Production-Ready")
        master.geometry("1000x800")
        self.cancel_flag = False

        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Menu
        self.menu_bar = tk.Menu(master)
        master.config(menu=self.menu_bar)
        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        help_menu.add_command(label="À propos", command=self.show_about)
        self.menu_bar.add_cascade(label="Aide", menu=help_menu)

        # Cadre principal
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Titre
        header = ttk.Label(main_frame, text="KAGEcrypt Production-Ready", font=("Helvetica", 24, "bold"))
        header.pack(pady=10)

        # Cadre de saisie
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        ttk.Label(input_frame, text="Mot de passe :").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(input_frame, show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Label(input_frame, text="MFA Code :").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.mfa_entry = ttk.Entry(input_frame)
        self.mfa_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Vérifier MFA", command=self.verify_mfa_gui).grid(row=0, column=4, padx=5)

        ttk.Label(input_frame, text="Chemin :").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.path_entry = ttk.Entry(input_frame)
        self.path_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Fichier", command=self.choose_file).grid(row=1, column=4, padx=5)
        ttk.Button(input_frame, text="Répertoire", command=self.choose_directory).grid(row=1, column=5, padx=5)
        input_frame.columnconfigure(1, weight=1)

        # Options : algorithme et compression
        option_frame = ttk.Frame(main_frame)
        option_frame.pack(fill=tk.X, pady=5)
        ttk.Label(option_frame, text="Algorithme:").pack(side=tk.LEFT, padx=5)
        self.algo_var = tk.StringVar(value="fernet")
        algo_combo = ttk.Combobox(option_frame, textvariable=self.algo_var, values=["fernet", "aesgcm"], state="readonly")
        algo_combo.pack(side=tk.LEFT, padx=5)
        self.compress_var = tk.BooleanVar()
        compress_check = ttk.Checkbutton(option_frame, text="Compression", variable=self.compress_var)
        compress_check.pack(side=tk.LEFT, padx=5)

        # Choix de l'opération
        op_frame = ttk.Frame(main_frame)
        op_frame.pack(fill=tk.X, pady=10)
        self.operation = tk.StringVar(value="encrypt")
        ttk.Radiobutton(op_frame, text="Crypter", variable=self.operation, value="encrypt").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(op_frame, text="Décrypter", variable=self.operation, value="decrypt").pack(side=tk.LEFT, padx=10)

        # Barre de progression
        self.progress = ttk.Progressbar(main_frame, mode="determinate")
        self.progress.pack(fill=tk.X, pady=5)

        # Boutons Exécuter / Annuler
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)
        self.exec_button = ttk.Button(btn_frame, text="Exécuter", command=self.execute_operation)
        self.exec_button.pack(side=tk.LEFT, padx=10)
        self.cancel_button = ttk.Button(btn_frame, text="Annuler", command=self.cancel_operation, state=tk.DISABLED)
        self.cancel_button.pack(side=tk.LEFT, padx=10)

        # Zone de logs
        log_label = ttk.Label(main_frame, text="Logs :")
        log_label.pack(anchor=tk.W, pady=(10,0))
        self.log_widget = scrolledtext.ScrolledText(main_frame, height=10, state="disabled")
        self.log_widget.pack(fill=tk.BOTH, expand=True, pady=5)
        text_handler = TextHandler(self.log_widget)
        text_handler.setFormatter(formatter)
        logger.addHandler(text_handler)

    def choose_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, file_path)
            logger.info(f"Fichier sélectionné: {file_path}")

    def choose_directory(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, dir_path)
            logger.info(f"Répertoire sélectionné: {dir_path}")

    def verify_mfa_gui(self):
        code = self.mfa_entry.get()
        if verify_mfa(code):
            messagebox.showinfo("MFA", "Vérification MFA réussie.")
            logger.info("MFA vérifié avec succès.")
        else:
            messagebox.showerror("MFA", "Échec de la vérification MFA.")
            logger.error("Échec de la vérification MFA.")

    def execute_operation(self):
        password = self.password_entry.get()
        mfa_code = self.mfa_entry.get()
        if not verify_mfa(mfa_code):
            messagebox.showerror("Erreur", "Vérification MFA échouée.")
            return
        path = self.path_entry.get()
        if not password or not path:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
            return
        self.cancel_flag = False
        self.exec_button.config(state=tk.DISABLED)
        self.cancel_button.config(state=tk.NORMAL)
        if os.path.isdir(path):
            if self.operation.get() == "encrypt":
                total = count_files(path, lambda p: any(p.endswith(ext) for ext in SUPPORTED_EXTENSIONS))
            else:
                total = count_files(path, lambda p: p.endswith(".kage"))
            self.progress.config(mode="determinate", maximum=total, value=0)
        else:
            self.progress.config(mode="indeterminate")
            self.progress.start(10)
        logger.info("Début de l'opération...")
        threading.Thread(target=self.run_operation, args=(password, path, self.compress_var.get(), self.algo_var.get()), daemon=True).start()

    def cancel_operation(self):
        self.cancel_flag = True
        logger.info("Annulation demandée par l'utilisateur.")

    def run_operation(self, password, path, compress, algo):
        def progress_callback(n):
            self.progress.step(n)
        success = False
        start_time = time.time()
        try:
            if self.operation.get() == "encrypt":
                if os.path.isfile(path):
                    if any(path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                        success = encrypt_file(path, password, compress, algo)
                    else:
                        messagebox.showinfo("Info", "Type de fichier non supporté pour le cryptage.")
                        logger.info("Type de fichier non supporté.")
                        self.exec_button.config(state=tk.NORMAL)
                        self.cancel_button.config(state=tk.DISABLED)
                        return
                elif os.path.isdir(path):
                    success = encrypt_directory(path, password, compress, algo,
                                                cancel_callback=lambda: self.cancel_flag,
                                                progress_callback=progress_callback)
                else:
                    messagebox.showerror("Erreur", "Chemin invalide.")
                    logger.error("Chemin invalide.")
                    return
            elif self.operation.get() == "decrypt":
                if os.path.isfile(path):
                    success = decrypt_file(path, password)
                elif os.path.isdir(path):
                    success = decrypt_directory(path, password,
                                                cancel_callback=lambda: self.cancel_flag,
                                                progress_callback=progress_callback)
                else:
                    messagebox.showerror("Erreur", "Chemin invalide.")
                    logger.error("Chemin invalide.")
                    return
            elapsed = time.time() - start_time
            if self.cancel_flag:
                self.status("Opération annulée.")
            elif success:
                messagebox.showinfo("Succès", f"Opération terminée avec succès en {elapsed:.2f} secondes.")
                self.status("Opération réussie.")
                cloud_sync(path)
            else:
                messagebox.showerror("Erreur", "L'opération a échoué.")
                self.status("Échec de l'opération.")
        except Exception as e:
            logger.error(f"Exception: {e}")
            messagebox.showerror("Erreur critique", f"Une erreur est survenue: {e}")
            self.status("Erreur critique lors de l'opération.")
        finally:
            self.progress.stop()
            self.exec_button.config(state=tk.NORMAL)
            self.cancel_button.config(state=tk.DISABLED)

    def status(self, message):
        logger.info(message)

    def show_about(self):
        messagebox.showinfo("À propos", "KAGEcrypt Production-Ready\nDéveloppé par GUY KOUAKOU\n(KAGEH@CK3R)")

# --- Point d'entrée principal ---
def main():
    if len(sys.argv) > 1:
        main_cli()
    else:
        root = tk.Tk()
        app = KAGEcryptApp(root)
        root.mainloop()

if __name__ == "__main__":
    main()

# KAGEH@CK3R – GUY KOUAKOU

