import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import bcrypt
from cryptography.fernet import Fernet
import os
import secrets
import string

#KEY MANAGEMENT 
class KeyManager:
    KEY_FILE = "secret.key"

    @staticmethod
    def load_key():
        if not os.path.exists(KeyManager.KEY_FILE):
            key = Fernet.generate_key()
            with open(KeyManager.KEY_FILE, "wb") as f:
                f.write(key)
        return Fernet(open(KeyManager.KEY_FILE, "rb").read())

#PASSWORD HASH TOOL 
class PasswordTool(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Enter Password").pack(pady=5)
        self.pwd_entry = tk.Entry(self, show="*", width=40)
        self.pwd_entry.pack()

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Show Password",
                       variable=self.show_var,
                       command=self.toggle_password).pack()

        tk.Button(self, text="Hash Password", command=self.hash_password).pack(pady=3)
        tk.Button(self, text="Verify Password", command=self.verify_password).pack(pady=3)
        tk.Button(self, text="Check Strength", command=self.check_strength).pack(pady=3)
        tk.Button(self, text="Generate Password", command=self.generate_password).pack(pady=3)

        self.hash_output = tk.Entry(self, width=70)
        self.hash_output.pack(pady=5)

    def toggle_password(self):
        self.pwd_entry.config(show="" if self.show_var.get() else "*")

    def hash_password(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            messagebox.showwarning("Error", "Enter a password")
            return
        hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
        self.hash_output.delete(0, tk.END)
        self.hash_output.insert(0, hashed.decode())

    def verify_password(self):
        pwd = self.pwd_entry.get()
        hashed = self.hash_output.get()
        if not pwd or not hashed:
            messagebox.showwarning("Error", "Enter password and hash")
            return
        if bcrypt.checkpw(pwd.encode(), hashed.encode()):
            messagebox.showinfo("Result", "Password MATCHED ✅")
        else:
            messagebox.showerror("Result", "Password NOT MATCHED ❌")

    def check_strength(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            return
        strength = "Weak ❌"
        if (len(pwd) >= 8 and any(c.isupper() for c in pwd)
            and any(c.islower() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*" for c in pwd)):
            strength = "Strong ✅"
        elif len(pwd) >= 6:
            strength = "Medium ⚠️"
        messagebox.showinfo("Password Strength", strength)

    def generate_password(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(secrets.choice(chars) for _ in range(12))
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, pwd)

#PASSWORD MANAGER 
class PasswordManager(ttk.Frame):
    DATA_FILE = "passwords.enc"

    def __init__(self, parent, fernet):
        super().__init__(parent)
        self.fernet = fernet
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Website").pack()
        self.site_entry = tk.Entry(self, width=40)
        self.site_entry.pack()

        tk.Label(self, text="Password").pack()
        self.site_pwd_entry = tk.Entry(self, show="*", width=40)
        self.site_pwd_entry.pack()

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Show Password",
                       variable=self.show_var,
                       command=self.toggle_site_password).pack()

        tk.Button(self, text="Save Password", command=self.save_password).pack(pady=3)
        tk.Button(self, text="View Passwords", command=self.view_passwords).pack()

        self.output = tk.Text(self, height=8)
        self.output.pack(pady=5)

    def toggle_site_password(self):
        self.site_pwd_entry.config(show="" if self.show_var.get() else "*")

    def save_password(self):
        site = self.site_entry.get()
        pwd = self.site_pwd_entry.get()
        if not site or not pwd:
            return
        encrypted = self.fernet.encrypt(f"{site}:{pwd}".encode())
        with open(self.DATA_FILE, "ab") as f:
            f.write(encrypted + b"\n")
        messagebox.showinfo("Saved", "Password Saved")
        self.site_entry.delete(0, tk.END)
        self.site_pwd_entry.delete(0, tk.END)

    def view_passwords(self):
        self.output.delete("1.0", tk.END)
        if not os.path.exists(self.DATA_FILE):
            return
        with open(self.DATA_FILE, "rb") as f:
            for line in f:
                try:
                    self.output.insert(tk.END, self.fernet.decrypt(line).decode() + "\n")
                except:
                    pass

#FILE ENCRYPTOR 
class FileEncryptor(ttk.Frame):
    def __init__(self, parent, fernet):
        super().__init__(parent)
        self.fernet = fernet
        self.create_widgets()

    def create_widgets(self):
        tk.Button(self, text="Encrypt File", width=30,
                  command=self.encrypt_file).pack(pady=10)
        tk.Button(self, text="Decrypt File", width=30,
                  command=self.decrypt_file).pack()

    def encrypt_file(self):
        file = filedialog.askopenfilename()
        if not file:
            return
        with open(file, "rb") as f:
            data = f.read()
        with open(file + ".enc", "wb") as f:
            f.write(self.fernet.encrypt(data))
        messagebox.showinfo("Done", "File Encrypted")

    def decrypt_file(self):
        file = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not file:
            return
        with open(file, "rb") as f:
            data = f.read()
        with open(file.replace(".enc", ""), "wb") as f:
            f.write(self.fernet.decrypt(data))
        messagebox.showinfo("Done", "File Decrypted")

#MAIN APPLICATION 
class SecureToolkit(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Secure Toolkit")
        self.geometry("600x500")

        self.fernet = KeyManager.load_key()

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(expand=1, fill="both")

        self.tabs.add(PasswordTool(self.tabs), text="Password Tool")
        self.tabs.add(PasswordManager(self.tabs, self.fernet), text="Password Manager")
        self.tabs.add(FileEncryptor(self.tabs, self.fernet), text="File Encryption")

# RUn application
if __name__ == "__main__":
    SecureToolkit().mainloop()



