import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import bcrypt
from cryptography.fernet import Fernet
import os
import secrets
import string
import pyperclip  # For copy to clipboard

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

#PASSWORD TOOL
class PasswordTool(ttk.Frame):
    def __init__(self, parent, fernet):
        super().__init__(parent)
        self.fernet = fernet
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Enter Password").pack(pady=5)
        self.pwd_entry = tk.Entry(self, show="*", width=40)
        self.pwd_entry.pack()

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Show Password",
                       variable=self.show_var,
                       command=self.toggle_password).pack()

        # tk.Button(self, text="Hash Password", command=self.hash_password).pack(pady=2)
        # tk.Button(self, text="Verify Password", command=self.verify_password).pack(pady=2)
        tk.Button(self, text="Encrypt Password", command=self.encrypt_password).pack(pady=2)
        tk.Button(self, text="Decrypt Password", command=self.decrypt_password).pack(pady=2)
        tk.Button(self, text="Check Strength", command=self.check_strength).pack(pady=2)
        tk.Button(self, text="Generate Password", command=self.generate_password).pack(pady=2)
        tk.Button(self, text="Copy Output", command=self.copy_output).pack(pady=2)

        self.output = tk.Entry(self, width=70)
        self.output.pack(pady=5)

    def toggle_password(self):
        self.pwd_entry.config(show="" if self.show_var.get() else "*")

    # def hash_password(self):
    #     pwd = self.pwd_entry.get()
    #     if not pwd:
    #         messagebox.showwarning("Error", "Enter a password")
    #         return
    #     hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
    #     self.output.delete(0, tk.END)
    #     self.output.insert(0, hashed.decode())

    # def verify_password(self):
    #     pwd = self.pwd_entry.get()
    #     hashed = self.output.get()
    #     if not pwd or not hashed:
    #         messagebox.showwarning("Error", "Enter password and hash")
    #         return
    #     try:
    #         if bcrypt.checkpw(pwd.encode(), hashed.encode()):
    #             messagebox.showinfo("Result", "Password MATCHED ✅")
    #         else:
    #             messagebox.showerror("Result", "Password NOT MATCHED ❌")
    #     except:
    #         messagebox.showerror("Error", "Invalid hash format")

    def encrypt_password(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            return
        encrypted = self.fernet.encrypt(pwd.encode())
        self.output.delete(0, tk.END)
        self.output.insert(0, encrypted.decode())

    def decrypt_password(self):
        encrypted = self.output.get()
        if not encrypted:
            return
        try:
            decrypted = self.fernet.decrypt(encrypted.encode()).decode()
            self.output.delete(0, tk.END)
            self.output.insert(0, decrypted)
        except:
            messagebox.showerror("Error", "Invalid encrypted string")

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

    def copy_output(self):
        out = self.output.get()
        if out:
            pyperclip.copy(out)
            messagebox.showinfo("Copied", "Output copied to clipboard")


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

        tk.Button(self, text="Save Password", command=self.save_password).pack(pady=2)
        tk.Button(self, text="View Passwords", command=self.view_passwords).pack(pady=2)
        tk.Button(self, text="Copy Selected", command=self.copy_selected).pack(pady=2)

        tk.Label(self, text="Search by Website").pack(pady=2)
        self.search_entry = tk.Entry(self, width=30)
        self.search_entry.pack()
        tk.Button(self, text="Search", command=self.search_password).pack(pady=2)

        self.output = tk.Text(self, height=10)
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

    def search_password(self):
        query = self.search_entry.get().lower()
        self.output.delete("1.0", tk.END)
        if not os.path.exists(self.DATA_FILE):
            return
        with open(self.DATA_FILE, "rb") as f:
            for line in f:
                try:
                    dec = self.fernet.decrypt(line).decode()
                    if query in dec.lower():
                        self.output.insert(tk.END, dec + "\n")
                except:
                    pass

    def copy_selected(self):
        try:
            selected = self.output.get(tk.SEL_FIRST, tk.SEL_LAST)
            pyperclip.copy(selected)
            messagebox.showinfo("Copied", "Selected text copied to clipboard")
        except:
            messagebox.showwarning("Error", "No text selected")

#FILE ENCRYPTOR
class FileEncryptor(ttk.Frame):
    def __init__(self, parent, fernet):
        super().__init__(parent)
        self.fernet = fernet
        self.create_widgets()

    def create_widgets(self):
        tk.Button(self, text="Encrypt File(s)", width=30,
                  command=self.encrypt_files).pack(pady=5)
        tk.Button(self, text="Decrypt File(s)", width=30,
                  command=self.decrypt_files).pack(pady=5)

    def encrypt_files(self):
        files = filedialog.askopenfilenames()
        if not files:
            return
        for file in files:
            with open(file, "rb") as f:
                data = f.read()
            with open(file + ".enc", "wb") as f:
                f.write(self.fernet.encrypt(data))
        messagebox.showinfo("Done", f"{len(files)} file(s) encrypted")

    def decrypt_files(self):
        files = filedialog.askopenfilenames(filetypes=[("Encrypted Files", "*.enc")])
        if not files:
            return
        for file in files:
            with open(file, "rb") as f:
                data = f.read()
            # Backup original
            backup_file = file + ".bak"
            with open(backup_file, "wb") as b:
                b.write(data)
            # Decrypt
            try:
                decrypted = self.fernet.decrypt(data)
                with open(file.replace(".enc", ""), "wb") as f:
                    f.write(decrypted)
            except:
                messagebox.showerror("Error", f"Failed to decrypt {file}")
        messagebox.showinfo("Done", f"{len(files)} file(s) decrypted (backups created)")

#SECURE NOTES(Personal Notepad)
class SecureNotes(ttk.Frame):
    DATA_FILE = "notes.enc"

    def __init__(self, parent, fernet):
        super().__init__(parent)
        self.fernet = fernet
        self.create_widgets()
        self.load_notes()

    def create_widgets(self):
        self.note_text = tk.Text(self, height=15)
        self.note_text.pack(pady=5)

        tk.Button(self, text="Save Notes", command=self.save_notes).pack(pady=2)
        tk.Button(self, text="Load Notes", command=self.load_notes).pack(pady=2)

    def save_notes(self):
        data = self.note_text.get("1.0", tk.END).encode()
        encrypted = self.fernet.encrypt(data)
        with open(self.DATA_FILE, "wb") as f:
            f.write(encrypted)
        messagebox.showinfo("Saved", "Notes saved securely")

    def load_notes(self):
        if not os.path.exists(self.DATA_FILE):
            return
        with open(self.DATA_FILE, "rb") as f:
            try:
                decrypted = self.fernet.decrypt(f.read()).decode()
                self.note_text.delete("1.0", tk.END)
                self.note_text.insert(tk.END, decrypted)
            except:
                messagebox.showerror("Error", "Failed to load notes")

#RANDOM KEY GENERATOR()
class KeyGenerator(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Key Length").pack()
        self.len_entry = tk.Entry(self)
        self.len_entry.pack()
        tk.Button(self, text="Generate Key/Token", command=self.generate_key).pack(pady=5)
        tk.Button(self, text="Copy to Clipboard", command=self.copy_key).pack(pady=2)
        self.output = tk.Entry(self, width=70)
        self.output.pack(pady=5)

    def generate_key(self):
        try:
            length = int(self.len_entry.get())
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            key = ''.join(secrets.choice(chars) for _ in range(length))
            self.output.delete(0, tk.END)
            self.output.insert(0, key)
        except:
            messagebox.showerror("Error", "Enter valid length")

    def copy_key(self):
        key = self.output.get()
        if key:
            pyperclip.copy(key)
            messagebox.showinfo("Copied", "Key copied to clipboard")

#MAIN APPLICATION
class SecureToolkit(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Secure Toolkit")
        self.geometry("700x600")

        self.fernet = KeyManager.load_key()

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(expand=1, fill="both")

        self.tabs.add(PasswordTool(self.tabs, self.fernet), text="Password Tool")
        self.tabs.add(PasswordManager(self.tabs, self.fernet), text="Password Manager")
        self.tabs.add(FileEncryptor(self.tabs, self.fernet), text="File Encryption")
        self.tabs.add(SecureNotes(self.tabs, self.fernet), text="Secure Notes")
        self.tabs.add(KeyGenerator(self.tabs), text="Key/Token Generator")


if __name__ == "__main__":
    SecureToolkit().mainloop()
