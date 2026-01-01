# 🔐 Security Toolkit (Python GUI)

An all-in-one **security toolkit** built with **Python & Tkinter** that demonstrates modern
**password security, encryption, and file protection** techniques.

This project is suitable for **students, beginners in cybersecurity, and Python developers**
looking to build real-world secure applications.

---

## 🚀 Features

### 🔑 Password Tool
- Secure password hashing using **bcrypt**
- Password verification
- Password strength checker
- Secure random password generator
- Show / hide password toggle

### 🗂️ Password Manager
- Store website credentials securely
- AES encryption using **Fernet**
- Encrypted password storage in file
- View decrypted passwords inside the app only

## 📂 Project Structure

```text
secure-toolkit/
│
├── secure_toolkit.py        # Main application (GUI + logic)
├── secret.key               # AES encryption key (auto-generated)
├── passwords.enc            # Encrypted password storage
├── README.md                # Project documentation
└── venv/                    # Virtual environment (optional
```

## 🔐 Security Notes

- Passwords are **bcrypt-hashed** (one-way, cannot be decrypted)  
- Data encrypted with **Fernet (AES)** using auto-generated `secret.key`  
- Deleting `secret.key` makes encrypted data unrecoverable  
- Passwords are **never stored in plain text**  
- File encryption uses **AES-128**  
- Secure random values generated with **Python `secrets` module**  
- Decryption occurs **only in memory**, not written to disk


---

## 🧩 Technologies Used

| Category | Technology |
|--------|------------|
| Programming Language | Python 3 |
| GUI Framework | Tkinter |
| Password Hashing | bcrypt |
| Encryption | cryptography (Fernet / AES) |
| Secure Random Generator | secrets |
| File Handling | Python OS & File I/O |
| UI Components | ttk (Themed Tkinter) |

---

## 🛠️ Installation

### 1️⃣ Clone the Repository
```bash
  git clone https://github.com/DevGopi-17/Multi-Functional-Security-Toolkit.git
  cd Multi-Functional-Security-Toolkit
```

## Create & Activate Virtual Environment (Recommended)
```bash
python3 -m venv venv
# macOS / Linux
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# Windows (CMD)
venv\Scripts\activate.bat
```

## Run the Application

```bash
python secure_toolkit.py
```








