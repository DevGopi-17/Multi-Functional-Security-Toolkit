# 🔐 Secure Toolkit — Python Security Application

A desktop-based **security toolkit** built with **Python and Tkinter** that demonstrates
practical concepts of **encryption, secure storage, and sensitive data handling**.

This project is designed as a **portfolio-grade application** for showcasing
skills in **Python development, cybersecurity fundamentals, and GUI design**.

---

## 📌 Overview

**Secure Toolkit** is a multi-module Python application that allows users to:

- Encrypt and decrypt sensitive data
- Securely store credentials and notes
- Protect files using strong symmetric encryption
- Generate cryptographically secure keys and passwords

The project emphasizes **clarity, security awareness, and real-world usability**.

---

## ✨ Key Features

### 🔑 Password Encryption Tool
- Reversible password encryption using **Fernet (AES)**
- Password decryption with key-based security
- Password strength analysis
- Secure random password generation
- Clipboard copy support
- Show / hide password toggle

---

### 🗂️ Encrypted Password Manager
- Secure storage of website credentials
- All data encrypted before being written to disk
- Search functionality for stored credentials
- Decryption performed only inside the application
- Clipboard support for selected entries

---

### 📁 File Encryption & Decryption
- Encrypt and decrypt files using AES encryption
- Supports multiple file selection
- Automatic backup creation during decryption
- Prevents accidental data loss

---

### 📝 Secure Notes
- Encrypted personal notes storage
- Notes remain encrypted on disk at all times
- Decryption occurs only on demand

---

### 🔐 Key / Token Generator
- Generates cryptographically secure random keys
- Customizable key length
- Suitable for tokens, API keys, or secrets

---

## 🗂️ Project Structure

```text
secure-toolkit/
│
├── secure_toolkit.py        # Main application (GUI + logic)
├── secret.key               # Symmetric encryption key (auto-generated)
├── passwords.enc            # Encrypted credentials storage
├── notes.enc                # Encrypted secure notes
├── README.md                # Project documentation
└── venv/                    # Virtual environment (optional)
```

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








