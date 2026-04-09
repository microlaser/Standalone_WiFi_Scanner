# Standalone WiFi Scanner (Minimal Network Manager Alternative)

## 🔐 Overview
A lightweight, command-line WiFi management and scanning tool designed as a minimal alternative to traditional Linux networking services like NetworkManager.

This tool prioritizes:
- **Low attack surface**
- **Simplicity**
- **Direct control over wireless operations**

It is intended for users who want a **lean, transparent, and security-conscious approach** to managing WiFi connections on Linux systems.

---

## 🧠 Why This Exists

Modern Linux distributions commonly rely on NetworkManager for wireless networking. While feature-rich, it introduces:

- Large codebase and complexity
- Inconsistent behavior across environments
- Increased attack surface
- Dependency-heavy architecture

This project was built with a different philosophy:

> **Networking should be simple, auditable, and predictable**

---

## ⚙️ Key Features

- 📡 Direct WiFi scanning (SSID, signal strength, etc.)
- 🧩 Minimal dependencies
- ⚡ Fast execution
- 🖥️ Fully CLI-driven
- 🔍 Transparent behavior (no hidden abstraction layers)

---

## 🛠️ Use Cases

- Replacing NetworkManager in hardened environments
- Minimal Linux systems (servers, labs, security setups)
- Security-conscious users reducing attack surface
- Debugging wireless issues without layered abstractions
- Controlled environments where predictability matters

---

## 🔐 Security Philosophy

This tool is built around a core principle:

> **Every additional layer increases attack surface**

Compared to traditional network management stacks, this approach:

- Reduces complexity
- Minimizes potential vulnerabilities
- Avoids unnecessary background services
- Keeps behavior fully observable

This aligns with real-world security practices where:
- Smaller systems are easier to secure
- Simpler code is easier to audit
- Fewer dependencies reduce risk

---

## 🚀 Usage

```bash
python3 standalone_wifi_scanner.py
