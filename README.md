# Reflected XSS Scanner (VipraTech Labs Assignment)

This repository contains a Python-based reflected XSS scanner developed for the VipraTech Labs assignment.

---

## 🛠 Features

- Supports **GET and POST** requests
- Detects reflections in responses using substring matching
- Payload generator with randomized tokens
- Handles **3 injection contexts**:
  - Attribute name
  - Attribute value
  - Text node
- Generates **HTML report output**

---

## 📌 Assumptions

- Authentication is passed via cookie (used DVWA as a test environment)
- UI is kept minimal as per requirement — focus is functionality over UI
- Only reflected XSS scanning is implemented (stored XSS may require multi-step execution)

---

## 🚀 How the Payload Generator Works

The `PayloadGenerator` class generates payloads based on the selected injection context:

| Context | Payload Example |
|--------|-----------------|
| Attribute Name | `onerror=alert("XSS_123")` |
| Attribute Value | `" autofocus onfocus=alert("XSS_123")"` |
| Text Node | `<script>alert("XSS_123")</script>` |

Random suffix is added to avoid caching and filtering.

---

## 🧪 Reflection Detection Logic

Reflection detection is performed using simple `substring matching` between:

- Payload sent
- Response content returned

If found → marked **YES**  
If not → marked **NO**

---

## 📥 Setup

git clone https://github.com/aBadRoy/Python-based-Reflected-XSS-scanner
cd Python-based-Reflected-XSS-scanner
pip install -r requirements.txt
