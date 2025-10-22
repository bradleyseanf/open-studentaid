# 🏛️ Open StudentAid API Wrapper

A Python library providing a clean interface for accessing loan and account data from StudentAid.gov servicers (e.g., **Nelnet**, **CRI**).  
It’s designed to be **open, local, and secure** — you control your credentials and tokens, stored only on your machine.

---

## ✨ Features
- Interactive **browser login with MFA** (text/email codes)
- **Automatic token caching** and refresh via local session store
- Consistent API surface across servicers (`loan_summary()`, etc.)
- Works with `.env` credentials or direct parameters
- Read-only scopes by default for safety

---

## 📦 Installation

Clone the repository and install dependencies:

    git clone https://github.com/bradleyseanf/open-studentaid.git
    cd open-studentaid
    python -m venv .venv
    # Activate the environment
    # Linux/Mac:
    source .venv/bin/activate
    # Windows PowerShell:
    .\.venv\Scripts\activate
    pip install -U pip -r requirements.txt

### Optional: environment variables

Create a `.env` file in the root for convenience:

    STUDENT_AID_PROVIDER=nelnet   # or cri
    CLIENT_ID=mma

---

## 🚀 Quick Start

    from open_studentaid import browser_login, ensure_login, loan_summary

    # 1️⃣ First-time login (opens real browser, completes MFA)
    browser_login(provider="nelnet", debug=True)

    # 2️⃣ Auto-refresh and fetch your loan data
    ensure_login(provider="nelnet")
    total, count, raw = loan_summary(provider="nelnet")

    print(f"You have {count} loans, total balance: ${total:,.2f}")

---

## 📚 API Overview

- **browser_login(provider, debug=False)**  
  Opens a real browser for login & MFA, then saves tokens under `~/.studentaid/`.

- **ensure_login(provider)**  
  Loads cached tokens; refreshes if expired using the refresh token.

- **loan_summary(provider)**  
  Retrieves borrower loan data. Returns `(total_balance, loan_count, raw_json)`.

- **StudentAid class**  
  Optional OOP wrapper: `StudentAid("nelnet").loan_summary()`.

---

## 🔒 Security
- Credentials and tokens **never leave your device**
- Tokens are cached safely under `~/.studentaid/tokens_<provider>.json`
- Only read-only API scopes (`mma.api.read`) are used by default

---

## 🧩 Folder Layout
- ├── init.py
- ├── auth.py
- ├── api.py
- ├── config.py
- └── sessions.py
---

## 🤝 Contributing
Pull requests are welcome!  
If you’d like to add support for additional servicers or endpoints:

1. Fork the repo  
2. Create a feature branch  
3. Submit a PR  

---

## 📄 License
This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
