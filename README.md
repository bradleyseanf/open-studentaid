# Open StudentAid API Wrapper

A Python library that provides a simple interface for accessing loan and account data from StudentAid.gov servicers (e.g. Nelnet, CRI).  
This project is designed to be **open, local, and user-friendly** — you control your own credentials and session locally.

---

## ✨ Features
- Login flow with username, password, and MFA (text/email codes).
- Automatic session/token handling (refresh & reuse).
- Consistent wrapper methods across different servicers (e.g. `loan_summary()` works for Nelnet, CRI, etc).
- Environment-based credentials (`.env` file).
- Read-only scopes by default for safety.

---

## 📦 Installation

Clone this repo and install requirements:

```bash
git clone https://github.com/bradleyseanf/open-studentaid.git
cd open-studentaid
python -m venv .venv
# Activate the venv
source .venv/bin/activate   # Linux/Mac
.\.venv\Scripts\activate    # Windows PowerShell
pip install -U pip -r requirements.txt

Setup

Create a .env file in the project root:

STUDENT_USERNAME=your_username_here
STUDENT_PASSWORD=your_password_here
STUDENT_PROVIDER=nelnet   # or cri, etc.


The wrapper will manage MFA prompts automatically (e.g., text/email code).

.

🚀 Usage Example
from open_studentaid import login_full, loan_summary

tokens = login_full(
    username="your_username_here",
    password="your_password_here",
    provider="nelnet"
)

summary = loan_summary(tokens)
print(summary)


📚 Functions Overview

The main functions currently available in open_studentaid are:

login(username, password, provider)
Starts the login flow but does not complete MFA. Returns the next step in the flow.

login_full(username, password, provider, debug=False)
Complete login + MFA in one call.
Returns an OAuth2 tokens dictionary that includes access_token and refresh_token.

loan_summary(tokens)
Uses a valid access token to fetch a borrower’s loan summary.
Returns details such as balances, loan counts, and groupings.

ensure_access_token(tokens)
Utility that checks if the current access token is still valid.
If expired, it will refresh using the refresh token.

🔒 Security & Privacy

Credentials are never uploaded anywhere; they stay local.

Tokens are cached locally in ~/.studentaid_tokens.json.

Only read-only scopes (mma.api.read) are requested.

🤝 Contributing

Pull requests are welcome!
If you’d like to add support for additional servicers or endpoints:

Fork the repo

Create a feature branch

Submit a PR

📄 License

This project is licensed under the MIT License — see LICENSE for details.