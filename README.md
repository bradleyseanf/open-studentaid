![Open StudentAid](assets/header.png)

# Open StudentAid

Read loan balances and per-loan details from supported `.studentaid.gov`
servicers through one Python API.

## Supported providers

| Provider | Authentication | Data source |
|---|---|---|
| `nelnet` | Username, password, and SMS, email, or authenticator MFA | Nelnet borrower API |
| `edfinancial` | Username, password, MFA, and DOB/SSN when the device is not recognized | Edfinancial Account Summary |

The public calls are identical for both providers. Set
`STUDENT_AID_PROVIDER` or pass `provider=` to select an implementation.

> [!WARNING]
> Login and data retrieval require a headed Chromium session because the
> servicer sites reject ordinary HTTP and headless-browser access. Linux
> servers can use Xvfb.

## Setup

### macOS or Linux desktop

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -e .
python -m playwright install chromium
```

### Ubuntu server

```bash
sudo apt update
sudo apt install -y xvfb
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -e .
python -m playwright install chromium
```

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt -e .
python -m playwright install chromium
```

## Configuration

Copy the variable names from `.env.example` into a local `.env`. Choose one
provider and enter that provider's credentials:

```dotenv
STUDENT_AID_PROVIDER=edfinancial
STUDENT_AID_USERNAME=your_username
STUDENT_AID_PASSWORD=your_password
STUDENT_AID_MFA_METHOD=sms
STUDENT_AID_DOB=MMDDYYYY
STUDENT_AID_SSN=123456789
```

`STUDENT_AID_DOB` and `STUDENT_AID_SSN` are only used by Edfinancial when it
does not recognize the browser. Nelnet requires the account username rather
than an email address.

Do not commit `.env`, `.osa/`, or `.studentaid/`. They contain credentials or
authenticated session material. These paths are excluded by the included
`.gitignore`.

## Usage

Complete the first login interactively so MFA and any identity challenge can
be answered. The saved session is reused on later calls.

```python
import open_studentaid

open_studentaid.login(provider="edfinancial")

total, count, raw = open_studentaid.loan_summary(provider="edfinancial")
loans = open_studentaid.loan_details(provider="edfinancial")
snapshot = open_studentaid.loan_snapshot(provider="edfinancial")
```

The same calls work for Nelnet:

```python
from open_studentaid import StudentAid

student_aid = StudentAid(provider="nelnet")
student_aid.login()
print(student_aid.loan_snapshot())
```

If `STUDENT_AID_PROVIDER` is set, `provider=` can be omitted.

### Public methods

| Method | Description |
|---|---|
| `login()` | Complete the selected provider's browser login and save the session. |
| `ensure_login()` | Reuse or refresh the saved authentication state. |
| `save_session()` | Save the current browser session under `.osa/`. |
| `loan_snapshot()` | Return total balance, loan count, normalized loans, and raw data. |
| `loan_summary()` | Return total balance, loan count, and raw provider data. |
| `loan_details()` | Return normalized details for each loan. |
| `get_amount()` | Return the total amount owed. |
| `get_data()` | Return raw provider data. |

Methods are available as top-level functions and on `StudentAid`.

## Provider layout

Provider-specific login and borrower-data implementations live in:

```text
open_studentaid/
  nelnet/
    auth.py
    api.py
  edfinancial/
    auth.py
    api.py
```

The top-level modules provide shared session management and dispatch, so
adding a provider does not require changing application calls.

## CLI

```bash
studentaid --provider edfinancial login
studentaid --provider edfinancial amount
studentaid --provider edfinancial details
studentaid --provider edfinancial summary
```

## Tests

```bash
python -m unittest discover -s tests -v
```

Interactive smoke test:

```bash
python tests/smoke_test.py
```

## License

MIT (see `LICENSE`).

## Notice

Open StudentAid is not affiliated with, endorsed by, or sponsored by
StudentAid.gov, Nelnet, Edfinancial, or the U.S. Department of Education. Use
it at your own risk and only to access your own data.
