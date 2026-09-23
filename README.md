# Secure Password Generator

> A modern, cryptographically secure CLI tool for generating resilient passwords and passphrases with real-time entropy scoring, HaveIBeenPwned breach checking, and a rich terminal interface.

![Demo](demo.gif)

---

## Why This Project?

Most password generator tutorials and scripts rely on Python's built-in `random` module. While convenient, `random` uses the **Mersenne Twister** algorithm—a pseudo-random number generator (PRNG) that is completely deterministic and cryptographically broken. Given just a handful of generated outputs, an attacker can reconstruct the internal state and predict past and future passwords.

**Secure Password Generator** was built to provide production-grade security, mathematical transparency, and a friction-free command-line experience:
- **Cryptographic Randomness:** Powered strictly by Python's `secrets` module, tapping into kernel-level entropy sources (`CryptGenRandom` / `getrandom(2)`).
- **True Entropy Metrics:** Calculates exact Shannon entropy in bits and estimates brute-force crack time against modern high-performance GPU clusters ($10^9$ guesses/second).
- **Privacy-Preserving Breach Checking:** Integrates HaveIBeenPwned's API using **k-anonymity**, allowing you to verify passwords without exposing your credentials or full hashes.
- **Smart Usability:** Eliminates confusable characters (like `0` vs `O`, `1` vs `l`) and human-predictable sequential patterns (`abc`, `123`) without sacrificing entropy.
- **Zero-Footprint Clipboard & Storage:** Automatically flushes the clipboard via a background timer and ignores sensitive exports and local profiles in version control.

---

## Features

1. **Character-Based Password Generation:** Fully customizable character pools (uppercase, lowercase, digits, symbols) ensuring guaranteed representation of all enabled character sets.
2. **Diceware Passphrase Mode:** Generates human-memorable, high-entropy passphrases bundled with the official **7,776-word EFF Large Wordlist**.
3. **Entropy Scoring & Crack-Time Estimation:** Computes bits of entropy ($\text{length} \times \log_2(\text{pool\_size})$) and translates it into human-readable crack times (from `"instantly"` to `"trillions of years"`).
4. **HaveIBeenPwned Breach Checking:** Opt-in validation against billions of leaked credentials via k-anonymity.
5. **Smart Character Rules:**
   - `--exclude-ambiguous`: Filters out visually confusing characters (`0`, `O`, `o`, `1`, `l`, `I`, `|`).
   - `--avoid-sequential`: Rejects passwords containing 3+ consecutive sequential letters/digits (`abc`, `123`, `987`) or repeats (`aaa`, `111`).
6. **Bulk Export:** Exports generated batches to `.csv` (with entropy and strength metadata) or `.txt` (one per line).
7. **Clipboard Auto-Clear:** Copies the generated credential to your system clipboard and wipes it after a configurable timeout (default: 30 seconds), with overwrite detection so it never erases newer clipboard data.
8. **Configuration Profiles:** Save and recall favorite generation settings (e.g. enterprise PIN rules, database credentials, long master passphrases) with seamless CLI flag overrides.

---

## Installation

### Prerequisites
- Python 3.10+ (tested up to Python 3.14)
- Git

### 1. Clone Repository
```bash
git clone https://github.com/iamhuqa/secure-password-generator.git
cd secure-password-generator
```

### 2. Create and Activate Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**On macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

### Interactive Wizard
If launched without arguments, the tool starts a step-by-step interactive wizard:
```bash
python main.py
```

### Basic Password Generation
Generate a default 16-character password:
```bash
python main.py --length 16
```

Generate a 24-character password without symbols:
```bash
python main.py --length 24 --no-symbols
```

Generate 5 passwords:
```bash
python main.py --length 16 --count 5
```

### Passphrase Mode
Generate a 6-word passphrase separated by hyphens (default):
```bash
python main.py --passphrase
```

Generate a 4-word passphrase with a custom separator:
```bash
python main.py --passphrase --words 4 --separator "_"
```

### Breach Checking (HaveIBeenPwned)
Check whether the generated password has appeared in known data breaches:
```bash
python main.py --length 16 --check-breach
```

### Smart Rules
Exclude ambiguous characters (`0/O`, `1/l/I`) and sequential patterns (`abc`, `123`):
```bash
python main.py --length 16 --exclude-ambiguous --avoid-sequential
```

### Bulk Export
Export generated passwords to CSV (includes entropy and strength rating):
```bash
python main.py --length 16 --count 10 --export passwords.csv
```

Export passphrases to a plain text file:
```bash
python main.py --passphrase --words 5 --count 10 --export passphrases.txt
```

### Clipboard Copy with Auto-Clear
Copy the password to your clipboard and automatically clear it after 30 seconds (or custom duration):
```bash
python main.py --length 16 --copy --clear-after 45
```

### Configuration Profiles
Save your preferred settings as a reusable profile:
```bash
python main.py --length 24 --no-symbols --exclude-ambiguous --save-profile dev_db
```

List all saved profiles:
```bash
python main.py --list-profiles
```

Load a profile (and optionally override any setting on the fly):
```bash
python main.py --load-profile dev_db
python main.py --load-profile dev_db --length 32
```

---

## Security Notes

- **Cryptographic Randomness:** All generation logic exclusively uses Python's `secrets` module (and `secrets.SystemRandom().shuffle`). At no point is the pseudo-random `random` module invoked.
- **K-Anonymity Privacy Guarantee:** When `--check-breach` is enabled, the password is never sent over the network. The tool computes a SHA-1 hash locally, transmits only the first 5 hexadecimal characters (`prefix`) to HaveIBeenPwned, and receives a list of matching hash suffixes. The final 35 characters are compared locally on your machine.
- **Zero Logging & Tracking:** No passwords, hashes, or passphrases are ever logged to disk, sent to analytics, or transmitted over the internet.
- **Version Control Safety:** The `.gitignore` configuration explicitly blocks `config_profiles/`, `*.csv`, `passwords.txt`, and `exports/` to prevent sensitive credentials or local environment settings from being committed accidentally.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
