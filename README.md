<div align="center">

```
  ██████╗ ███████╗██╗███╗   ██╗████████╗     █████╗ ██╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔══██╗██║
 ██║   ██║███████╗██║██╔██╗ ██║   ██║       ███████║██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══██║██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║       ██║  ██║██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚═╝
```

# OSINT-AI — Person Finder
### AI-powered OSINT reconnaissance CLI tool

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![BlackSec](https://img.shields.io/badge/by-BlackSec-red?style=flat-square)

</div>

---

## What is this?

**OSINT-AI** is a command-line tool that automates open-source intelligence gathering on a target (username, full name, email, or phone number) and uses an AI model to analyze all findings and generate a structured red team profile.

Built for **security researchers, CTF players, and red teamers** who want fast, AI-assisted reconnaissance without switching between 10 different tools.

---

## Features

- 🔍 **Username lookup** across 20+ platforms (GitHub, Reddit, Instagram, TikTok, Steam, Twitch, HackerNews, PyPI, npm, and more)
- 🎯 **Confidence scoring** — each result is rated High / Medium / Low to reduce false positives
- ⚠️ **False positive detection** — platforms like PyPI, npm, and HackerNews are cross-verified before marking as FOUND
- 🐙 **GitHub deep scan** — full profile, bio, location, email, repos, followers, tech stack
- 📰 **HackerNews activity** — post count and recent activity via Algolia API
- 📦 **npm packages** — published packages linked to the username
- 🔎 **Google Dorks** — auto-generated dorks for manual follow-up
- 📧 **Email breach check** — checks against known breach databases (Have I Been Pwned / XposedOrNot)
- 🧠 **AI analysis** — sends all findings to your chosen AI model for a full OSINT profile with attack vectors, behavioral patterns, and next steps
- 💾 **Export** — save results as `.json` or `.txt`
- 🔐 **Secure local config** — API keys are encrypted and stored locally, never in the repo

---

## Supported AI Providers

| Provider | Model | Notes |
|---|---|---|
| **Claude** (Anthropic) | claude-sonnet-4-6 | Recommended |
| **GPT-4** (OpenAI) | gpt-4o | |
| **Grok** (xAI) | grok-3 | |
| **Gemini** (Google) | gemini-2.0-flash | |

On first run, the tool walks you through selecting your provider and entering your API key. The key is **encrypted and stored at `~/.config/osint-ai/`** — completely outside the project directory and never committed to Git.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/EzeTauil/OSINT-AI.git
cd OSINT-AI

# Install dependencies
pip install -r requirements.txt

# Run
python osint_finder.py -u target_username
```

**Requirements:** Python 3.10+, Linux (tested on Arch Linux)

---

## Usage

```bash
# Username lookup (most powerful — recommended starting point)
python osint_finder.py -u johndoe

# Full profile combining all vectors
python osint_finder.py -n "John Doe" -u johndoe -e john@example.com -p +1234567890

# Fast recon without AI (no API tokens used)
python osint_finder.py --no-ai -u johndoe

# Save results to JSON
python osint_finder.py -u johndoe --save report.json

# Save results to TXT
python osint_finder.py -u johndoe --save report.txt

# Email breach check + dorks
python osint_finder.py -e victim@company.com

# Name-based dorks with first/last separation
python osint_finder.py -n "Jane Smith" --save output.txt
```

### Flags

| Flag | Description |
|---|---|
| `-u, --username` | Username / handle — triggers full platform lookup, GitHub scan, HN, npm |
| `-n, --name` | Full name — generates targeted Google Dorks with first/last separation |
| `-e, --email` | Email — breach database check + email-specific dorks |
| `-p, --phone` | Phone number — stored for AI context (paid API hooks ready) |
| `--save` | Export results to `.json` or `.txt` |
| `--no-ai` | Skip AI analysis (useful for quick recon or saving API tokens) |

---

## Output Example

```
┌─────────────────── Username Lookup ───────────────────┐
│ Platform     │ Status        │ Confidence │ URL        │
│ GitHub       │ ✓ FOUND       │ 🟢 High    │ github.com │
│ Reddit       │ ✓ FOUND       │ 🟢 High    │ reddit.com │
│ Steam        │ ✓ FOUND       │ 🟡 Medium  │ steam...   │
│ PyPI         │ ⚠ POSSIBLE FP │ 🔴 Low     │ pypi.org   │
└───────────────────────────────────────────────────────┘

┌─────────────── AI Analysis — Claude ──────────────────┐
│ ## EXECUTIVE SUMMARY                                   │
│ Target is a Linux-based developer focused on...        │
│                                                        │
│ ## DIGITAL FOOTPRINT                                   │
│ Confirmed on 9/20 platforms tested...                  │
│                                                        │
│ ## ATTACK VECTORS                                      │
│ Consistent username across platforms enables...        │
└───────────────────────────────────────────────────────┘
```

---

## Architecture

```
OSINT-AI/
├── osint_finder.py      # Main CLI — search modules, output, AI analysis
├── config_manager.py    # Encrypted API key management (local only)
├── requirements.txt     # Dependencies
└── .gitignore           # Excludes keys, cache, reports
```

API keys and config are stored at `~/.config/osint-ai/` (outside the repo).

---

## Paid API Hooks (coming soon)

The `PaidAPIHooks` class in `osint_finder.py` has stubs ready for:

- **Shodan** — infrastructure and IP intelligence
- **Hunter.io** — email verification and discovery
- **Intelligence X** — deep web and breach search
- **DeHashed** — breach database with full record lookup

---

## Roadmap

- [ ] Username variant correlation (`johndoe` → `johndoe_`, `_johndoe`, `johndoe01`)
- [ ] Activity timeline — cross-platform chronological view
- [ ] HTML report export — styled, shareable pentest report
- [ ] Metadata extraction from public files (PDFs, images in repos)
- [ ] Wayback Machine integration
- [ ] theHarvester integration

---

## Legal Disclaimer

This tool is intended for **authorized security testing, CTF competitions, and educational purposes only**. Using it against targets without explicit permission may be illegal in your jurisdiction. The author is not responsible for misuse.

---

## Author

**BlackSec** / [EzeTauil](https://github.com/EzeTauil)

> *"The best recon is the one the target never sees."*

---

<div align="center">
<sub>Built on Arch Linux • Powered by AI • Made for red teamers</sub>
</div>
