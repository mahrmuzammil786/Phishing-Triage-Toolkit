# Phishing Triage Toolkit

DecodeLabs Cyber Security Training Kit — Project 3: Phishing Awareness Analysis

A hands-on toolkit for identifying phishing attempts in emails and text messages.
Includes a non-expert red-flag checklist, a triage decision tree, five analyzed
sample messages, and a Python tool that automates the checklist against any
pasted message.

## Goal

Analyze sample emails/messages to identify phishing attempts: flag suspicious
links or keywords, list red flags found, and explain why each message is unsafe
(or safe) — then act on it using a clear triage decision tree.

## Project Structure

```
phishing_triage_toolkit/
├── README.md
├── analyzer.py                          # Automated red-flag scanner (CLI tool)
├── app.py                               # Flask web app wrapping the analyzer
├── requirements.txt                     # Flask dependency for the web app
├── templates/
│   └── index.html                       # Web UI for the analyzer
├── checklist/
│   └── red_flag_checklist.md            # Manual, non-expert triage checklist
├── decision_tree/
│   └── decision_tree.md                 # Safe/Suspicious/Malicious action flow
├── analysis/
│   └── sample_analysis.md               # Full write-up analyzing all 5 samples
└── samples/
    ├── sample_1_bec_wire_transfer.txt   # Malicious - BEC wire transfer scam
    ├── sample_2_it_password_reset.txt   # Malicious - fake IT credential harvest
    ├── sample_3_legit_project_update.txt# Safe - normal internal email
    ├── sample_4_fake_invoice.txt        # Malicious - fake subscription/invoice
    └── sample_5_smishing_text.txt       # Malicious - SMS phishing (smishing)
```

## How it works

1. **Checklist** (`checklist/red_flag_checklist.md`) — a plain-language list of
   11+ red flags across sender, content, technical, and live-interaction
   categories, with a simple scoring guide.
2. **Decision tree** (`decision_tree/decision_tree.md`) — turns a checklist
   score into one of three actions: **Close**, **Warn User**, or
   **Block & Escalate**, following the "Pause, Verify, Report" rule.
3. **Sample analysis** (`analysis/sample_analysis.md`) — each of the 5 sample
   messages walked through the checklist by hand, with red flags listed and a
   final verdict.
4. **Analyzer tool** (`analyzer.py`) — a Python CLI that automates the same
   checklist: paste in a message (or point it at a sample file) and it scores
   red flags, sender-domain mismatches, suspicious/shortened links, brand
   impersonation, dangerous attachments, and more — then prints a verdict and
   recommended action.

## Run the analyzer

### Requirements
Python 3.6 or later. No external libraries needed.

### How to run
```
python analyzer.py
```
(On some systems use `python3 analyzer.py`)

You'll see a menu:
```
1. Analyze a message (paste text)
2. Analyze a sample file from /samples
3. Exit
```

- **Option 1**: paste any email/text, optionally provide a trusted company
  domain (e.g. `northwindcorp.com`) to check the sender against, then type
  `END` on its own line to run the analysis.
- **Option 2**: instantly analyze any file from the `samples/` folder.

### Example output
```
=======================================================
  PHISHING TRIAGE REPORT
=======================================================

Red flags found (5):
  1. Urgency pressure language detected
  2. Authority impersonation language detected (CEO/IT/HR/etc.)
  3. Secrecy or bypass-normal-procedure request detected
  4. Request for sensitive info or payment/credentials detected
  5. Sender-domain mismatch: 'northwind-corp.co' does not match trusted domain 'northwindcorp.com'

Risk score: 7
Verdict:    MALICIOUS
Action:     Block & Escalate
```

## Run the web app (local server)

The same analyzer logic is also available as a browser-based tool via Flask.

### Requirements
```
pip install -r requirements.txt
```

### How to run
```
python app.py
```
Then open `http://127.0.0.1:5000/` in your browser. Paste a message, optionally
enter a trusted company domain, and click **Analyze Message** to see the same
verdict/action report rendered as a web page with color-coded results
(green = Safe, yellow = Suspicious, red = Malicious).

## Results Summary

| Sample | Verdict | Action |
|---|---|---|
| BEC Wire Transfer | Malicious | Block & Escalate |
| Fake IT Password Reset | Malicious | Block & Escalate |
| Legit Project Update | Safe | Close |
| Fake Invoice | Malicious | Block & Escalate |
| Smishing Text | Malicious | Block & Escalate |

## Note on the automated tool

`analyzer.py` is a rule-based support tool, not a replacement for judgment.
It's intentionally transparent (regex + keyword rules you can read and edit)
so it's useful for learning *why* a message is flagged, not just *that* it was
flagged. Real-world phishing filters combine this kind of heuristic scoring
with sender reputation, DKIM/SPF/DMARC verification, and machine learning —
this project focuses on the human-analyst layer described in the training deck.

## Next steps (bonus)

- Add SPF/DKIM/DMARC header parsing for real inbound emails
- Build a small web UI (like the Caesar Cipher project's browser version) so
  non-technical staff can paste a message and get an instant verdict
- Expand the brand-impersonation list and add homoglyph (lookalike character)
  detection for domains
