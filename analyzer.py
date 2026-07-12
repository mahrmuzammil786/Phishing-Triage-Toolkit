"""
Phishing Triage Analyzer
DecodeLabs - Cyber Security Industrial Training Kit - Project 3

Goal: Scan an email/text message against a rule-based red-flag checklist,
score its risk, and recommend a triage action (Close / Warn User /
Block & Escalate), matching red_flag_checklist.md and decision_tree.md.
"""

import re

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

URGENCY_PATTERNS = [
    r"\bimmediately\b", r"(?<!non-)(?<!non )\burgent(ly)?\b", r"\bact now\b",
    r"\bexpires? (today|soon)\b",
    r"\b\d{1,2}\s?(hours?|hrs?|minutes?|mins?)\b.*(deadline|expire|suspend|lock)",
    r"\bwithin \d+\s?(hours?|hrs?|minutes?|mins?)\b", r"\bright away\b", r"\bfinal notice\b",
]

SUSPICIOUS_LINK_WORDING = [
    "login", "secure", "verify", "update", "redeliver", "recovery", "confirm", "reset",
]

# Well-known brands commonly impersonated in phishing/smishing links.
# Maps brand keyword -> its real primary domain, for a simple mismatch check.
KNOWN_BRANDS = {
    "fedex": "fedex.com", "ups": "ups.com", "dhl": "dhl.com", "amazon": "amazon.com",
    "paypal": "paypal.com", "microsoft": "microsoft.com", "google": "google.com",
    "apple": "apple.com", "netflix": "netflix.com", "chase": "chase.com",
}

AUTHORITY_PATTERNS = [
    r"\bceo\b", r"\bit security\b", r"\bhr department\b", r"\blaw enforcement\b",
    r"\bexecutive\b", r"\bmanagement\b", r"\baccounting department\b",
]

SECRECY_BYPASS_PATTERNS = [
    r"\bconfidential\b", r"\bdo not (discuss|tell|share)\b", r"\bbypass\b",
    r"\bdon'?t (call|verify|check)\b", r"\bkeep this (between us|private)\b",
]

FEAR_GREED_PATTERNS = [
    r"\bsuspend(ed|sion)?\b", r"\blegal action\b", r"\baccount (will be )?locked\b",
    r"\bfailure to\b", r"\brefund\b", r"\bwinner\b", r"\bcongratulations\b",
    r"\bclaim your\b",
]

SENSITIVE_INFO_PATTERNS = [
    r"\bpassword\b", r"\bverification code\b", r"\bmfa code\b", r"\botp\b",
    r"\bbank details\b", r"\bwire transfer\b", r"\baccount number\b", r"\brouting\b",
    r"\bssn\b", r"\bsocial security\b", r"\bupdate your billing\b",
]

LINK_PATTERNS = [
    r"https?://\S+",
]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

DANGEROUS_EXTENSIONS = [".exe", ".scr", ".js", ".iso", ".jar", ".bat", ".vbs", ".html"]

FORWARD_CHAIN_PATTERN = r"^\s*(re:\s*)?fw:"

QR_CODE_PATTERN = r"\bqr code\b|\bscan (this|the) code\b"

CALLBACK_SCAM_PATTERN = r"\bcall (us|support|the number below)\b|\b1-800-\S+\b"


def find_matches(text, patterns):
    """Return list of pattern descriptions that matched in text (case-insensitive)."""
    hits = []
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(pat)
    return hits


def extract_sender_domain(text):
    """Try to extract the sender's email domain from a 'From:' line."""
    match = re.search(r"From:.*?<[^@]+@([\w\.-]+)>", text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def check_lookalike_domain(domain, trusted_domain):
    """Very simple lookalike check: domain differs from trusted domain but is
    similar (extra hyphens/words, different TLD, or trusted name buried as a
    subdomain rather than being the actual root domain)."""
    if not domain or not trusted_domain:
        return False
    if domain == trusted_domain:
        return False
    trusted_root = trusted_domain.split(".")[0]
    if trusted_root in domain:
        return True
    return False


def analyze(text, trusted_domain=None):
    findings = []
    score = 0

    if find_matches(text, URGENCY_PATTERNS):
        findings.append("Urgency pressure language detected")
        score += 1

    if find_matches(text, AUTHORITY_PATTERNS):
        findings.append("Authority impersonation language detected (CEO/IT/HR/etc.)")
        score += 1

    if find_matches(text, SECRECY_BYPASS_PATTERNS):
        findings.append("Secrecy or bypass-normal-procedure request detected")
        score += 1

    if find_matches(text, FEAR_GREED_PATTERNS):
        findings.append("Fear or greed hook detected (threats/rewards)")
        score += 1

    if find_matches(text, SENSITIVE_INFO_PATTERNS):
        findings.append("Request for sensitive info or payment/credentials detected")
        score += 2  # weighted higher - this is a high-risk indicator

    links = re.findall(LINK_PATTERNS[0], text)
    flagged_links = set()
    for link in links:
        for shortener in SHORTENER_DOMAINS:
            if shortener in link:
                findings.append(f"Shortened/obscured link detected: {link}")
                score += 2
                flagged_links.add(link)
        link_lower = link.lower()
        for brand, real_domain in KNOWN_BRANDS.items():
            if brand in link_lower and real_domain not in link_lower:
                findings.append(
                    f"Brand impersonation domain detected: '{link}' references "
                    f"'{brand}' but is not the real {real_domain} domain"
                )
                score += 2
                flagged_links.add(link)
                break

        if link not in flagged_links:
            for word in SUSPICIOUS_LINK_WORDING:
                if word in link_lower:
                    findings.append(f"Suspicious link wording detected: {link}")
                    score += 1
                    flagged_links.add(link)
                    break

    for ext in DANGEROUS_EXTENSIONS:
        if ext in text.lower():
            findings.append(f"Dangerous attachment extension detected: {ext}")
            score += 2

    if re.search(FORWARD_CHAIN_PATTERN, text, re.IGNORECASE | re.MULTILINE):
        findings.append("Fake forwarded chain marker detected (FW: on a fresh message)")
        score += 1

    if re.search(QR_CODE_PATTERN, text, re.IGNORECASE):
        findings.append("QR code prompt detected (Quishing)")
        score += 1

    if re.search(CALLBACK_SCAM_PATTERN, text, re.IGNORECASE):
        findings.append("Callback scam pattern detected (TOAD)")
        score += 1

    sender_domain = extract_sender_domain(text)
    if trusted_domain and sender_domain:
        if sender_domain != trusted_domain.lower():
            if check_lookalike_domain(sender_domain, trusted_domain.lower()):
                findings.append(
                    f"Lookalike/spoofed domain detected: '{sender_domain}' "
                    f"resembles trusted domain '{trusted_domain}' but does not match exactly"
                )
                score += 2
            else:
                findings.append(
                    f"Sender-domain mismatch: '{sender_domain}' does not match "
                    f"trusted domain '{trusted_domain}'"
                )
                score += 2

    return findings, score


def verdict_from_score(score):
    if score == 0:
        return "SAFE", "Close"
    elif score <= 2:
        return "SUSPICIOUS", "Warn User"
    else:
        return "MALICIOUS", "Block & Escalate"


def print_report(findings, score):
    verdict, action = verdict_from_score(score)
    print("\n" + "=" * 55)
    print("  PHISHING TRIAGE REPORT")
    print("=" * 55)
    if findings:
        print(f"\nRed flags found ({len(findings)}):")
        for i, f in enumerate(findings, 1):
            print(f"  {i}. {f}")
    else:
        print("\nNo red flags found.")
    print(f"\nRisk score: {score}")
    print(f"Verdict:    {verdict}")
    print(f"Action:     {action}")
    print("=" * 55)


def get_multiline_input(prompt):
    print(prompt)
    print("(Paste the message, then type END on its own line to finish)")
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def run_demo():
    print("=" * 55)
    print("  PHISHING TRIAGE ANALYZER")
    print("  DecodeLabs - Cyber Security Training Kit - Project 3")
    print("=" * 55)

    while True:
        print("\nChoose an option:")
        print("1. Analyze a message (paste text)")
        print("2. Analyze a sample file from /samples")
        print("3. Exit")
        choice = input("Enter choice (1-3): ").strip()

        if choice == "1":
            text = get_multiline_input("\nPaste the email/text message:")
            trusted = input(
                "Trusted company domain to compare against (e.g. northwindcorp.com), "
                "or press Enter to skip: "
            ).strip()
            findings, score = analyze(text, trusted_domain=trusted or None)
            print_report(findings, score)

        elif choice == "2":
            filename = input("Enter sample filename (e.g. sample_1_bec_wire_transfer.txt): ").strip()
            path = f"samples/{filename}"
            try:
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()
                findings, score = analyze(text, trusted_domain="northwindcorp.com")
                print_report(findings, score)
            except FileNotFoundError:
                print(f"File not found: {path}")

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    run_demo()
