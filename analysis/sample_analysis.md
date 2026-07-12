# Sample Message Analysis

Each sample from `/samples` analyzed against `red_flag_checklist.md`, with a
verdict and action from `decision_tree.md`.

---

## Sample 1 - BEC Wire Transfer ("Lost Wallet" style)
File: `sample_1_bec_wire_transfer.txt`

**Red flags found:**
1. **Sender-domain mismatch** - Sender is `northwind-corp.co`, but the company's
   real domain is `northwindcorp.com`. Note the added hyphen and different TLD (`.co` vs `.com`).
2. **Authority pressure** - Impersonates the CEO directly.
3. **Urgency pressure** - "before close of business today," time-sensitive framing.
4. **Secrecy/bypass request** - "Strictly confidential," explicitly asks not to
   discuss with the team.
5. **Request for sensitive action** - Direct wire transfer to an unfamiliar account,
   with instructions not to call and verify by phone.

**Why it's dangerous:** This mirrors the Business Email Compromise (BEC) pattern
where an attacker spoofs an executive's identity to bypass normal financial
controls. The explicit instruction to avoid phone verification is designed to
prevent the one thing that would expose the scam.

**Verdict: Malicious → Block & Escalate**

---

## Sample 2 - Fake IT Password Reset
File: `sample_2_it_password_reset.txt`

**Red flags found:**
1. **Lookalike/subdomain trap domain** - `northwindcorp.tech.login-update.com`.
   Reading right to left, the true root domain is `login-update.com` - the real
   company name is just a fake subdomain prefix.
2. **Fake forwarded chain** - Subject line starts with "FW:" despite being a
   fresh, unsolicited message.
3. **Urgency pressure** - "24 hrs" deadline, plus a fake 30-minute countdown on
   the link itself.
4. **Fear-based consequence** - Threatens "immediate account suspension."
5. **Credential harvesting link** - Directs to a fake login/reset page.

**Why it's dangerous:** This is a classic credential-harvesting attack. The
layered urgency (24 hours, then 30 minutes) is designed to prevent the reader
from pausing to check the URL carefully.

**Verdict: Malicious → Block & Escalate**

---

## Sample 3 - Legitimate Project Update
File: `sample_3_legit_project_update.txt`

**Red flags found:** None.

- Sender domain (`northwindcorp.com`) matches the company domain exactly.
- No urgency language - explicitly states "No immediate action is required."
- No requests for credentials, payment, or sensitive data.
- Attachment is a plain `.pdf`, a normal business document type.
- Tone is calm and consistent with routine internal communication.

**Why it's safe:** Matches normal, low-pressure internal communication with a
verified sender domain and no technical or psychological red flags.

**Verdict: Safe → Close**

---

## Sample 4 - Fake Subscription/Invoice
File: `sample_4_fake_invoice.txt`

**Red flags found:**
1. **Sender-domain mismatch** - Claims to be a billing team but sends from an
   unrelated domain (`cloudsuite-payments.net`) rather than a recognized vendor domain.
2. **Urgency pressure** - "24 hours" before service suspension.
3. **Shortened/obscured link** - Uses a `bit.ly` shortened URL, hiding the true destination.
4. **Dangerous attachment** - `.iso` file extension disguised as an invoice - not
   a normal document format.
5. **Callback scam element (TOAD)** - Also provides a phone number as an
   alternate pressure path.

**Why it's dangerous:** Combines multiple attack vectors (malicious link +
malicious attachment + callback scam) targeting whichever channel the victim
is more likely to trust.

**Verdict: Malicious → Block & Escalate**

---

## Sample 5 - Smishing Text
File: `sample_5_smishing_text.txt`

**Red flags found:**
1. **Unknown/unverified sender** - No legitimate carrier identification.
2. **Urgency pressure** - "12 hours" deadline framed around a package being lost.
3. **Suspicious link domain** - `fedex-redeliver.info` is not an official
   carrier domain (combosquatting: real brand name + unrelated words + `.info` TLD).
4. **Channel exploitation (Smishing)** - Uses SMS specifically because mobile
   screens make it harder to inspect a full URL before tapping.

**Why it's dangerous:** Classic mass-phishing smishing pattern impersonating a
trusted delivery brand to drive a fast, low-scrutiny click on a mobile device.

**Verdict: Malicious → Block & Escalate**

---

## Summary Table

| Sample | Verdict | Action |
|---|---|---|
| 1 - BEC Wire Transfer | Malicious | Block & Escalate |
| 2 - Fake IT Password Reset | Malicious | Block & Escalate |
| 3 - Legit Project Update | Safe | Close |
| 4 - Fake Invoice | Malicious | Block & Escalate |
| 5 - Smishing Text | Malicious | Block & Escalate |
