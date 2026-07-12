# Phishing Red Flag Checklist

A non-expert triage checklist for identifying suspicious emails, texts, and calls.
Use this before clicking any link, replying, or downloading an attachment.

## 1. Sender Checks

- [ ] **Sender-domain mismatch** - Does the "From" name look trustworthy, but the
      actual email address (after the `@`) belongs to a free or unrelated domain
      (e.g. gmail.com) or a domain that's almost-but-not-quite the real one?
- [ ] **Lookalike domain** - Check for:
  - *Typosquatting*: a common misspelling (`amaz0n.com`)
  - *Homoglyph swap*: a letter replaced with a similar-looking character
  - *Combosquatting*: extra words added to a real brand (`yourcompany-secure-login.com`)
  - *Subdomain trap*: the real company name buried as a subdomain of an
    unrelated root domain — read the URL **right to left** to find the true root
    (e.g. `www.company.tech.login-update.com` → root is `login-update.com`, not `company.tech`)
- [ ] **Fake forwarded chain** - Does the email contain a "FW:" subject with pasted
      headers or timestamps from a conversation you were never part of?

## 2. Content & Tone Checks

- [ ] **Urgency pressure** - Deadlines measured in minutes or hours ("act within
      30 minutes," "expires today")
- [ ] **Authority pressure** - Claims to be from the CEO, IT, HR, or law
      enforcement, demanding unquestioned compliance
- [ ] **Secrecy or bypass requests** - Asked to keep it confidential, skip normal
      procedure, or not verify with anyone else
- [ ] **Fear or greed hooks** - Threats of legal action / account loss, or promises
      of unexpected rewards or refunds
- [ ] **Requests for sensitive info** - Passwords, MFA codes, bank details, or
      payment changes requested over email/text (legitimate teams rarely ask this way)

## 3. Technical Checks

- [ ] **Suspicious links** - Shortened URLs (bit.ly, tinyurl), IP-address links, or
      a link's visible text not matching where it actually points
- [ ] **Dangerous attachments** - Uncommon file extensions: `.exe`, `.scr`, `.js`,
      `.iso`, `.html` disguised as invoices or documents
- [ ] **Unusual sign-in / activity alerts** - Alarmist alerts that push you straight
      to a login page instead of telling you to check manually via the official app/site
- [ ] **MFA fatigue** - Multiple unexpected authenticator push notifications you
      didn't trigger
- [ ] **QR codes (Quishing)** - Unsolicited QR codes asking you to scan with your
      phone to "secure" or "verify" an account
- [ ] **Callback scams (TOAD)** - An email/text with no malicious link, only a
      phone number urging you to call about a fake charge or subscription

## 4. Live Interaction Checks

- [ ] **Deepfake voice/video** - An urgent voice note or video call from an
      executive requesting a payment or vendor change mid-conversation
- [ ] **Caller ID spoofing (Vishing)** - A call claiming to be IT support or a
      government agency, pressuring immediate action over the phone

---

## Scoring Guide

| Flags found | Risk Level |
|---|---|
| 0 flags | Safe |
| 1-2 flags | Suspicious |
| 3+ flags, or any technical/credential-harvesting flag | Malicious |

See `decision_tree/decision_tree.md` for what to do at each risk level.
