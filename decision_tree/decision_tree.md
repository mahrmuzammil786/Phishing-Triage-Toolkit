# Phishing Triage Decision Tree

Every triage event must end in one of three definitive actions. This tree turns
the Red Flag Checklist scoring into a clear next step.

```
                        Incoming Suspicious Message
                                    |
                    Run it against the Red Flag Checklist
                                    |
              -----------------------------------------------
              |                    |                        |
           0 flags            1-2 flags            3+ flags, OR any
                                                  credential/payment
                                                  request, OR malicious
                                                  attachment/link
              |                    |                        |
            SAFE              SUSPICIOUS               MALICIOUS
              |                    |                        |
            CLOSE             WARN USER             BLOCK & ESCALATE
```

## The Golden Rule: Pause, Verify, Report

Before taking any action on a flagged message, apply this three-step rule:

1. **PAUSE** - Recognize the cognitive trigger (urgency, fear, authority) and
   stop interacting with the message. Apply the Five-Minute Rule: wait before
   clicking, replying, or calling any number in the message.
2. **VERIFY** - Confirm the request through a **secondary, out-of-band channel**.
   If the request came by email, verify by phone using a number from the
   official company directory - never a number provided in the message itself.
3. **REPORT** - Use the internal reporting tool/plugin. Do not simply delete the
   message - reporting lets the security team purge the same threat from other
   inboxes.

## Action Definitions

| Verdict | Action | What it means |
|---|---|---|
| **Safe** | **Close** | No red flags found. No further action needed. |
| **Suspicious** | **Warn User** | Some red flags present but not conclusive. Notify the recipient/team to avoid interacting with it, and monitor for similar messages. |
| **Malicious** | **Block & Escalate** | Clear evidence of phishing (credential harvesting, payment request, malicious attachment/link, spoofed domain). Block the sender/domain and escalate to the security team immediately. |

## Escalation Checklist (for Malicious verdicts)

- [ ] Do not click any links or open any attachments
- [ ] Do not reply to the sender
- [ ] Report via internal security tooling
- [ ] Block sender domain at the mail gateway
- [ ] Alert anyone else who may have received the same message
- [ ] If credentials or payment info were already entered, escalate for immediate
      password reset / bank notification
