"""
Phishing Triage Analyzer - Web App
DecodeLabs - Cyber Security Industrial Training Kit - Project 3

Flask web wrapper around analyzer.py's rule-based red-flag scanner.
"""

from flask import Flask, render_template, request
from analyzer import analyze, verdict_from_score

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    trusted_domain = ""
    findings = None
    score = None
    verdict = None
    action = None

    if request.method == "POST":
        message = request.form.get("message", "")
        trusted_domain = request.form.get("trusted_domain", "").strip()

        if message.strip():
            findings, score = analyze(message, trusted_domain=trusted_domain or None)
            verdict, action = verdict_from_score(score)

    return render_template(
        "index.html",
        message=message,
        trusted_domain=trusted_domain,
        findings=findings,
        score=score,
        verdict=verdict,
        action=action,
    )


if __name__ == "__main__":
    app.run(debug=True)
