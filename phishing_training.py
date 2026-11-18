#!/usr/bin/env python3
"""
Task 2: Phishing Awareness Training
-----------------------------------
An interactive, terminal-based training module (standard library only).

Covers:
  1. What phishing is
  2. How to recognize phishing emails
  3. How to recognize fake websites (+ a hands-on URL red-flag checker)
  4. Social engineering tactics
  5. Real-world examples
  6. Best practices and tips
  7. Interactive quiz with scoring and explanations

Run:  python3 phishing_training.py
"""

import random
import re
import shutil
import sys
from urllib.parse import urlparse

WIDTH = min(shutil.get_terminal_size((80, 20)).columns, 80)


# --------------------------------------------------------------------------
# Display helpers
# --------------------------------------------------------------------------
def line(char="="):
    print(char * WIDTH)


def title(text):
    print()
    line()
    print(text.center(WIDTH))
    line()


def wrap(text, indent=2):
    import textwrap
    for para in text.strip().split("\n"):
        print(textwrap.fill(para, WIDTH, initial_indent=" " * indent,
                            subsequent_indent=" " * (indent + 2)) if para.strip() else "")


def pause():
    ask("\n  [Press Enter to continue] ")


def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        sys.exit("\nInput closed. Goodbye!")


# --------------------------------------------------------------------------
# Lesson content
# --------------------------------------------------------------------------
def lesson_intro():
    title("1. WHAT IS PHISHING?")
    wrap("""
Phishing is a cyberattack where criminals pretend to be a trusted person or organisation (a bank, your employer, a delivery company) to trick you into revealing passwords, financial details or into installing malware.

Common forms:
- Email phishing: mass messages that imitate well-known brands.
- Spear phishing: targeted messages that use details about you or your job.
- Whaling: spear phishing aimed at executives.
- Smishing: phishing by SMS.
- Vishing: phishing by phone call or voicemail.
- Quishing: malicious QR codes that lead to fake login pages.

Why it matters: most data breaches involve a human element. One click can expose an entire organisation.
""")
    pause()


def lesson_emails():
    title("2. RECOGNIZING PHISHING EMAILS")
    wrap("""
Check these seven red flags before you click or reply:

1. SENDER MISMATCH - The display name says "PayPal" but the address is support@paypa1-security.com. Look at the real domain after the @.
2. URGENCY OR THREATS - "Your account will be closed in 24 hours!" Pressure is designed to stop you thinking.
3. GENERIC GREETING - "Dear customer" from a company that should know your name (note: spear phishing may use your real name).
4. SUSPICIOUS LINKS - Hover over a link (do not click) and compare the real destination with the text shown.
5. UNEXPECTED ATTACHMENTS - Invoices, "voicemails" or ZIP/.html/.exe/macro-enabled Office files you did not ask for.
6. REQUESTS FOR SENSITIVE DATA - Legitimate companies do not ask for passwords, PINs or full card numbers by email.
7. POOR OR ODD WRITING - Spelling errors, strange formatting or an unusual tone (AI-written phishing can be flawless, so don't rely on this alone).
""")
    print("\n  Example of a phishing email:\n")
    for l in [
        "  From:    PayPal Support <security@paypa1-alerts.com>",
        "  Subject: URGENT: Unusual activity - verify within 24 hours",
        "",
        "  Dear Customer,",
        "  We detected a login from a new device. Your account will be",
        "  suspended unless you confirm your identity immediately:",
        "  >> http://paypal.com.verify-account-login.net/secure <<",
    ]:
        print(l)
    wrap("""
What's wrong? (a) 'paypa1' uses the digit 1 instead of the letter l. (b) The real domain of the link is verify-account-login.net, NOT paypal.com. (c) Artificial urgency. (d) Generic greeting.
""")
    pause()


def lesson_websites():
    title("3. RECOGNIZING FAKE WEBSITES")
    wrap("""
Attackers clone login pages so that they look identical to the real thing. The page may look perfect - the URL is what gives it away.

- LOOKALIKE DOMAINS: amaz0n.com, micros0ft-support.com, faceb00k-login.net.
- BRAND IN THE WRONG PLACE: In login.paypal.com.evil.net the real domain is evil.net. Read the domain from right to left, up to the first single slash.
- HOMOGRAPH TRICKS: Characters from other alphabets that look the same (the 'a' in "apple.com" can be Cyrillic). Browsers show these as xn-- (punycode).
- PADLOCK != SAFE: HTTPS only means the connection is encrypted. Phishing sites commonly use HTTPS too.
- ODD ELEMENTS: Pop-ups asking for credentials, missing privacy policy, broken images, forms that ask for far more data than needed.
- HOW YOU ARRIVED: Links from email, SMS, QR codes and ads are riskier than typing the address or using your own bookmark.
""")
    pause()


def url_checker():
    title("HANDS-ON: URL RED-FLAG CHECKER")
    wrap("Type a URL to see which warning signs it triggers. Leave blank to go back.\nTry: http://paypal.com.verify-login.net/secure")
    while True:
        url = ask("\n  URL> ")
        if not url:
            return
        if "://" not in url:
            url = "http://" + url
        flags = analyze_url(url)
        print()
        if flags:
            print(f"  {len(flags)} warning sign(s) found:")
            for f in flags:
                print("   [!]", f)
        else:
            print("  No obvious red flags - but still verify the source independently.")


def analyze_url(url):
    """Return a list of simple heuristic warnings about a URL (educational)."""
    flags = []
    p = urlparse(url)
    host = (p.hostname or "").lower()
    parts = host.split(".")
    brands = ["paypal", "amazon", "microsoft", "google", "apple", "facebook",
              "netflix", "bank", "dhl", "fedex"]

    if p.scheme != "https":
        flags.append("Not using HTTPS (note: HTTPS alone does not prove a site is safe).")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        flags.append("Uses a raw IP address instead of a domain name.")
    if "@" in p.netloc:
        flags.append("Contains '@' - everything before it is ignored by the browser.")
    if "xn--" in host:
        flags.append("Punycode (xn--) domain: may hide lookalike foreign characters.")
    if len(parts) > 3 and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        flags.append(f"Many subdomains ({len(parts)} labels) - check the REAL domain at the end.")
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else host
    for b in brands:
        if b in host and not registered.startswith(b + "."):
            flags.append(f"Mentions '{b}' but the real domain is '{registered}'.")
            break
    if re.search(r"[a-z][013]+(?:[a-z]|-|$)", registered.split(".")[0]):
        flags.append("Digits mixed into letters (e.g. paypa1, micros0ft) - possible lookalike.")
    if registered.split(".")[0].count("-") >= 2:
        flags.append("Many hyphens in the domain name - common in throwaway phishing domains.")
    if parts and parts[-1] in {"zip", "xyz", "top", "click", "support", "live", "icu"}:
        flags.append(f"Top-level domain '.{parts[-1]}' is frequently abused (not proof by itself).")
    if len(url) > 100:
        flags.append("Very long URL - may hide the real destination.")
    if re.search(r"(?<![a-z])(login|verify|secure|update|confirm|account)(?![a-z])", p.path.lower() + " " + host.replace(".", " ").replace("-", " ")):
        flags.append("Urgent/credential words in the address (login, verify, secure...).")
    return flags


def lesson_social_engineering():
    title("4. SOCIAL ENGINEERING TACTICS")
    wrap("""
Social engineering manipulates human psychology rather than technology. Attackers exploit natural instincts:

- AUTHORITY: Pretending to be the CEO, IT support, police or tax office. ("This is the CEO - wire the payment now.")
- URGENCY / SCARCITY: "Act within 1 hour or lose access."
- FEAR: "Your account was hacked," "A warrant has been issued."
- GREED / CURIOSITY: Prizes, refunds, "see who viewed your profile," leaked salary lists.
- HELPFULNESS / TRUST: Asking for a "small favour" or posing as a colleague who is stuck.
- RECIPROCITY: Offering help first, then asking for a credential in return.
- FAMILIARITY: Using details scraped from LinkedIn or social media to sound credible (pretexting).

Related physical and phone tactics:
- Pretexting: inventing a believable scenario (e.g. "I'm from the helpdesk").
- Baiting: infected USB drives left in a car park.
- Tailgating: following an employee through a secure door.
- MFA fatigue: spamming approval prompts until the victim taps "Approve".

Defence: slow down, verify through a second trusted channel (call the known number, not the one in the message), and remember that real organisations rarely demand secrets under time pressure.
""")
    pause()


def lesson_examples():
    title("5. REAL-WORLD EXAMPLES")
    wrap("""
(a) RSA Security, 2011 - Employees received a spear-phishing email titled "2011 Recruitment plan" with an Excel attachment containing an exploit. It gave attackers a foothold that led to the theft of data related to RSA's SecurID products.

(b) Target, 2013 - Attackers reportedly first compromised a third-party HVAC vendor via phishing, then used its credentials to reach Target's network, eventually exposing roughly 40 million payment cards. Lesson: your supply chain is part of your attack surface.

(c) Google and Facebook invoice scam, 2013-2015 - A fraudster impersonated a hardware supplier and sent fake invoices, tricking both companies into paying over $100 million combined (most was later recovered). Lesson: verify changes to payment details and invoices out-of-band.

(d) Twitter, 2020 - Attackers phoned employees pretending to be internal IT support (vishing) and obtained credentials, taking over high-profile accounts to promote a Bitcoin scam. Lesson: voice calls can be phishing too.

(e) Everyday scams - "Your parcel couldn't be delivered" SMS messages, fake bank fraud alerts, and QR-code parking-meter stickers that lead to fake payment pages.
""")
    pause()


def lesson_best_practices():
    title("6. BEST PRACTICES & TIPS")
    wrap("""
BEFORE YOU CLICK
- Pause. Ask: Was I expecting this? Does the sender really need this from me?
- Hover over links; type known addresses yourself or use bookmarks.
- Never open unexpected attachments; verify with the sender by another channel.

PROTECT YOUR ACCOUNTS
- Use a password manager: it won't autofill on a fake domain - a great phishing detector.
- Turn on multi-factor authentication (MFA). Prefer passkeys or hardware security keys, which resist phishing better than SMS codes.
- Use unique passwords for every account.
- Never share one-time codes with anyone - not even "support".

KEEP SYSTEMS SAFE
- Install updates for your OS, browser and email client promptly.
- Use spam filtering and reputable endpoint protection.
- Back up important data offline.

IF YOU SUSPECT PHISHING
- Don't click, reply or forward to colleagues. Use your organisation's "Report phishing" button or contact IT/security.
- If you already clicked or entered a password: change it immediately, enable MFA, tell IT, and monitor accounts for unusual activity.
- Report to your national authority (e.g. reportphishing@apwg.org, or your local cybercrime/CERT service).
""")
    pause()


# --------------------------------------------------------------------------
# Quiz
# --------------------------------------------------------------------------
QUIZ = [
    {
        "q": "You get an email from 'security@paypa1-alerts.com' saying your account will be locked in 24 hours. What is the BEST action?",
        "options": ["Click the link quickly to avoid being locked out",
                    "Reply asking if it's real",
                    "Ignore the link, go to PayPal by typing the address yourself, and report the email",
                    "Forward it to coworkers as a warning"],
        "answer": 3,
        "why": "The domain uses a '1' instead of 'l' and relies on urgency. Go to the real site independently and report the message - don't forward live phishing to others.",
    },
    {
        "q": "Which URL actually belongs to PayPal?",
        "options": ["https://paypal.com.secure-login.net/", "https://www.paypal.com/signin",
                    "https://paypal-support.example-help.com/", "http://192.168.4.7/paypal"],
        "answer": 2,
        "why": "Read the domain right-to-left before the first '/'. Only 'www.paypal.com' ends in paypal.com; in the others the real domain is something else.",
    },
    {
        "q": "A site shows a padlock (HTTPS). Does that mean it's safe?",
        "options": ["Yes, the padlock guarantees it's legitimate",
                    "No, it only means the connection is encrypted - phishing sites can use HTTPS too"],
        "answer": 2,
        "why": "HTTPS proves encryption, not trustworthiness. Always check the domain.",
    },
    {
        "q": "Your 'CEO' emails asking you to urgently buy gift cards and keep it confidential. Which social engineering tactic is mainly used?",
        "options": ["Authority + urgency", "Reciprocity", "Baiting", "Tailgating"],
        "answer": 1,
        "why": "Impersonating a senior person (authority) and demanding quick, secret action (urgency) is classic business email compromise.",
    },
    {
        "q": "What is 'spear phishing'?",
        "options": ["Mass emails sent to millions of random people",
                    "A targeted phishing message tailored to a specific person or organisation",
                    "Phishing by phone call", "A virus that spreads through USB drives"],
        "answer": 2,
        "why": "Spear phishing uses personal or company details to look credible. Phone-based phishing is called vishing.",
    },
    {
        "q": "Which MFA method is generally MOST resistant to phishing?",
        "options": ["SMS codes", "Hardware security key / passkey", "Security questions", "Email codes"],
        "answer": 2,
        "why": "Passkeys and security keys are bound to the real website, so they won't work on a lookalike domain.",
    },
    {
        "q": "You clicked a suspicious link and typed your password. What should you do FIRST?",
        "options": ["Nothing - it was probably fine", "Change the password immediately, enable MFA and tell IT/security",
                    "Delete the email and hope for the best", "Wait a week to see if anything happens"],
        "answer": 2,
        "why": "Act fast: change the password (and anywhere it was reused), enable MFA, and report the incident so others can be protected.",
    },
    {
        "q": "You get a phone call from 'IT support' asking you to read out the verification code just sent to your phone. You should:",
        "options": ["Read it out - they're IT", "Refuse, hang up, and call IT using the official number",
                    "Ask them to email you instead", "Give only the first three digits"],
        "answer": 2,
        "why": "Verification codes are secrets. Real support will never ask for them - this is vishing, often used to bypass MFA.",
    },
]


def run_quiz():
    title("7. INTERACTIVE QUIZ")
    questions = QUIZ[:]
    random.shuffle(questions)
    score = 0
    for n, item in enumerate(questions, 1):
        print(f"\n  Question {n}/{len(questions)}")
        wrap(item["q"])
        opts = item["options"][:]
        correct_text = opts[item["answer"] - 1]
        random.shuffle(opts)
        for i, o in enumerate(opts, 1):
            wrap(f"{i}) {o}", indent=4)
        while True:
            choice = ask("\n  Your answer (number): ")
            if choice.isdigit() and 1 <= int(choice) <= len(opts):
                break
            print("  Please enter a valid option number.")
        if opts[int(choice) - 1] == correct_text:
            score += 1
            print("\n  [OK] Correct!")
        else:
            print(f"\n  [X] Not quite. Correct answer: {correct_text}")
        wrap("Why: " + item["why"], indent=4)

    pct = score / len(questions) * 100
    title("QUIZ RESULTS")
    print(f"  Score: {score}/{len(questions)} ({pct:.0f}%)")
    if pct >= 85:
        print("  Excellent! You're a strong line of defence against phishing.")
    elif pct >= 60:
        print("  Good job - review the sections you missed and try again.")
    else:
        print("  Keep learning! Revisit the lessons (options 1-6) and retake the quiz.")
    pause()
    return score, len(questions)


# --------------------------------------------------------------------------
# Main menu
# --------------------------------------------------------------------------
MENU = [
    ("What is phishing?", lesson_intro),
    ("Recognizing phishing emails", lesson_emails),
    ("Recognizing fake websites", lesson_websites),
    ("Hands-on URL red-flag checker", url_checker),
    ("Social engineering tactics", lesson_social_engineering),
    ("Real-world examples", lesson_examples),
    ("Best practices & tips", lesson_best_practices),
    ("Take the quiz", run_quiz),
]


def main():
    title("PHISHING AWARENESS TRAINING")
    wrap("Welcome! This module teaches you to spot and avoid phishing attacks. Work through the lessons in order, then test yourself with the quiz.")
    best = None
    while True:
        print()
        line("-")
        for i, (name, _) in enumerate(MENU, 1):
            print(f"  {i}. {name}")
        print("  0. Exit")
        if best:
            print(f"\n  Best quiz score so far: {best[0]}/{best[1]}")
        choice = ask("\n  Choose an option: ")
        if choice == "0":
            print("\n  Stay vigilant: when in doubt, don't click - verify!\n")
            break
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            result = MENU[int(choice) - 1][1]()
            if result and (best is None or result[0] > best[0]):
                best = result
        else:
            print("  Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Training ended. Stay safe online!")