# PhishBlock

A browser extension that warns you when a web page looks like a phishing attempt, with a focus on Microsoft Office 365 and BIUST portal impersonation.

I built PhishBlock after BIUST's Directorate of ICT issued a cybersecurity alert about a rise in phishing emails impersonating Office 365 services. The alert listed the warning signs: urgent requests, unfamiliar sender domains, links to non-Microsoft domains, and requests to re-enter credentials. PhishBlock checks for the same signs on the page itself, at the moment a user is about to enter their details.

## How it works

PhishBlock is a Manifest V3 extension. It runs a content script on every page and a background service worker, and combines three kinds of checks into a risk score.

**Lexical checks (domain)**
- Trusted domains are allowed: `microsoftonline.com`, `office.com`, `microsoft.com` and `biust.ac.bw`, including their subdomains.
- Domains containing brand keywords such as "microsoft", "office365", "outlook" or "biust" that are not on the trusted list are flagged.
- Domains that are one or two characters away from a protected brand name (for example, typosquatting) are flagged, using Levenshtein edit distance.

**Visual checks (page content)**
- Brand cues in placeholders, labels, buttons, headings and image text or sources.

**Behavioural checks**
- Urgency phrases in visible text, such as "verify immediately" and "action required".
- Password forms that submit to an untrusted, external, invalid or insecure (HTTP) destination.
- The page is rescanned when content changes, so pages that load their login form late are still caught.

### Scoring

| Signal | Points |
| --- | --- |
| Lookalike domain | +80 |
| Brand keyword in an untrusted domain | +50 |
| Password form submitting to an untrusted destination | +70 |
| Brand cues on the page | +25 |
| Urgency phrase | +15 each |

| Score | Result |
| --- | --- |
| 60 or more | **Malicious**: full-screen warning overlay |
| Above 15 | **Suspicious**: warning badge |
| Otherwise | **Safe** |

The toolbar badge shows **HIGH** (red) for malicious pages and **WARN** (amber) for suspicious ones. The popup shows the status for the current tab.

On a malicious page, the overlay blocks the page and lists why it was flagged. The user can choose **Go Back to Safety**, or bypass it after a confirmation prompt (the bypass lasts for that tab's session).

## Installation

PhishBlock is not on the Chrome Web Store yet. To try it:

1. Clone or download this repository.
2. Open `chrome://extensions` in Chrome (or `edge://extensions` in Edge).
3. Turn on **Developer mode**.
4. Click **Load unpacked** and select the PhishBlock folder.
5. Pin the extension to see its status badge.

## Project structure

| File | Purpose |
| --- | --- |
| `manifest.json` | Extension configuration (Manifest V3, `activeTab` and `storage` permissions) |
| `background.js` | Service worker: domain checks, tab threat status and badge |
| `content.js` | Page scanner: scoring, rescanning and the warning overlay |
| `popup.html` / `popup.js` | Toolbar popup showing the current tab's status |
| `styles.css` | Styles for the extension |

## Limitations

PhishBlock is a personal learning project, not a replacement for your organisation's email security or for reporting phishing to ICT.

- It uses rules and a fixed list of trusted domains, so it can produce false positives (for example, an unrelated domain that contains "outlook") and can miss phishing pages that avoid these signals.
- It analyses the page, not the email that delivered the link.
- Pages with non-HTTP addresses are not checked.

## If you receive a phishing email

Follow your ICT directorate's guidance: do not click links or attachments, do not enter credentials, report it to ICT, and delete the email. BIUST ICT will never ask for your password or MFA approval by email.

## Author

Katlego Caangu Munisola, [katlego.tech](https://katlego.tech/)
