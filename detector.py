import re
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

try:
    import joblib
except ModuleNotFoundError:  # pragma: no cover - handled gracefully at runtime
    joblib = None

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "spam_classifier.joblib"

SUSPICIOUS_PHRASES = [
    "verify your account",
    "urgent action",
    "click here",
    "password expired",
    "account suspended",
    "claim your prize",
    "bank details",
    "login immediately",
    "won a prize",
    "confirm your password",
    "unusual activity",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
]


def extract_urls(text):
    """Extract URLs without opening or visiting them."""
    if text is None:
        return []
    return URL_PATTERN.findall(str(text))


def inspect_email(subject, body, sender=""):
    """Analyze email text using simple security rules."""
    subject_text = "" if subject is None else str(subject)
    body_text = "" if body is None else str(body)
    sender_text = "" if sender is None else str(sender)

    text = f"{subject_text}\n{body_text}".lower()
    indicators = []
    risk_points = 0

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text:
            indicators.append(f"Suspicious phrase: {phrase}")
            risk_points += 1

    urls = extract_urls(text)

    if urls:
        indicators.append(f"Contains {len(urls)} URL(s)")

    for url in urls:
        normalized_url = url.lower()
        if any(shortener in normalized_url for shortener in SHORTENERS):
            indicators.append("URL shortener detected")
            risk_points += 2

        # A basic heuristic, not proof of a malicious URL
        if "@" in normalized_url:
            indicators.append("URL contains an @ character")
            risk_points += 2

    if sender_text:
        sender_address = parseaddr(sender_text)[1]
        if not sender_address or not re.search(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender_address):
            indicators.append("Sender address has an unusual format")

    if risk_points >= 3:
        rule_label = "HIGH RISK"
    elif risk_points >= 1:
        rule_label = "SUSPICIOUS"
    else:
        rule_label = "NO RULE-BASED WARNING"

    return {
        "rule_label": rule_label,
        "risk_points": risk_points,
        "indicators": indicators,
        "urls": urls,
    }


def predict_spam(subject, body):
    """Use the trained model if available."""
    subject_text = "" if subject is None else str(subject)
    body_text = "" if body is None else str(body)
    text = " ".join(part for part in (subject_text, body_text) if part).strip()

    if not MODEL_PATH.exists() or not text or joblib is None:
        return {"label": "unknown", "confidence": None}

    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        return {"label": "unknown", "confidence": None}

    prediction = model.predict([text])[0]

    confidence = None
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba([text])[0]
        confidence = float(max(probabilities))

    return {
        "label": str(prediction).lower(),
        "confidence": confidence,
    }


def read_eml_file(file_bytes):
    """Extract basic headers and text from an uploaded .eml file."""
    if file_bytes is None:
        raise ValueError("Email content is required.")

    message = BytesParser(policy=policy.default).parsebytes(file_bytes)

    subject = str(message.get("subject", ""))
    sender = str(message.get("from", ""))

    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() != "text":
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    payload = part.get_payload()
                if payload is None:
                    continue
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text = payload.decode(charset, errors="replace")
                    except LookupError:
                        text = payload.decode("utf-8", errors="replace")
                else:
                    text = str(payload)
                if text.strip():
                    body_parts.append(text)
            except Exception:
                pass
    elif message.get_content_maintype() == "text":
        try:
            payload = message.get_payload(decode=True)
            if payload is None:
                payload = message.get_payload()
            if isinstance(payload, bytes):
                charset = message.get_content_charset() or "utf-8"
                try:
                    payload = payload.decode(charset, errors="replace")
                except LookupError:
                    payload = payload.decode("utf-8", errors="replace")
            if payload is not None and str(payload).strip():
                body_parts.append(str(payload))
        except Exception:
            pass

    body = "\n".join(body_parts).strip()

    return subject, sender, body