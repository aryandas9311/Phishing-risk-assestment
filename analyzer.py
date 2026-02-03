def is_suspicious(url):
    score = 0
    reasons = []

    if len(url) > 75:
        score += 20
        reasons.append("URL length is unusually long")

    if "@" in url:
        score += 30
        reasons.append("URL contains '@' symbol")

    if url.startswith("http://"):
        score += 15
        reasons.append("Unsecured HTTP protocol used")

    if any(char.isdigit() for char in url):
        score += 15
        reasons.append("URL contains numeric characters")

    suspicious_words = ["login", "verify", "update", "secure", "bank"]
    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword detected: {word}")

    return score, reasons
