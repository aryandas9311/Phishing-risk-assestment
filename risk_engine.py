from analyzer import is_suspicious
from datetime import datetime

def classify_risk(score):
    if score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"

def log_alert(url, score, risk, reasons):
    timestamp = datetime.now().isoformat()
    with open("alerts.log", "a") as f:
        f.write(
            f"{timestamp} | {url} | {score} | {risk} | {', '.join(reasons)}\n"
        )

def write_risk_register(risk):
    impact = "Credential Theft"
    likelihood = (
        "High" if risk == "HIGH"
        else "Medium" if risk == "MEDIUM"
        else "Low"
    )
    control = "User Awareness Training, Email Filtering"

    with open("risk_register.csv", "a") as f:
        f.write(f"Phishing,{impact},{likelihood},{risk},{control}\n")

# -------- MAIN EXECUTION --------

url = input("Enter a URL: ")

score, reasons = is_suspicious(url)
risk = classify_risk(score)

print("\nRisk score:", score)
print("Risk level:", risk)
print("Reasons:")
for r in reasons:
    print("-", r)

log_alert(url, score, risk, reasons)
write_risk_register(risk)
