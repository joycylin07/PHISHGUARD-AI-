import re

FEATURE_NAMES = [
    "Have_IP", "Have_At", "URL_Length", "URL_Depth", "Redirection",
    "https_Domain", "TinyURL", "Prefix/Suffix", "DNS_Record", "Web_Traffic",
    "Domain_Age", "Domain_End", "iFrame", "Mouse_Over", "Right_Click",
    "Web_Forwards", "Domain_Length", "Dot_Count", "Hyphen_Count",
    "Digit_Count", "Has_Digits", "Subdomain_Count"
]

def extract_domain_features(domain_str: str) -> dict:
    domain_str = str(domain_str).lower()
    return {
        "Domain_Length": len(domain_str),
        "Dot_Count": domain_str.count("."),
        "Hyphen_Count": domain_str.count("-"),
        "Digit_Count": sum(c.isdigit() for c in domain_str),
        "Has_Digits": 1 if any(c.isdigit() for c in domain_str) else 0,
        "Subdomain_Count": max(0, len(domain_str.split(".")) - 2)
    }

if __name__ == "__main__":
    test_domain = "paypal-account-verify.xyz"
    extracted = extract_domain_features(test_domain)
    print("\n--- Feature Extraction Test ---")
    for k, v in extracted.items():
        print(f"  {k}: {v}")