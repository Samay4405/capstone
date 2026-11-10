"""Verifies all sample emails against the pipeline."""

import os
from fastapi.testclient import TestClient
from active_verification.api.server import app

client = TestClient(app)
base = "sample_emails"

print("=" * 115)
print(f"{'Category Folder':<30} | {'Sample File':<42} | {'Decision':<10} | {'Score':<6} | {'Active Verif'}")
print("=" * 115)

for root, dirs, files in os.walk(base):
    for f in sorted(files):
        if not f.endswith(".eml"):
            continue
        path = os.path.join(root, f)
        folder_name = os.path.basename(root)
        with open(path, "rb") as fp:
            resp = client.post("/api/v1/upload", files={"file": (f, fp, "message/rfc822")})
            if resp.status_code == 200:
                d = resp.json()
                engaged = "ENGAGED (Twin)" if d.get("active_verification") and d["active_verification"]["engaged"] else "Skipped"
                dec = d["decision"].upper()
                print(f"{folder_name:<30} | {f:<42} | {dec:<10} | {d['calibrated_score']:.2f}  | {engaged}")
            else:
                print(f"Error on {f}: {resp.status_code}")

print("=" * 115)

