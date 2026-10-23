import re
import os

pdf_path = os.path.expanduser("~/phish-lab/samples/attachments/1000_0.bin")

if not os.path.exists(pdf_path):
    print(f"Error: {pdf_path} not found.")
    exit(1)

with open(pdf_path, "rb") as f:
    raw = f.read()

print("=" * 50)
print("PDF STRUCTURAL OBJECT CHECK (1000_0.bin)")
print("=" * 50)
for marker in [b"/URI", b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/SubmitForm"]:
    count = len(re.findall(marker, raw))
    print(f"{marker.decode():15}: {count} occurrence(s)")

print("\n" + "=" * 50)
print("EXTRACTED URLS (DEFANGED)")
print("=" * 50)
urls = re.findall(rb'https?://[^\s<>"\'\)]+', raw)
if urls:
    for u in set(urls):
        defanged = u.decode('utf-8', errors='ignore').replace('http', 'hxxp').replace('.', '[.]')
        print("  ->", defanged)
else:
    print("  No plaintext HTTP/HTTPS URLs found in streams.")

print("\n" + "=" * 50)
print("RAW ASCII TEXT FRAGMENTS")
print("=" * 50)
text_strings = re.findall(rb'[A-Za-z0-9 ,.:;!?-]{5,}', raw)
for s in text_strings[:10]:
    print(" ", s.decode('utf-8', errors='ignore'))
