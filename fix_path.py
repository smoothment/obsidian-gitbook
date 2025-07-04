import os
import re
from urllib.parse import quote

# Path to your Obsidian vault
VAULT_DIR = r"C:\Users\samue\Downloads\obsidian-gitbook\obsidian"

# Skip directory
SKIP_DIR = os.path.join(VAULT_DIR, "CYBERSECURITY", "TRYHACKME", "RED TEAMING PATH", "Host Evasions").lower()

# Regex to match Obsidian embedded images
pattern = re.compile(r'!\[\[(Pasted image [^\[\]]+\.(?:png|jpg|jpeg|gif|bmp|svg))\]\]')

def convert_links_in_file(filepath):
    modified = False
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()

    matches = pattern.findall(content)
    if matches:
        print(f"🔍 Found {len(matches)} match(es) in {filepath}")

    for match in matches:
        encoded = quote(match)
        rel_path = f"![](../images/{encoded})"
        content = content.replace(f"![[{match}]]", rel_path)
        modified = True

    if modified:
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"[✔] Updated: {filepath}")

def walk_and_convert(vault_dir):
    for root, _, files in os.walk(vault_dir):
        if SKIP_DIR in root.lower():
            continue
        for file in files:
            if file.endswith(".md"):
                filepath = os.path.join(root, file)
                convert_links_in_file(filepath)

if __name__ == "__main__":
    walk_and_convert(VAULT_DIR)
