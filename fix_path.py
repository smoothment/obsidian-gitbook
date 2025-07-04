import os
import re
from urllib.parse import quote

# Base vault directory
VAULT_DIR = r"C:\Users\samue\Downloads\obsidian-gitbook\obsidian"

# Relative path from vault root to images folder
REL_IMAGE_PATH = "CYBERSECURITY/IMAGES"

# Pattern for Obsidian-style embeds
obsidian_pattern = re.compile(r'!\[\[(Pasted image [^\[\]]+\.(?:png|jpg|jpeg|gif|bmp|svg))\]\]')

# Pattern for existing broken references (e.g. ../IMAGES or similar)
broken_reference_pattern = re.compile(r'!\[\]\([\.\/\\]*images[\/\\](Pasted%20image[^\)]+)\)', re.IGNORECASE)

def fix_image_links(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original = content

    # Convert Obsidian-style image embeds
    matches = obsidian_pattern.findall(content)
    for match in matches:
        encoded = quote(match)
        replacement = f"![]({REL_IMAGE_PATH}/{encoded})"
        content = content.replace(f"![[{match}]]", replacement)

    # Convert broken ![](../images/...) references
    matches = broken_reference_pattern.findall(content)
    for match in matches:
        replacement = f"![]({REL_IMAGE_PATH}/{match})"
        content = re.sub(rf'!\[\]\([\.\/\\]*images[\/\\]{re.escape(match)}\)', replacement, content, flags=re.IGNORECASE)

    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[✔] Fixed: {filepath}")
    else:
        print(f"[=] No changes: {filepath}")

def walk_and_fix_images(vault_dir):
    for root, _, files in os.walk(vault_dir):
        for file in files:
            if file.endswith(".md"):
                filepath = os.path.join(root, file)
                fix_image_links(filepath)

if __name__ == "__main__":
    walk_and_fix_images(VAULT_DIR)
