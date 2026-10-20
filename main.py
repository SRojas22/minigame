"""Build the password-protected apology page.

Reads the private content from content.json, encrypts it with a key derived
from a username + password, and writes a single self-contained page to
docs/index.html (served by GitHub Pages). The gift card image is packed inside
the encrypted data too.

Only docs/index.html gets published. It contains nothing readable without the
password: the message and gift card are AES-256-GCM encrypted, and the key is
derived with PBKDF2-SHA256 (600k iterations), so guessing passwords is slow.

Usage:
    .venv/bin/python main.py
"""

import argparse
import base64
import getpass
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).parent
ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 8


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encrypt(plaintext: bytes, password: str) -> dict:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(
        password.encode("utf-8")
    )
    # AESGCM appends the 16-byte auth tag, which is the layout WebCrypto expects.
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    return {"v": 1, "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "ct": b64(ciphertext)}


def login_secret(username: str, password: str) -> str:
    # Must match loginSecret() in template.html.
    return f"{username.strip().lower()}\n{password.strip()}"


def ask_username() -> str:
    env = os.environ.get("SORRY_USERNAME")
    if env:
        return env
    while True:
        name = input("Username for your friend (not case-sensitive): ").strip()
        if name:
            return name


def ask_password() -> str:
    # SORRY_USERNAME / SORRY_PASSWORD exist for scripted test builds; prefer the prompts.
    env = os.environ.get("SORRY_PASSWORD")
    if env:
        return env.strip()

    while True:
        first = getpass.getpass("Password for your friend: ").strip()
        if len(first) < MIN_PASSWORD_LENGTH:
            print(f"  Too short. Use at least {MIN_PASSWORD_LENGTH} characters "
                  "(a short phrase only you two know works great).")
            continue
        if getpass.getpass("Type it again: ").strip() != first:
            print("  Those didn't match, try again.")
            continue
        return first


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--content", type=Path, default=ROOT / "content.json")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "index.html")
    args = parser.parse_args()

    content = json.loads(args.content.read_text(encoding="utf-8"))
    hint = content.pop("public_hint", "") or ""

    if "XXXX" in content.get("gift", {}).get("code", ""):
        print("Heads up: the gift card code in content.json is still the placeholder.")

    image = content.get("gift", {}).get("image")
    if image:
        path = args.content.parent / image
        mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
        content["gift"]["image"] = f"data:{mime};base64,{b64(path.read_bytes())}"

    password = login_secret(ask_username(), ask_password())
    payload = encrypt(json.dumps(content, ensure_ascii=False).encode("utf-8"), password)

    template = (ROOT / "template.html").read_text(encoding="utf-8")
    page = (
        template
        .replace("/*__PAYLOAD__*/null", json.dumps(payload))
        .replace("/*__HINT__*/\"\"", json.dumps(hint, ensure_ascii=False).replace("</", "<\\/"))
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(page, encoding="utf-8")
    print(f"Built {args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}")
    print("Only docs/ gets published. Keep content.json to yourself.")


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        sys.exit("Needs Python 3.9+")
    main()
