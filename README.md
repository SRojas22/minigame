# minigame

A small password-protected 3D web game, served from `docs/` with GitHub Pages.

Everything private (the message, the gift card and its image) is AES-256-GCM
encrypted inside `docs/index.html`, with a key derived from a username and
password (PBKDF2-SHA256, 600k iterations). Nothing readable is stored in this
repo.

## Rebuilding

The private content lives in `content.json`, which is gitignored and never
committed.

```
python3 -m venv .venv && .venv/bin/pip install cryptography
.venv/bin/python main.py
```

`main.py` asks for the username and password, then writes `docs/index.html`.
