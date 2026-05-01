#!/usr/bin/env python3
"""
Crane Blog SMTP listener.

Receives one envelope, drops the raw bytes verbatim into
posts-encrypted/<UTC-isoZ>.eml, and pushes the commit to the blog repo.
The author encrypts client-side; this server never sees plaintext and never
runs gpg. Authentication is by Tailscale ACL plus an optional MAIL FROM
allowlist; a payload-shape check rejects anything that does not contain a
PGP armor block.
"""
import asyncio
import datetime as dt
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session, SMTP

BANNER = os.environ.get("SMTP_BANNER", "wklm.github.io")

REPO = Path(os.environ.get("BLOG_REPO_PATH", "/repo"))
BRANCH = os.environ.get("BLOG_BRANCH", "main")
HOST = os.environ.get("SMTP_HOST", "0.0.0.0")
PORT = int(os.environ.get("SMTP_PORT", "2525"))
ALLOW = {a.strip().lower() for a in os.environ.get("BLOG_ALLOW_FROM", "").split(",") if a.strip()}
REQUIRE_PGP = os.environ.get("BLOG_REQUIRE_PGP", "1") == "1"
PGP_MARKER = b"-----BEGIN PGP MESSAGE-----"

log = logging.getLogger("crane-blog-smtp")
_git_lock = asyncio.Lock()


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=REPO, check=True, capture_output=True, text=True
    )


class Handler:
    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        sender = (envelope.mail_from or "").lower()
        peer = session.peer[0] if session.peer else "?"
        size = len(envelope.content or b"")
        log.info("DATA from=%s peer=%s size=%d", sender, peer, size)

        if ALLOW and sender not in ALLOW:
            log.warning("reject: sender %r not in allowlist", sender)
            return "550 sender not allowed"
        if REQUIRE_PGP and PGP_MARKER not in (envelope.content or b""):
            log.warning("reject: no PGP armor block in payload")
            return "550 message must contain a PGP-encrypted body"

        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rel = Path("posts-encrypted") / f"{ts}.eml"

        async with _git_lock:
            try:
                _git("fetch", "origin", BRANCH)
                _git("reset", "--hard", f"origin/{BRANCH}")
                target = REPO / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(envelope.content or b"")
                _git("add", str(rel))
                _git("commit", "-m", f"post: {ts} (via smtp from {sender or 'unknown'})")
                _git("push", "origin", f"HEAD:{BRANCH}")
            except subprocess.CalledProcessError as e:
                log.error("git failed: %s\nstderr: %s", e, e.stderr)
                return f"451 git failed: {e.stderr.strip()[:180]}"

        log.info("published %s", rel)
        return "250 OK"


async def amain() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    log.info("repo=%s branch=%s allow=%s require_pgp=%s", REPO, BRANCH, sorted(ALLOW) or "*", REQUIRE_PGP)
    controller = Controller(Handler(), hostname=HOST, port=PORT, server_hostname=BANNER)
    controller.start()
    log.info("listening on %s:%d", HOST, PORT)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        controller.stop()
        log.info("stopped")


if __name__ == "__main__":
    asyncio.run(amain())
