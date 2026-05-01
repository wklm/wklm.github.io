#!/usr/bin/env python3
"""
Crane Blog SMTP listener.

Receives one envelope, encrypts normal Mail.app plaintext in memory with the
author's public key, writes posts-encrypted/<UTC-isoZ>.eml, and pushes the
commit to the blog repo. If the envelope already contains a PGP armor block,
it is stored verbatim for script-driven clients. Authentication is by Tailscale
ACL plus an optional MAIL FROM allowlist.
"""
import asyncio
import datetime as dt
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime
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
GPG_RECIPIENT = os.environ.get("BLOG_GPG_RECIPIENT", "wklm@protonmail.com")
PGP_MARKER = b"-----BEGIN PGP MESSAGE-----"

log = logging.getLogger("crane-blog-smtp")
_git_lock = asyncio.Lock()


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=REPO, check=True, capture_output=True, text=True
    )


def _header(msg: EmailMessage, name: str, fallback: str = "") -> str:
    value = msg.get(name)
    return str(value).replace("\r", " ").replace("\n", " ").strip() if value else fallback


def _plain_body(msg: EmailMessage) -> str:
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is not None:
        return body.get_content()

    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            if part.get_content_maintype() == "text":
                parts.append(part.get_content())
        if parts:
            return "\n\n".join(parts)

    payload = msg.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
    return str(msg.get_payload() or "")


def _encrypt(text: str) -> str:
    proc = subprocess.run(
        [
            "gpg",
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--armor",
            "--encrypt",
            "-r",
            GPG_RECIPIENT,
        ],
        input=text.encode("utf-8"),
        check=True,
        capture_output=True,
    )
    return proc.stdout.decode("ascii")


def _encrypted_envelope(envelope: Envelope, now: dt.datetime) -> bytes:
    incoming = BytesParser(policy=policy.default).parsebytes(envelope.content or b"")
    sender = _header(incoming, "From", envelope.mail_from or "unknown")
    recipients = _header(incoming, "To", ", ".join(envelope.rcpt_tos or []) or "blog@wklm.github.io")
    subject = _header(incoming, "Subject", "Untitled")
    date = _header(incoming, "Date", format_datetime(now))
    armor = _encrypt(_plain_body(incoming))

    outgoing = EmailMessage(policy=policy.SMTP)
    outgoing["From"] = sender
    outgoing["To"] = recipients
    outgoing["Date"] = date
    outgoing["Subject"] = subject
    outgoing["MIME-Version"] = "1.0"
    outgoing.set_content(armor)
    outgoing.replace_header("Content-Type", 'application/pgp-encrypted; name="post.asc"')
    outgoing["Content-Disposition"] = 'inline; filename="post.asc"'
    return outgoing.as_bytes()


class Handler:
    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        sender = (envelope.mail_from or "").lower()
        peer = session.peer[0] if session.peer else "?"
        size = len(envelope.content or b"")
        log.info("DATA from=%s peer=%s size=%d", sender, peer, size)

        if ALLOW and sender not in ALLOW:
            log.warning("reject: sender %r not in allowlist", sender)
            return "550 sender not allowed"
        now = dt.datetime.now(dt.timezone.utc)
        ts = now.strftime("%Y%m%dT%H%M%SZ")
        rel = Path("posts-encrypted") / f"{ts}.eml"
        try:
            if PGP_MARKER in (envelope.content or b""):
                post_bytes = envelope.content or b""
                log.info("payload already encrypted; storing verbatim")
            else:
                post_bytes = _encrypted_envelope(envelope, now)
                log.info("encrypted plaintext message for %s", GPG_RECIPIENT)
        except subprocess.CalledProcessError as e:
            log.error("gpg failed: %s\nstderr: %s", e, e.stderr.decode("utf-8", errors="replace"))
            return "451 encryption failed"

        async with _git_lock:
            try:
                _git("fetch", "origin", BRANCH)
                _git("reset", "--hard", f"origin/{BRANCH}")
                target = REPO / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(post_bytes)
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
    log.info("repo=%s branch=%s allow=%s recipient=%s", REPO, BRANCH, sorted(ALLOW) or "*", GPG_RECIPIENT)
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
