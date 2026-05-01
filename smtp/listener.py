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
from email.parser import BytesParser
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


def _header(msg, name: str, fallback: str = "") -> str:
    value = msg.get(name)
    return str(value).replace("\r", " ").replace("\n", " ").strip() if value else fallback


def _plain_body(msg) -> str:
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


def _armor_from_bytes(payload: bytes) -> str:
    text = payload.decode("utf-8", errors="replace")
    begin = text.find("-----BEGIN PGP MESSAGE-----")
    end = text.find("-----END PGP MESSAGE-----")
    if begin < 0 or end < begin:
        raise ValueError("PGP armor block not found")
    end += len("-----END PGP MESSAGE-----")
    return text[begin:end] + "\n"


def _public_envelope(subject: str, armor: str) -> bytes:
    return (f"Subject: {subject}\r\n\r\n{armor}").encode("utf-8")


def _encrypted_envelope(envelope: Envelope) -> bytes:
    incoming = BytesParser(policy=policy.default).parsebytes(envelope.content or b"")
    subject = _header(incoming, "Subject", "Untitled")
    armor = _encrypt(_plain_body(incoming))
    return _public_envelope(subject, armor)


def _sanitized_envelope(envelope: Envelope) -> bytes:
    incoming = BytesParser(policy=policy.default).parsebytes(envelope.content or b"")
    subject = _header(incoming, "Subject", "Untitled")
    return _public_envelope(subject, _armor_from_bytes(envelope.content or b""))


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
                post_bytes = _sanitized_envelope(envelope)
                log.info("payload already encrypted; storing sanitized envelope")
            else:
                post_bytes = _encrypted_envelope(envelope)
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
                _git("commit", "-m", f"post: {ts} (via smtp)")
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
    log.info("repo=%s branch=%s allow=%s", REPO, BRANCH, sorted(ALLOW) or "*")
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
