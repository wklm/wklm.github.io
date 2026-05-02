#!/usr/bin/env python3
"""
Crane Blog SMTP listener.

Receives one envelope, encrypts normal Mail.app plaintext in memory with the
author's public key, wraps it in a canonical RFC 3156 multipart/encrypted
message, writes posts-encrypted/<UTC-isoZ>.eml, and pushes the commit to the
blog repo. Authentication is by Tailscale ACL plus an optional MAIL FROM
allowlist.
"""
import asyncio
import datetime as dt
from email import policy
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
GPG_RECIPIENT = os.environ.get("BLOG_GPG_RECIPIENT", "B2467F312C5F4BDCDF50D57993F51309D4C9372A")

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


def _header_line(name: str, value: str) -> str:
    return f"{name}: {value.replace(chr(13), ' ').replace(chr(10), ' ').strip()}\r\n"


def _encrypt(text: str) -> str:
    proc = subprocess.run(
        [
            "gpg",
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--no-auto-key-retrieve",
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
    date = format_datetime(now)
    subject = _header(incoming, "Subject", "Untitled")
    body = _plain_body(incoming)
    inner = "".join(
        [
            _header_line("From", sender),
            _header_line("To", recipients),
            _header_line("Date", date),
            _header_line("Subject", subject),
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: 8bit\r\n",
            "\r\n",
            body,
            "" if body.endswith("\n") else "\r\n",
        ]
    )
    armor = _encrypt(inner)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    boundary = f"=_cb_smtp_{ts}_="
    outer = "".join(
        [
            "Subject: ...\r\n",
            "MIME-Version: 1.0\r\n",
            f'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="{boundary}"\r\n',
            "\r\n",
            "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156).\r\n",
            f"--{boundary}\r\n",
            "Content-Type: application/pgp-encrypted\r\n",
            "Content-Description: PGP/MIME version identification\r\n",
            "\r\n",
            "Version: 1\r\n",
            f"--{boundary}\r\n",
            "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n",
            "Content-Description: OpenPGP encrypted message\r\n",
            "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n",
            "\r\n",
            armor,
            "" if armor.endswith("\n") else "\r\n",
            f"--{boundary}--\r\n",
        ]
    )
    return outer.encode("utf-8")


class Handler:
    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        sender = (envelope.mail_from or "").lower()
        peer = session.peer[0] if session.peer else "?"
        size = len(envelope.content or b"")
        log.info("DATA peer=%s size=%d", peer, size)

        if ALLOW and sender not in ALLOW:
            log.warning("reject: sender not in allowlist")
            return "550 sender not allowed"
        now = dt.datetime.now(dt.timezone.utc)
        ts = now.strftime("%Y%m%dT%H%M%SZ")
        rel = Path("posts-encrypted") / f"{ts}.eml"
        try:
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
    logging.getLogger("mail.log").setLevel(logging.WARNING)
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
