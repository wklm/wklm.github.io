#!/usr/bin/env python3
"""
Crane Blog SMTP listener.

Receives one envelope, writes it as a markdown post with frontmatter,
encrypts via the `encrypt_post` tool (HPKE with per-reader wrapped keys),
and pushes the commit to the blog repo.  Replaces the old gpg-based
RFC 3156 PGP/MIME pipeline.
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

BANNER = os.environ.get("SMTP_BANNER", "wklm.online")

REPO = Path(os.environ.get("BLOG_REPO_PATH", "/repo"))
BRANCH = os.environ.get("BLOG_BRANCH", "main")
HOST = os.environ.get("SMTP_HOST", "0.0.0.0")
PORT = int(os.environ.get("SMTP_PORT", "2525"))
ALLOW = {a.strip().lower() for a in os.environ.get("BLOG_ALLOW_FROM", "").split(",") if a.strip()}
PUBLIC_KEYS = os.environ.get("BLOG_PUBLIC_KEYS", "")
AUTHOR_KEY_ID = os.environ.get("CRANE_BLOG_AUTHOR_KEY_ID", "")
ENCRYPT_POST = os.environ.get("ENCRYPT_POST_BIN", "encrypt_post")

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


def _encrypt_post(md_path: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [ENCRYPT_POST, "--stage", md_path],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )


def _slug_from_subject(subject: str, ts: str) -> str:
    import re
    slug = subject.lower()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    if not slug or len(slug) > 64:
        slug = ts
    return slug[:64]


def _build_md(sender: str, subject: str, body: str, date: str, public_keys: str) -> str:
    frontmatter = "---\n"
    frontmatter += f"title: {subject}\n"
    frontmatter += f"slug: {_slug_from_subject(subject, dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))}\n"
    frontmatter += f"author: {sender}\n"
    frontmatter += f"date: {date}\n"
    if public_keys:
        frontmatter += f"public-keys: {public_keys}\n"
    elif AUTHOR_KEY_ID:
        frontmatter += f"public-keys: {AUTHOR_KEY_ID}\n"
    frontmatter += "---\n\n"
    frontmatter += body
    if not body.endswith("\n"):
        frontmatter += "\n"
    return frontmatter


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

        try:
            incoming = BytesParser(policy=policy.default).parsebytes(envelope.content or b"")
        except Exception as e:
            log.error("parse failed: %s", e)
            return "550 cannot parse message"

        subject = _header(incoming, "Subject", "Untitled")
        body = _plain_body(incoming)
        date = format_datetime(now)

        if not body:
            log.warning("empty body, rejecting")
            return "550 message has no body"

        # Check for X-Crane-Public-Keys header in the email
        email_public_keys = _header(incoming, "X-Crane-Public-Keys", "")
        public_keys = email_public_keys or PUBLIC_KEYS

        md_content = _build_md(sender, subject, body, date, public_keys)
        md_rel = Path("posts") / f"{ts}.md"

        async with _git_lock:
            try:
                _git("fetch", "origin", BRANCH)
                _git("reset", "--hard", f"origin/{BRANCH}")
                target = REPO / md_rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(md_content, encoding="utf-8")
                _git("add", str(md_rel))

                # Run encrypt_post to produce the encrypted .eml in posts-encrypted/
                enc_result = _encrypt_post(str(md_rel))
                log.info("encrypted post: %s", enc_result.stdout.strip())

                _git("add", "posts-encrypted/")
                _git("commit", "-m", f"post: {ts} (via smtp)")
                _git("push", "origin", f"HEAD:{BRANCH}")
            except subprocess.CalledProcessError as e:
                log.error("command failed: %s\nstderr: %s", e, e.stderr)
                return f"451 processing failed: {e.stderr.strip()[:180]}"

        log.info("published %s", md_rel)
        return "250 OK"


async def amain() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("mail.log").setLevel(logging.WARNING)
    log.info("repo=%s branch=%s allow=%s public_keys=%s", REPO, BRANCH, sorted(ALLOW) or "*", PUBLIC_KEYS or "author-only")
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
