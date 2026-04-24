#!/usr/bin/env python3
import os
import re
import subprocess
import email
from email.header import decode_header
from datetime import datetime
import asyncio
from aiosmtpd.controller import Controller

def clean_slug(title):
    slug = title.lower()
    slug = re.sub(r'[^a-z0-9-]', '-', slug)
    slug = re.sub(r'-+', '-', slug)
    return slug.strip('-') or "post"

class BlogEmailHandler:
    async def handle_DATA(self, server, session, envelope):
        sender = envelope.mail_from
        print(f"Receiving email from {sender}...")
        
        # Parse email
        msg = email.message_from_bytes(envelope.content)
        
        # Get subject
        subject_header = msg.get("Subject", "Untitled Post")
        decoded_header = decode_header(subject_header)[0]
        subject, encoding = decoded_header
        if isinstance(subject, bytes):
            subject = subject.decode(encoding if encoding else "utf-8", errors="replace")
            
        title = subject
        slug = clean_slug(title)
        
        # Get body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="replace")
                    break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="replace")
                
        # Clean up signature if present
        body = body.split('\n-- \n')[0]
        date_str = datetime.now().strftime("%Y-%m-%d")
        
        # Build frontmatter
        frontmatter = "---\n"
        frontmatter += f"title: {title}\n"
        frontmatter += f"date: {date_str}\n"
        frontmatter += f"slug: {slug}\n"
        frontmatter += "---\n\n"
        
        content = frontmatter + body.strip() + "\n"
        
        # Switch to the correct directory (assumes script is inside crane_blog/scripts/)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.abspath(os.path.join(script_dir, ".."))
        os.chdir(project_dir)
        
        if not os.path.exists("posts"):
            os.makedirs("posts")
            
        filepath = os.path.join("posts", f"{slug}.md")
        counter = 1
        while os.path.exists(filepath):
            filepath = os.path.join("posts", f"{slug}-{counter}.md")
            counter += 1
            
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
            
        print(f"Created post: {filepath}")
        
        # Run docker build & git publish
        print("Running build via docker...")
        try:
            subprocess.run(["docker", "build", "-t", "crane-blog", "."], check=True)
            subprocess.run(["docker", "run", "--name", "crane-blog-run", "crane-blog"], check=True)
            subprocess.run(["docker", "cp", "crane-blog-run:/home/opam/crane-blog/_site", "./_site"], check=True)
            subprocess.run(["docker", "rm", "crane-blog-run"], check=True)
            
            subprocess.run(["git", "add", "posts/"], check=True)
            subprocess.run(["git", "commit", "-m", f"feat: new post via Tailscale SMTP ({slug})"], check=True)
            subprocess.run(["git", "push"], check=True)
            
            print("Successfully published via git push!")
            
            # Announce via wall!
            subprocess.run(["wall"], input=f"Crane Blog post published: {title} ({slug})".encode(), check=False)
            
        except Exception as e:
            print(f"Error during build/publish: {e}")
            subprocess.run(["wall"], input=f"Crane Blog post build FAILED for: {title}".encode(), check=False)
            try:
                subprocess.run(["docker", "rm", "-f", "crane-blog-run"], check=False, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            
        return '250 Message accepted for delivery'

if __name__ == '__main__':
    # Listen on port 2525 by default, so it doesn't require root (Apple Mail can configure custom ports easily)
    port = int(os.environ.get("SMTP_PORT", 2525))
    handler = BlogEmailHandler()
    controller = Controller(handler, hostname='0.0.0.0', port=port)
    controller.start()
    print(f"SMTP server listening on 0.0.0.0:{port} over Tailscale.")
    print("In Apple Mail: Add a custom SMTP server with address matching fuji's Tailscale IP and port 2525.")
    print("Press Ctrl+C to stop.")
    
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
