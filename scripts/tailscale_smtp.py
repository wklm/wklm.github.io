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

async def process_and_publish(slug, title, filepath, project_dir):
    print(f"Background: encrypting and publishing {slug}...")
    try:
        # Run Docker container to encrypt the file
        docker_cmd = [
            "docker", "run", "--rm",
            "-v", f"{project_dir}:/workspace",
            "-w", "/workspace",
            "ocaml/opam:debian-13-ocaml-5.4",
            "bash", "-c",
            f"""
            sudo apt-get update && sudo apt-get install -y gnupg && \\
            gpg --import wklm-sec.asc && \\
            git config --global --add safe.directory /workspace && \\
            git config --global user.email "wojtekkulma@gmail.com" && \\
            git config --global user.name "wklm" && \\
            eval $(opam env) && \\
            dune build tools/encrypt_post.exe && \\
            ./_build/default/tools/encrypt_post.exe {filepath}
            """
        ]
        
        print("Running encryption via docker...")
        process = await asyncio.create_subprocess_exec(
            *docker_cmd,
            cwd=project_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            print(f"Docker encryption failed: {stderr.decode('utf-8', errors='replace')}")
            subprocess.run(["wall"], input=f"Crane Blog encryption FAILED for: {title}".encode(), check=False)
            return
            
        print("Encryption successful. Committing to git...")
        eml_path = f"posts-encrypted/{slug}.eml"
        
        subprocess.run(["git", "add", eml_path], cwd=project_dir, check=True)
        # Use --no-verify so pre-commit doesn't run natively
        subprocess.run(["git", "commit", "--no-verify", "-m", f"feat: new encrypted post via Tailscale SMTP ({slug})"], cwd=project_dir, check=True)
        subprocess.run(["git", "push"], cwd=project_dir, check=True)
        
        print("Successfully published via git push!")
        subprocess.run(["wall"], input=f"Crane Blog post published: {title} ({slug})".encode(), check=False)
        
    except Exception as e:
        print(f"Error during background publish: {e}")
        subprocess.run(["wall"], input=f"Crane Blog publish FAILED for: {title}".encode(), check=False)

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
        
        # Switch to the correct directory
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
            
        print(f"Created plaintext post: {filepath}")
        
        # Spawn background task to encrypt and push, so we don't timeout the SMTP client
        asyncio.create_task(process_and_publish(slug, title, filepath, project_dir))
            
        return '250 Message accepted for delivery'

if __name__ == '__main__':
    # Listen on port 2525
    port = int(os.environ.get("SMTP_PORT", 2525))
    handler = BlogEmailHandler()
    controller = Controller(handler, hostname='0.0.0.0', port=port)
    controller.start()
    print(f"SMTP server listening on 0.0.0.0:{port} over Tailscale.")
    print("Press Ctrl+C to stop.")
    
    try:
        # Use asyncio.get_event_loop().run_forever() correctly
        loop = asyncio.get_event_loop()
        loop.run_forever()
    except KeyboardInterrupt:
        pass
