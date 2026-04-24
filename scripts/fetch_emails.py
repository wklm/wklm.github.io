import os
import imaplib
import email
import re
from email.header import decode_header
from email.utils import parseaddr
from datetime import datetime
import string

IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = os.environ.get("EMAIL_ACCOUNT")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
ALLOWED_SENDER = os.environ.get("ALLOWED_SENDER")

def clean_slug(title):
    slug = title.lower()
    slug = re.sub(r'[^a-z0-9-]', '-', slug)
    slug = re.sub(r'-+', '-', slug)
    return slug.strip('-')

def main():
    if not all([EMAIL_ACCOUNT, EMAIL_PASSWORD, ALLOWED_SENDER]):
        print("Missing environment variables: EMAIL_ACCOUNT, EMAIL_PASSWORD, or ALLOWED_SENDER.")
        return

    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
        mail.select("inbox")
    except Exception as e:
        print(f"Failed to connect or login: {e}")
        return

    status, messages = mail.search(None, "UNSEEN")
    if status != "OK" or not messages[0]:
        print("No new messages found.")
        mail.logout()
        return

    email_ids = messages[0].split()
    for e_id in email_ids:
        status, msg_data = mail.fetch(e_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                
                # Get sender
                from_header = msg.get("From", "")
                name, sender_email = parseaddr(from_header)
                
                if sender_email.strip().lower() != ALLOWED_SENDER.strip().lower():
                    print(f"Ignoring email from unauthorized sender: {sender_email}")
                    continue

                # Get subject
                subject_header = msg.get("Subject", "Untitled Post")
                decoded_header = decode_header(subject_header)[0]
                subject, encoding = decoded_header
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8", errors="replace")
                
                title = subject
                slug = clean_slug(title)
                if not slug:
                    slug = "post"
                
                # Get body
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        
                        if content_type == "text/plain" and "attachment" not in content_disposition:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body = payload.decode(errors="replace")
                            break
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="replace")
                
                # Format body - clean up signature if present (often separated by '-- ')
                body = body.split('\n-- \n')[0]
                
                # Create post file
                date_str = datetime.now().strftime("%Y-%m-%d")
                
                frontmatter = "---\n"
                frontmatter += f"title: {title}\n"
                frontmatter += f"date: {date_str}\n"
                frontmatter += f"slug: {slug}\n"
                frontmatter += "---\n\n"
                
                content = frontmatter + body.strip() + "\n"
                
                # Handle duplicate filenames
                filepath = os.path.join("posts", f"{slug}.md")
                counter = 1
                while os.path.exists(filepath):
                    filepath = os.path.join("posts", f"{slug}-{counter}.md")
                    counter += 1
                
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                
                print(f"Created post: {filepath} from {sender_email}")

    mail.close()
    mail.logout()

if __name__ == "__main__":
    main()