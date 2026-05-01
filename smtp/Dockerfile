FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir aiosmtpd==1.4.6

WORKDIR /app
COPY listener.py entrypoint.sh author.pub /app/
RUN chmod +x /app/entrypoint.sh

ENV PYTHONUNBUFFERED=1 \
    BLOG_REPO_PATH=/repo \
    BLOG_BRANCH=main \
    SMTP_HOST=0.0.0.0 \
    SMTP_PORT=2525

ENTRYPOINT ["/app/entrypoint.sh"]
