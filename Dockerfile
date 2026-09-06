FROM python:3.12-slim

WORKDIR /app

COPY system_info.py start.sh ./
RUN chmod +x start.sh

ENTRYPOINT ["/app/start.sh"]
