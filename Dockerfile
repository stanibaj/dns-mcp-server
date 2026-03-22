FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dns_server.py healthcheck.py ./

EXPOSE 8000

# Connects to /sse, checks for HTTP 200, exits immediately.
# start_period gives the server time to finish booting before failures count.
HEALTHCHECK --interval=30s --timeout=30s --start-period=15s --retries=3 \
    CMD python healthcheck.py

CMD ["python", "dns_server.py"]
