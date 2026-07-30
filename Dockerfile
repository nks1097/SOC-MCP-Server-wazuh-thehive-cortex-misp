# syntax=docker/dockerfile:1.9
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS production

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src/ ./src/
COPY .env .env

ENV PYTHONPATH="/app"
ENV FAST_MCP_PORT=8000
EXPOSE 8000

# FastMCP CLI can be run using the standard entrypoint or via python
CMD ["python", "-m", "src.main"]