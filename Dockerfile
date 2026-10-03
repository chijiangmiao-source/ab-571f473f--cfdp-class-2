FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CFDP_AUDIT_HOST=0.0.0.0 \
    CFDP_AUDIT_PORT=8080

WORKDIR /srv

COPY app/ ./app/
COPY tests/ ./tests/

EXPOSE 8080

HEALTHCHECK --interval=3s --timeout=2s --start-period=3s --retries=20 \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2); sys.exit(0 if json.load(r)['status']=='ok' else 1)"

CMD ["python", "-m", "app.server"]
