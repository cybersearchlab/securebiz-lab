FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Installation des dependances applicatives et des versions corrigees
# dans une seule couche Docker.
COPY requirements.txt .

RUN python -m pip install --no-cache-dir \
    --timeout 120 --retries 5 \
    --index-url https://pypi.org/simple/ \
    -r requirements.txt \
    && python -m pip install --no-cache-dir --upgrade \
    --timeout 120 --retries 5 \
    --index-url https://pypi.org/simple/ \
    "certifi==2026.10.23" \
    "msgpack==1.2.4" \
    "setuptools==84.2.1" \
    "urllib3==2.8.0" \
    && python -m pip check

# Suppression de pip (non utilise au runtime).
RUN python -m pip uninstall -y pip

COPY ./app ./app

# Creation d'un utilisateur non-root dedie (DS-0002).
RUN groupadd --system --gid 1000 appgroup \
    && useradd --system --uid 1000 --gid appgroup \
       --no-create-home --shell /usr/sbin/nologin appuser

# Code detenu par root, accessible en lecture uniquement.
RUN chown -R root:appgroup /app \
    && find /app -type d -exec chmod 0550 {} \; \
    && find /app -type f -exec chmod 0440 {} \;

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
