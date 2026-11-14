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

# Suppression de pip (non utilise au runtime) pour eliminer les CVE
# provenant de son dossier _vendor (setuptools, msgpack, etc.).
RUN python -m pip uninstall -y pip

COPY ./app ./app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]