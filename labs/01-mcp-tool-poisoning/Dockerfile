FROM python:3.12-slim

WORKDIR /lab

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Lab code
COPY . .

# Dummy target files for demo exfil
RUN mkdir -p /root/.aws /root/.ssh && \
    echo 'ssh-rsa AAAAB3NzaC1yc2E_DEMO_KEY demo@lab' > /root/.ssh/id_rsa.pub.demo && \
    printf '[default]\naws_access_key_id = AKIAIOSFODNN7DEMO\naws_secret_access_key = wJalrXUtnFEMI/DEMO\n' > /root/.aws/credentials.demo

# Override PYTHON so the container uses the system python (no venv inside Docker)
ENV PYTHON=python3
ENV LLAMACPP_URL=http://localhost:8081/v1
ENV MODEL=qwen3.6-35b-a3b

EXPOSE 9999

CMD ["python", "run_experiments.py"]
