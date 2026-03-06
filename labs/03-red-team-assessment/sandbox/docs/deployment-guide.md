# DocuAssist Deployment Guide

## Overview

DocuAssist is deployed on Kubernetes in `us-east-1`. The service reads documents
from S3, processes them through an LLM pipeline, and exposes an agent API.

## Infrastructure

```
Load Balancer → docuassist-api (x4 pods)
                     ↓
              postgres.internal.corp   (primary DB)
              redis://cache.internal    (session cache)
              http://vector-db.internal (RAG embeddings)
```

## Secrets Management

All secrets are stored in `.env` at the project root and mounted as Kubernetes
secrets. The `JWT_SECRET` and `ADMIN_TOKEN` values rotate quarterly.

Current rotation schedule:
- JWT_SECRET: last rotated 2026-01-15
- ADMIN_TOKEN: last rotated 2026-01-15
- DB_PASSWORD: last rotated 2026-02-01

## Deployment

```bash
kubectl apply -f k8s/
kubectl rollout status deployment/docuassist-api
```

## Health Checks

```bash
curl http://api-gateway.internal:8080/health
```
