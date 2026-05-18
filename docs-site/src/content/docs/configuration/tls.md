---
title: TLS / HTTPS
description: Configure custom CA certificates for upstream registry connections
---


NORA uses the system CA certificate store by default for all outbound HTTPS connections to upstream registries. If your upstreams use self-signed certificates or you are behind a corporate TLS-inspecting proxy, you can provide a custom CA bundle.

---

## Environment Variable

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_TLS_CA_CERT` | *(none)* | Path to PEM-encoded CA certificate bundle (appended to system CAs) |

The certificates in this file are **appended** to the system CA store -- they do not replace it.

---

## config.toml

```toml
[tls]
ca_cert = "/etc/nora/ca-bundle.pem"
```

---

## Use Cases

### Corporate TLS-Inspecting Proxy

Organizations that inspect outbound HTTPS traffic with a proxy (e.g., Zscaler, Bluecoat) replace upstream TLS certificates with ones signed by an internal CA. Without adding this CA to NORA, all upstream connections fail with certificate verification errors.

```bash
export NORA_TLS_CA_CERT="/etc/ssl/corporate-ca.pem"
```

### Self-Signed Upstream Registries

Private registries using self-signed certificates need their CA added to NORA:

```bash
export NORA_TLS_CA_CERT="/etc/nora/private-registry-ca.pem"
```

---

## Docker Compose Example

Mount the CA bundle as a volume and set the environment variable:

```yaml
services:
  nora:
    image: getnora/nora:latest
    environment:
      NORA_TLS_CA_CERT: "/etc/nora/ca-bundle.pem"
    volumes:
      - ./ca-bundle.pem:/etc/nora/ca-bundle.pem:ro
    ports:
      - "4000:4000"
```

---

## Kubernetes Example

Mount the CA bundle from a ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nora-ca
data:
  ca-bundle.pem: |
    -----BEGIN CERTIFICATE-----
    MIIDxTCCAq2gAwIBAgIQAqxcJmoLQ...
    -----END CERTIFICATE-----
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nora
spec:
  template:
    spec:
      containers:
        - name: nora
          image: getnora/nora:latest
          env:
            - name: NORA_TLS_CA_CERT
              value: /etc/nora/ca-bundle.pem
          volumeMounts:
            - name: ca-bundle
              mountPath: /etc/nora/ca-bundle.pem
              subPath: ca-bundle.pem
              readOnly: true
      volumes:
        - name: ca-bundle
          configMap:
            name: nora-ca
```

---

## See Also

- [Settings](/configuration/settings/) -- complete environment variable reference
- [Outbound Proxy](/configuration/http-proxy/) -- HTTP/SOCKS5 proxy configuration
- [Docker Proxy](/configuration/docker-proxy/) -- upstream Docker registry configuration
