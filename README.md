# Container Vulnerability Scanner Platform

A comprehensive DevSecOps platform for scanning Docker container images for known CVEs using Trivy, storing results in PostgreSQL, and visualizing them through a modern web dashboard. Deployed on Kubernetes (KinD) and managed via ArgoCD (GitOps).

![Architecture](docs/architecture.png)

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Kubernetes Cluster (KinD)                       │
│                                                                              │
│  ┌─────────────┐     ┌─────────────────┐     ┌───────────────────────────┐  │
│  │  Dashboard  │────▶│   API Service   │────▶│       PostgreSQL          │  │
│  │   (nginx)   │     │    (FastAPI)    │     │   (Persistent Storage)    │  │
│  │  Port:30081 │     │   Port:30080    │     │                           │  │
│  └─────────────┘     └────────┬────────┘     └───────────────────────────┘  │
│                               │                            ▲                 │
│                               │ Creates Jobs               │                 │
│                               ▼                            │                 │
│                      ┌─────────────────┐                   │                 │
│                      │  Scanner Worker │───────────────────┘                 │
│                      │  (Trivy + Python)│   Saves Results                    │
│                      │   K8s Job        │                                    │
│                      └─────────────────┘                                     │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         ArgoCD (GitOps)                               │   │
│  │                    Syncs from Git Repository                          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Technology | Description |
|-----------|------------|-------------|
| **API Service** | FastAPI + Python | REST API for scan management, creates K8s Jobs |
| **Scanner Worker** | Trivy + Python | Ephemeral K8s Job that scans images and saves results |
| **Dashboard** | HTML/CSS/JS + nginx | Web UI for viewing scans and vulnerabilities |
| **Database** | PostgreSQL 15 | Stores images, scans, and vulnerability data |
| **GitOps** | ArgoCD | Continuous deployment from Git repository |

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Docker Desktop** (with Kubernetes support) or Docker Engine
- **KinD** (Kubernetes in Docker) - [Installation Guide](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- **kubectl** - [Installation Guide](https://kubernetes.io/docs/tasks/tools/)
- **Git** - For cloning and GitOps

### Verify Prerequisites

```bash
# Check Docker
docker --version

# Check KinD
kind --version

# Check kubectl
kubectl version --client
```

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/michaelgameel5/scanning_container_trivy.git
cd scanning_container_trivy
```

### 2. Create KinD Cluster

```bash
# Create a KinD cluster with port mappings for NodePort services
cat <<EOF | kind create cluster --name vuln-scanner --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30080
    hostPort: 30080
    protocol: TCP
  - containerPort: 30081
    hostPort: 30081
    protocol: TCP
  - containerPort: 30082
    hostPort: 30082
    protocol: TCP
EOF

# Verify cluster is running
kubectl cluster-info --context kind-vuln-scanner
```

### 3. Build Docker Images

```bash
# Build API image
docker build -t vuln-scanner-api:latest ./api

# Build Worker image
docker build -t vuln-scanner-worker:latest ./worker

# Build Dashboard image
docker build -t vuln-scanner-dashboard:latest ./dashboard

# Load images into KinD cluster
kind load docker-image vuln-scanner-api:latest --name vuln-scanner
kind load docker-image vuln-scanner-worker:latest --name vuln-scanner
kind load docker-image vuln-scanner-dashboard:latest --name vuln-scanner
```

### 4. Deploy to Kubernetes

```bash
# Deploy PostgreSQL
kubectl apply -f k8s/postgres.yaml

# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod -l component=database --timeout=120s

# Deploy API Service
kubectl apply -f k8s/api.yaml

# Wait for API to be ready
kubectl wait --for=condition=ready pod -l component=api --timeout=120s

# Deploy Dashboard
kubectl apply -f k8s/dashboard.yaml

# Verify all pods are running
kubectl get pods
```

### 5. Access the Application

| Service | URL | Description |
|---------|-----|-------------|
| **Dashboard** | http://localhost:30081 | Web UI |
| **API** | http://localhost:30080 | REST API |
| **API Docs** | http://localhost:30080/docs | Swagger UI |

## 🔧 ArgoCD Setup (GitOps)

### Install ArgoCD

```bash
# Create namespace
kubectl create namespace argocd

# Install ArgoCD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for ArgoCD to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=argocd-server -n argocd --timeout=300s
```

### Access ArgoCD UI

```bash
# Port forward ArgoCD server
kubectl port-forward svc/argocd-server -n argocd 8080:443

# Get initial admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Access at: https://localhost:8080
# Username: admin
# Password: (from command above)
```

### Configure ArgoCD Application

1. **Update the repository URL** in `argocd/application.yaml`:
   ```yaml
   source:
     repoURL: https://github.com/michaelgameel5/scanning_container_trivy.git
   ```

2. **Apply the ArgoCD Application**:
   ```bash
   kubectl apply -f argocd/application.yaml
   ```

3. **Verify in ArgoCD UI** - The application should appear and sync automatically.

## 📝 API Usage

### Submit a Scan

```bash
# Using curl
curl -X POST http://localhost:30080/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:latest"}'

# Response
{
  "id": 1,
  "image_name": "nginx:latest",
  "job_name": "scan-a1b2c3d4",
  "status": "pending",
  "message": "Scan queued successfully. Job 'scan-a1b2c3d4' will process the image."
}
```

### List All Scans

```bash
curl http://localhost:30080/scans
```

### Get Scan Details

```bash
curl http://localhost:30080/scan/1
```

### Get Dashboard Statistics

```bash
curl http://localhost:30080/stats
```

### API Documentation

Interactive API documentation is available at:
- **Swagger UI**: http://localhost:30080/docs
- **ReDoc**: http://localhost:30080/redoc

## 🧪 Test Vulnerable Images

Use these images to test the scanner (they contain known vulnerabilities):

```bash
# DVWA - Damn Vulnerable Web Application
curl -X POST http://localhost:30080/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "vulnerables/web-dvwa:latest"}'

# Old nginx version
curl -X POST http://localhost:30080/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:1.16"}'

# Python 3.8 slim
curl -X POST http://localhost:30080/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "python:3.8-slim"}'

# Alpine with vulnerabilities
curl -X POST http://localhost:30080/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "alpine:3.10"}'

# Node.js old version
curl -X POST http://localhost:30080/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "node:14-alpine"}'
```

## 🗄️ Database Schema

```sql
-- Images table
CREATE TABLE images (
    id SERIAL PRIMARY KEY,
    name VARCHAR(512) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Scans table
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    image_id INTEGER REFERENCES images(id) ON DELETE CASCADE,
    job_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    error_message TEXT,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    unknown_count INTEGER DEFAULT 0,
    total_count INTEGER DEFAULT 0
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_id VARCHAR(64) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    installed_version VARCHAR(128),
    fixed_version VARCHAR(128),
    title TEXT,
    description TEXT,
    target VARCHAR(512),
    pkg_type VARCHAR(64)
);
```

## 📁 Project Structure

```
container-vuln-scanner/
│
├── api/                          # FastAPI Backend
│   ├── main.py                   # API endpoints and K8s job creation
│   ├── database.py               # SQLAlchemy configuration
│   ├── models.py                 # ORM models
│   ├── schemas.py                # Pydantic schemas
│   ├── requirements.txt          # Python dependencies
│   └── Dockerfile                # API container image
│
├── worker/                       # Scanner Worker
│   ├── scan.py                   # Trivy execution and result parsing
│   └── Dockerfile                # Worker container image (based on Trivy)
│
├── dashboard/                    # Web Dashboard
│   ├── index.html                # Single-page application
│   ├── nginx.conf                # nginx configuration with API proxy
│   └── Dockerfile                # Dashboard container image
│
├── k8s/                          # Kubernetes Manifests
│   ├── postgres.yaml             # PostgreSQL deployment + service
│   ├── api.yaml                  # API deployment + RBAC + services
│   ├── worker-job.yaml           # Worker job template (reference)
│   └── dashboard.yaml            # Dashboard deployment + services
│
├── argocd/                       # ArgoCD Configuration
│   └── application.yaml          # ArgoCD Application manifest
│
└── README.md                     # This file
```

## 🔒 Security Considerations

### Implemented Security Measures

1. **Secrets Management**
   - Database credentials stored in Kubernetes Secrets
   - Environment variables for sensitive configuration

2. **RBAC (Role-Based Access Control)**
   - API service has minimal permissions to create Jobs only
   - Principle of least privilege applied

3. **Network Security**
   - PostgreSQL accessible only within the cluster (ClusterIP)
   - API exposed via NodePort for development only

4. **Input Validation**
   - Image names validated against injection attacks
   - Pydantic schemas for request validation

5. **Container Security**
   - Non-root user execution where possible
   - Minimal base images (Alpine, slim variants)
   - Resource limits prevent DoS

### Production Recommendations

For production deployment, consider:

- [ ] Use external secret management (HashiCorp Vault, AWS Secrets Manager)
- [ ] Enable TLS/HTTPS with cert-manager
- [ ] Add authentication/authorization (OAuth2, OIDC)
- [ ] Use Ingress instead of NodePort
- [ ] Enable PostgreSQL replication for HA
- [ ] Add network policies for pod-to-pod communication
- [ ] Implement rate limiting on API
- [ ] Set up monitoring with Prometheus/Grafana
- [ ] Configure log aggregation (EFK stack)

## 🛠️ Troubleshooting

### Common Issues

**1. Pods not starting**
```bash
# Check pod status
kubectl get pods

# View pod events
kubectl describe pod <pod-name>

# View logs
kubectl logs <pod-name>
```

**2. Database connection issues**
```bash
# Check PostgreSQL is running
kubectl get pods -l component=database

# View PostgreSQL logs
kubectl logs -l component=database
```

**3. Scanner jobs failing**
```bash
# List scan jobs
kubectl get jobs

# View job logs
kubectl logs job/<job-name>
```

**4. Images not loading in KinD**
```bash
# Verify images are loaded
docker exec -it vuln-scanner-control-plane crictl images
```

### Reset Everything

```bash
# Delete all resources
kubectl delete -f k8s/

# Delete PVC (WARNING: Deletes all data)
kubectl delete pvc postgres-pvc

# Delete KinD cluster
kind delete cluster --name vuln-scanner
```

## 📊 Monitoring

### View Scan Jobs

```bash
# Watch jobs in real-time
kubectl get jobs -w

# View all pods including completed jobs
kubectl get pods --show-all
```

### Database Queries

```bash
# Connect to PostgreSQL
kubectl exec -it $(kubectl get pod -l component=database -o jsonpath='{.items[0].metadata.name}') -- psql -U vulnscanner -d vulnscanner

# View recent scans
SELECT s.id, i.name, s.status, s.total_count FROM scans s JOIN images i ON s.image_id = i.id ORDER BY s.created_at DESC LIMIT 10;

# View vulnerability summary
SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity ORDER BY severity;
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanner by Aqua Security
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [ArgoCD](https://argo-cd.readthedocs.io/) - GitOps continuous delivery
- [KinD](https://kind.sigs.k8s.io/) - Kubernetes in Docker

---

**Built with ❤️ for the DevSecOps community**
