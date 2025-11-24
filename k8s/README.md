# Virtual HSM Kubernetes Deployment

This directory contains Kubernetes manifests for deploying Virtual HSM in a Kubernetes cluster, with full support for secrets management via Kubernetes Secrets, HashiCorp Vault, and minikube.

## Quick Start with Minikube

```bash
cd k8s
./minikube-setup.sh
```

## Manual Deployment

### 1. Create Namespace
```bash
kubectl apply -f namespace.yaml
```

### 2. Create Secrets

#### Option A: Using Kubernetes Secrets
```bash
kubectl create secret generic vhsm-secrets \
  --from-literal=master-key=$(openssl rand -hex 32) \
  --from-literal=admin-password=$(openssl rand -base64 32) \
  --namespace=vhsm
```

#### Option B: Using HashiCorp Vault
```bash
# Store secrets in Vault
vault kv put secret/vhsm/master-key key=$(openssl rand -hex 32)
vault kv put secret/vhsm/admin-password password=$(openssl rand -base64 32)

# Deploy with Vault integration
kubectl apply -f vault-integration.yaml
```

### 3. Apply Configuration
```bash
kubectl apply -f configmap.yaml
kubectl apply -f rbac.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f networkpolicy.yaml
```

### 4. Verify Deployment
```bash
kubectl get pods -n vhsm
kubectl get svc -n vhsm
```

## Accessing the Service

### Port Forward
```bash
kubectl port-forward -n vhsm service/vhsm-service 8443:8443
curl -k https://localhost:8443/api/version
```

### Load Balancer (if supported)
```bash
kubectl get svc -n vhsm vhsm-loadbalancer
# Use the EXTERNAL-IP provided
```

### Minikube
```bash
minikube service vhsm-service -n vhsm --url
```

## Secrets Management Options

### 1. Kubernetes Secrets (Default)
- Secrets stored in etcd (encrypted at rest recommended)
- Simple to use, built into Kubernetes
- See `secrets.yaml` template

### 2. HashiCorp Vault
- Enterprise-grade secrets management
- Dynamic secrets, encryption as a service
- See `vault-integration.yaml` for setup

### 3. AWS Secrets Manager
```yaml
# Install AWS Secrets Manager CSI driver
# https://github.com/aws/secrets-store-csi-driver-provider-aws

apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vhsm-aws-secrets
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "vhsm-master-key"
        objectType: "secretsmanager"
      - objectName: "vhsm-admin-password"
        objectType: "secretsmanager"
```

### 4. Azure Key Vault
```yaml
# Install Azure Key Vault provider
# https://azure.github.io/secrets-store-csi-driver-provider-azure/

apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vhsm-azure-keyvault
spec:
  provider: azure
  parameters:
    keyvaultName: "your-keyvault-name"
    objects: |
      array:
        - objectName: vhsm-master-key
          objectType: secret
        - objectName: vhsm-admin-password
          objectType: secret
```

### 5. Google Secret Manager
```yaml
# Install Google Secret Manager CSI driver

apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vhsm-gcp-secrets
spec:
  provider: gcp
  parameters:
    secrets: |
      - resourceName: "projects/PROJECT_ID/secrets/vhsm-master-key/versions/latest"
        path: "master-key"
      - resourceName: "projects/PROJECT_ID/secrets/vhsm-admin-password/versions/latest"
        path: "admin-password"
```

## Security Features

### Pod Security
- Non-root user execution
- Read-only root filesystem
- No privilege escalation
- Minimal capabilities
- Seccomp profile

### Network Security
- NetworkPolicy enforcement
- TLS encryption required
- Security headers enabled
- CORS restrictions

### Resource Management
- CPU and memory limits
- Disk space quotas
- Request rate limiting

## Monitoring and Health Checks

### Liveness Probe
Checks if the container is running:
```bash
https://localhost:8443/api/health
```

### Readiness Probe
Checks if the container is ready to serve traffic:
```bash
https://localhost:8443/api/health
```

### Metrics
```bash
kubectl top pods -n vhsm
kubectl top nodes
```

## Scaling

### Manual Scaling
```bash
kubectl scale deployment vhsm-server --replicas=3 -n vhsm
```

### Horizontal Pod Autoscaler
```bash
kubectl autoscale deployment vhsm-server \
  --cpu-percent=70 \
  --min=2 \
  --max=10 \
  -n vhsm
```

## Backup and Restore

### Backup Storage
```bash
kubectl exec -n vhsm deployment/vhsm-server -- tar czf - /app/storage > vhsm-backup.tar.gz
```

### Restore Storage
```bash
kubectl exec -n vhsm deployment/vhsm-server -- tar xzf - -C / < vhsm-backup.tar.gz
```

## Troubleshooting

### Check Logs
```bash
kubectl logs -n vhsm deployment/vhsm-server -f
```

### Debug Pod
```bash
kubectl exec -it -n vhsm deployment/vhsm-server -- /bin/bash
```

### Check Events
```bash
kubectl get events -n vhsm --sort-by='.lastTimestamp'
```

## Clean Up

```bash
kubectl delete namespace vhsm
```

## Production Recommendations

1. **Enable etcd encryption at rest**
2. **Use external secrets management (Vault, AWS/Azure/GCP)**
3. **Enable audit logging**
4. **Configure pod security policies/admission controllers**
5. **Use network policies to restrict traffic**
6. **Enable TLS for all communications**
7. **Regular security updates and patching**
8. **Implement backup and disaster recovery**
9. **Monitor and alert on security events**
10. **Regular security audits and penetration testing**
