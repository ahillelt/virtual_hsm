#!/bin/bash
# Minikube setup script for Virtual HSM

set -e

echo "========================================="
echo "Virtual HSM Minikube Setup"
echo "========================================="

# Check if minikube is installed
if ! command -v minikube &> /dev/null; then
    echo "Error: minikube is not installed"
    echo "Install from: https://minikube.sigs.k8s.io/docs/start/"
    exit 1
fi

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed"
    exit 1
fi

# Start minikube if not running
if ! minikube status | grep -q "Running"; then
    echo "Starting minikube..."
    minikube start --driver=docker --memory=4096 --cpus=2
fi

# Enable required addons
echo "Enabling minikube addons..."
minikube addons enable ingress
minikube addons enable metrics-server
minikube addons enable storage-provisioner

# Build Docker image in minikube's Docker environment
echo "Building Virtual HSM Docker image..."
eval $(minikube docker-env)
cd ..
docker build -t virtual-hsm:latest .

# Create namespace
echo "Creating vhsm namespace..."
kubectl create namespace vhsm --dry-run=client -o yaml | kubectl apply -f -

# Generate secrets
echo "Generating secure secrets..."
MASTER_KEY=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -base64 32)

kubectl create secret generic vhsm-secrets \
  --from-literal=master-key="$MASTER_KEY" \
  --from-literal=admin-password="$ADMIN_PASSWORD" \
  --namespace=vhsm \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Master Key: $MASTER_KEY"
echo "Admin Password: $ADMIN_PASSWORD"
echo "IMPORTANT: Save these credentials securely!"

# Apply Kubernetes manifests
echo "Applying Kubernetes manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/networkpolicy.yaml

# Wait for deployment
echo "Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=120s deployment/vhsm-server -n vhsm

# Get service URL
echo ""
echo "========================================="
echo "Deployment Complete!"
echo "========================================="
echo ""
echo "Access the service:"
echo "  minikube service vhsm-service -n vhsm --url"
echo ""
echo "Or use port-forward:"
echo "  kubectl port-forward -n vhsm service/vhsm-service 8443:8443"
echo ""
echo "Test the API:"
echo "  curl -k https://localhost:8443/api/version"
echo ""
