#!/usr/bin/env bash
set -euo pipefail

# Setup script: annotates the SA with IRSA role and restarts the pod
# Run after: kubectl apply -f deploy.yaml && terraform apply

NAMESPACE="cdrgoat-sc03"
SA_NAME="dev-deployer-sa"
POD_NAME="backend-app"

echo "[1/4] Getting IRSA role ARN from terraform output..."
IRSA_ARN=$(terraform output -raw irsa_role_arn)
echo "  Role: ${IRSA_ARN}"

echo "[2/4] Annotating SA with IRSA role..."
kubectl annotate sa "$SA_NAME" -n "$NAMESPACE" \
  "eks.amazonaws.com/role-arn=${IRSA_ARN}" --overwrite
echo "  Done"

echo "[3/4] Restarting pod to pick up IRSA credentials..."
kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found
kubectl apply -f deploy.yaml
echo "  Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/"$POD_NAME" -n "$NAMESPACE" --timeout=120s

echo "[4/4] Generating leaked kubeconfig..."
./generate-kubeconfig.sh "$@"

echo ""
echo "Setup complete. Run ./attack.sh to start the attack."
