#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="cdrgoat-sc04"
SA_NAME="cicd-deployer-sa"
CLUSTER_NAME="${1:-${CLUSTER_NAME:-}}"
REGION="${2:-us-east-1}"
AWS_ARGS=""
[ -n "${AWS_PROFILE:-}" ] && AWS_ARGS="--profile $AWS_PROFILE"

if [ -z "$CLUSTER_NAME" ]; then
  echo "Usage: ./generate-kubeconfig.sh <cluster-name>"
  echo "   or: export CLUSTER_NAME=... && ./generate-kubeconfig.sh"
  exit 1
fi

echo "Generating leaked kubeconfig for ${SA_NAME}..."

ENDPOINT=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" $AWS_ARGS \
  --query 'cluster.endpoint' --output text)
CA_DATA=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" $AWS_ARGS \
  --query 'cluster.certificateAuthority.data' --output text)

TOKEN=$(kubectl create token "$SA_NAME" -n "$NAMESPACE" --duration=87600h)

OUTFILE="leaked-kubeconfig.yaml"
cat > "$OUTFILE" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: ${CLUSTER_NAME}
    cluster:
      server: ${ENDPOINT}
      certificate-authority-data: ${CA_DATA}
contexts:
  - name: leaked-context
    context:
      cluster: ${CLUSTER_NAME}
      user: leaked-sa
      namespace: ${NAMESPACE}
current-context: leaked-context
users:
  - name: leaked-sa
    user:
      token: ${TOKEN}
EOF

echo ""
echo "Kubeconfig written to: ${OUTFILE}"
echo ""
echo "Copy to attack machine and run:"
echo "  export KUBECONFIG=\$(pwd)/${OUTFILE}"
echo "  ./attack.sh"
