#!/usr/bin/env bash
set -euo pipefail

# Generate a "leaked" kubeconfig for the dev-deployer SA
# This simulates a kubeconfig accidentally exposed in a public repo

NAMESPACE="cdrgoat-sc03"
SA_NAME="dev-deployer-sa"
CLUSTER_NAME="${1:-${CLUSTER_NAME:-scanner-test}}"
REGION="${2:-us-east-1}"
AWS_ARGS=""
[ -n "${AWS_PROFILE:-}" ] && AWS_ARGS="--profile $AWS_PROFILE"

echo "Generating leaked kubeconfig for ${SA_NAME}..."

# Get cluster endpoint and CA
ENDPOINT=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" $AWS_ARGS \
  --query 'cluster.endpoint' --output text)
CA_DATA=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" $AWS_ARGS \
  --query 'cluster.certificateAuthority.data' --output text)

# Generate a long-lived token for the SA
TOKEN=$(kubectl create token "$SA_NAME" -n "$NAMESPACE" --duration=87600h)

# Write the kubeconfig
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
echo "Simulate the attacker:"
echo "  export KUBECONFIG=\$(pwd)/${OUTFILE}"
echo "  kubectl get pods -n ${NAMESPACE}"
echo ""
echo "Or pass it to attack.sh which will prompt for the path."
