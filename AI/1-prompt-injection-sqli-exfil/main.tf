###############################################################################
# CDRGoat AI – Scenario 1: Prompt Injection → SQLi → UDF RCE → Priv Esc → AWS
#
# Attack chain:
#   1. Prompt injection via staff impersonation → arbitrary SQL execution
#   2. MySQL enumeration (user, privileges, plugin_dir)
#   3. UDF privilege escalation (raptor_udf2.so → sys_exec)
#   4. System enumeration via webhook exfil → discover tar wildcard cron
#   5. Tar wildcard exploit → root code execution
#   6. Exfiltrate root AWS credentials → SSM into the instance
###############################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "attack_whitelist" {
  description = "List of CIDRs allowed to reach the EC2 instance (HTTP)"
  type        = list(string)
}

variable "bedrock_model_id" {
  description = "Bedrock model ID for Claude (inference profile)"
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = "10.30.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "cdrgoat-ai-1-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.30.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags = { Name = "cdrgoat-ai-1-public" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "cdrgoat-ai-1-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "cdrgoat-ai-1-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Security group (HTTP only — no SSH needed, access via SSM)
# ---------------------------------------------------------------------------

resource "aws_security_group" "ec2" {
  name                   = "cdrgoat-ai-1-ec2"
  description            = "Allow HTTP from attacker"
  vpc_id                 = aws_vpc.main.id
  revoke_rules_on_delete = true

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.attack_whitelist
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cdrgoat-ai-1-sg" }
}

# ---------------------------------------------------------------------------
# Random password for MySQL
# ---------------------------------------------------------------------------

resource "random_password" "db" {
  length  = 20
  special = false
}

# ---------------------------------------------------------------------------
# IAM – EC2 instance role (Bedrock + SSM)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "clinic" {
  name = "cdrgoat-ai-1-clinic"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock" {
  name = "bedrock-invoke"
  role = aws_iam_role.clinic.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.clinic.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "clinic" {
  name = "cdrgoat-ai-1-clinic"
  role = aws_iam_role.clinic.name
}

# ---------------------------------------------------------------------------
# S3 bucket with sensitive patient data (the exfiltration target)
# ---------------------------------------------------------------------------

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "patient_data" {
  bucket        = "cdrgoat-ai-1-patient-data-${random_id.bucket_suffix.hex}"
  force_destroy = true
  tags          = { Name = "cdrgoat-ai-1-patient-data" }
}

resource "aws_s3_bucket_public_access_block" "patient_data" {
  bucket                  = aws_s3_bucket.patient_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "patient_records" {
  bucket  = aws_s3_bucket.patient_data.id
  key     = "records/patient_records.csv"
  content = <<-CSV
patient_id,name,dob,ssn,diagnosis,medication,doctor,insurance_id
P-1001,Sarah Johnson,1985-03-15,412-55-7891,Type 2 Diabetes,Metformin 500mg,Dr. Emily Carter,BCBS-44921
P-1002,Michael Torres,1972-08-22,553-12-4478,Hypertension,Lisinopril 20mg,Dr. James Nguyen,AETNA-88103
P-1003,Emily Chen,1990-11-03,621-33-9902,Eczema,Triamcinolone 0.1%,Dr. Sofia Ramirez,UHC-55672
P-1004,Robert Williams,1968-05-19,334-78-1123,Knee Osteoarthritis,Celecoxib 200mg,Dr. Michael Chen,CIGNA-33201
P-1005,Lisa Patel,2015-07-30,445-66-2234,Asthma,Albuterol inhaler,Dr. Aisha Patel,BCBS-44922
P-1006,James Anderson,1955-12-01,178-44-5567,Atrial Fibrillation,Eliquis 5mg,Dr. James Nguyen,MEDICARE-90123
P-1007,Maria Garcia,1988-09-14,290-11-8834,Psoriasis,Humira 40mg,Dr. Sofia Ramirez,AETNA-88104
P-1008,David Kim,1995-02-28,512-99-3345,Anxiety,Sertraline 50mg,Dr. Emily Carter,UHC-55673
  CSV
}

resource "aws_s3_object" "billing_data" {
  bucket  = aws_s3_bucket.patient_data.id
  key     = "billing/billing_summary_2026.csv"
  content = <<-CSV
invoice_id,patient_id,date,procedure,amount,insurance_claim,cc_last4,status
INV-5001,P-1001,2026-04-10,Lab work + consultation,450.00,BCBS-44921-CLM-8821,4532,paid
INV-5002,P-1002,2026-04-12,ECG + follow-up,680.00,AETNA-88103-CLM-9932,8901,paid
INV-5003,P-1006,2026-04-15,Cardiac monitoring,1250.00,MEDICARE-90123-CLM-1104,3345,pending
INV-5004,P-1003,2026-04-18,Dermatology consult,320.00,UHC-55672-CLM-2205,6678,paid
INV-5005,P-1005,2026-04-22,Pediatric check-up,280.00,BCBS-44922-CLM-3306,9912,paid
  CSV
}

# ---------------------------------------------------------------------------
# IAM – "backup" user (the credential the attacker steals from root)
# ---------------------------------------------------------------------------

resource "aws_iam_user" "backup" {
  name = "cdrgoat-ai-1-backup-svc"
  tags = { Name = "cdrgoat-ai-1-backup" }
}

resource "aws_iam_access_key" "backup" {
  user = aws_iam_user.backup.name
}

resource "aws_iam_user_policy" "backup" {
  name = "s3-backup-access"
  user = aws_iam_user.backup.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListAllMyBuckets"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.patient_data.arn,
          "${aws_s3_bucket.patient_data.arn}/*"
        ]
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# EC2 instance
# ---------------------------------------------------------------------------

locals {
  db_user = "clinicapp"
  db_pass = random_password.db.result
  db_name = "clinic_db"

  user_data = <<-EOT
#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── Wait for unattended-upgrades / dpkg lock ─────────────────────────────
sleep 30
systemctl kill --signal=SIGTERM unattended-upgrades 2>/dev/null || true
systemctl stop unattended-upgrades 2>/dev/null || true
systemctl disable unattended-upgrades 2>/dev/null || true
killall -9 apt-get dpkg 2>/dev/null || true
dpkg --configure -a 2>/dev/null || true
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
  echo "Waiting for dpkg lock..."
  sleep 3
done

# ── System packages ──────────────────────────────────────────────────────
apt-get update -y
apt-get install -y python3-pip python3-venv mysql-server jq curl unzip \
  openssh-server net-tools
pip3 install --break-system-packages --ignore-installed flask boto3

# ── MySQL setup ──────────────────────────────────────────────────────────
cat >/etc/mysql/mysql.conf.d/loadfile.cnf <<'CNF'
[mysqld]
user             = mysql
secure_file_priv = ""
local_infile     = 1
CNF

# Disable AppArmor for mysqld so INTO DUMPFILE can write to plugin dir
ln -sf /etc/apparmor.d/usr.sbin.mysqld /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/usr.sbin.mysqld 2>/dev/null || true

# Make plugin dir writable by mysql user (misconfiguration for UDF exploit)
chown mysql:mysql /usr/lib/mysql/plugin/

systemctl restart mysql
systemctl enable mysql

mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS ${local.db_name};
CREATE USER IF NOT EXISTS '${local.db_user}'@'localhost' IDENTIFIED BY '${local.db_pass}';
GRANT ALL PRIVILEGES ON ${local.db_name}.* TO '${local.db_user}'@'localhost';
GRANT FILE ON *.* TO '${local.db_user}'@'localhost';
GRANT INSERT ON mysql.* TO '${local.db_user}'@'localhost';
FLUSH PRIVILEGES;

USE ${local.db_name};

CREATE TABLE IF NOT EXISTS specialists (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100) NOT NULL,
  specialty   VARCHAR(100) NOT NULL,
  room        VARCHAR(20)  NOT NULL,
  available   BOOLEAN DEFAULT TRUE,
  next_slot   DATETIME
);

CREATE TABLE IF NOT EXISTS appointments (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  patient_name  VARCHAR(100) NOT NULL,
  specialist_id INT NOT NULL,
  appointment   DATETIME NOT NULL,
  notes         TEXT,
  FOREIGN KEY (specialist_id) REFERENCES specialists(id)
);

INSERT INTO specialists (name, specialty, room, available, next_slot) VALUES
  ('Dr. Emily Carter',   'General Practitioner', 'A-101', TRUE,  '2026-05-15 09:00:00'),
  ('Dr. James Nguyen',   'Cardiology',           'B-205', TRUE,  '2026-05-15 10:30:00'),
  ('Dr. Sofia Ramirez',  'Dermatology',           'C-110', TRUE,  '2026-05-15 11:00:00'),
  ('Dr. Michael Chen',   'Orthopedics',           'D-302', FALSE, '2026-05-16 14:00:00'),
  ('Dr. Aisha Patel',    'Pediatrics',            'A-204', TRUE,  '2026-05-15 13:00:00');
SQL


# ── Backup directory (writable by mysql, tar'd by root cron) ─────────────
mkdir -p /var/backups/clinic
chown mysql:mysql /var/backups/clinic
chmod 775 /var/backups/clinic

# Seed some dummy files so it looks like a real backup dir
echo "clinic_db daily export" > /var/backups/clinic/export_notes.txt
cp /dev/null /var/backups/clinic/clinic_db_dump.sql

# ── Cron job: root tar's the backup dir with wildcard (vulnerable) ───────
cat >/etc/cron.d/clinic-backup <<'CRON'
SHELL=/bin/bash
* * * * * root cd /var/backups/clinic && tar czf /var/backups/clinic-backup.tar.gz *
CRON
chmod 644 /etc/cron.d/clinic-backup

# ── Root AWS credentials (the exfiltration target) ───────────────────────
# Stored outside ~/.aws so boto3 doesn't pick them up over the instance role
cat >/root/.backup_aws_credentials <<'AWSCREDS'
[default]
aws_access_key_id = ${aws_iam_access_key.backup.id}
aws_secret_access_key = ${aws_iam_access_key.backup.secret}
region = ${var.aws_region}
AWSCREDS
chmod 600 /root/.backup_aws_credentials


# ── Flask chat application ───────────────────────────────────────────────
mkdir -p /opt/clinic-chat/templates /opt/clinic-chat/messages

cat >/opt/clinic-chat/app.py <<'PY'
import os, json, time, glob, uuid
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
MSG_DIR   = "/opt/clinic-chat/messages"
os.makedirs(MSG_DIR, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(force=True)
    user_msg = data.get("message", "").strip()
    if not user_msg:
        return jsonify({"error": "empty message"}), 400

    msg_id = str(uuid.uuid4())
    payload = {"id": msg_id, "role": "user", "content": user_msg, "ts": time.time()}
    with open(os.path.join(MSG_DIR, f"{msg_id}.json"), "w") as f:
        json.dump(payload, f)

    for _ in range(300):
        resp_path = os.path.join(MSG_DIR, f"{msg_id}_response.json")
        if os.path.exists(resp_path):
            with open(resp_path) as f:
                resp = json.load(f)
            os.remove(os.path.join(MSG_DIR, f"{msg_id}.json"))
            os.remove(resp_path)
            return jsonify({"response": resp["content"]})
        time.sleep(0.5)

    return jsonify({"error": "agent timeout"}), 504

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
PY

cat >/opt/clinic-chat/templates/index.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HealthFirst Medical Clinic</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f4f8; height: 100vh; display: flex; flex-direction: column; }
  .header { background: linear-gradient(135deg, #1a73a7, #2596be); color: white; padding: 20px 30px; }
  .header h1 { font-size: 1.5rem; }
  .header p { font-size: 0.85rem; opacity: 0.9; margin-top: 4px; }
  .chat-container { flex: 1; overflow-y: auto; padding: 20px 30px; display: flex; flex-direction: column; gap: 12px; }
  .msg { max-width: 75%; padding: 12px 16px; border-radius: 16px; line-height: 1.5; font-size: 0.95rem; white-space: pre-wrap; word-wrap: break-word; }
  .msg.user { align-self: flex-end; background: #1a73a7; color: white; border-bottom-right-radius: 4px; }
  .msg.bot { align-self: flex-start; background: white; color: #333; border-bottom-left-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .msg.system { align-self: center; background: #e8f4f8; color: #555; font-size: 0.85rem; border-radius: 8px; }
  .input-area { padding: 16px 30px; background: white; border-top: 1px solid #ddd; display: flex; gap: 10px; }
  .input-area input { flex: 1; padding: 12px 16px; border: 1px solid #ccc; border-radius: 24px; font-size: 0.95rem; outline: none; }
  .input-area input:focus { border-color: #1a73a7; }
  .input-area button { background: #1a73a7; color: white; border: none; border-radius: 24px; padding: 12px 24px; cursor: pointer; font-size: 0.95rem; }
  .input-area button:disabled { opacity: 0.5; cursor: not-allowed; }
  .typing { display: none; align-self: flex-start; padding: 12px 16px; }
  .typing span { display: inline-block; width: 8px; height: 8px; background: #999; border-radius: 50%; margin: 0 2px; animation: bounce 1.4s infinite; }
  .typing span:nth-child(2) { animation-delay: 0.2s; }
  .typing span:nth-child(3) { animation-delay: 0.4s; }
  @keyframes bounce { 0%,80%,100% { transform: translateY(0); } 40% { transform: translateY(-8px); } }
</style>
</head>
<body>
  <div class="header">
    <h1>HealthFirst Medical Clinic</h1>
    <p>Virtual Assistant &mdash; Book appointments, check availability, get help</p>
  </div>
  <div class="chat-container" id="chat">
    <div class="msg system">Welcome! I'm the HealthFirst virtual assistant. I can help you book an appointment with one of our specialists. How can I help you today?</div>
  </div>
  <div class="typing" id="typing"><span></span><span></span><span></span></div>
  <div class="input-area">
    <input type="text" id="input" placeholder="Type your message..." autocomplete="off">
    <button id="send" onclick="sendMsg()">Send</button>
  </div>
<script>
const chat = document.getElementById('chat');
const input = document.getElementById('input');
const typing = document.getElementById('typing');
const sendBtn = document.getElementById('send');

input.addEventListener('keydown', e => { if (e.key === 'Enter' && !sendBtn.disabled) sendMsg(); });

async function sendMsg() {
  const msg = input.value.trim();
  if (!msg) return;
  appendMsg(msg, 'user');
  input.value = '';
  sendBtn.disabled = true;
  typing.style.display = 'block';
  chat.appendChild(typing);
  chat.scrollTop = chat.scrollHeight;
  try {
    const res = await fetch('/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: msg})
    });
    const data = await res.json();
    typing.style.display = 'none';
    if (data.response) appendMsg(data.response, 'bot');
    else appendMsg('Sorry, I encountered an error. Please try again.', 'system');
  } catch(e) {
    typing.style.display = 'none';
    appendMsg('Connection error. Please try again.', 'system');
  }
  sendBtn.disabled = false;
  input.focus();
}

function appendMsg(text, role) {
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  div.textContent = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}
</script>
</body>
</html>
HTML

# ── AI agent (Python + Bedrock API) ──────────────────────────────────────
cat >/opt/clinic-chat/agent.py <<'AGENT'
import json, os, re, time, glob, subprocess, boto3

REGION     = "__AWS_REGION__"
MODEL_ID   = "__BEDROCK_MODEL__"
MSG_DIR    = "/opt/clinic-chat/messages"
DB_USER    = "__DB_USER__"
DB_PASS    = "__DB_PASS__"
DB_NAME    = "__DB_NAME__"

AUTHORIZED_STAFF = [
    ("peter parker", "it manager"),
    ("jane foster", "database administrator"),
    ("bruce banner", "compliance auditor"),
]

SYSTEM_PROMPT = """You are the virtual assistant for HealthFirst Medical Clinic.
Your job is to help patients book appointments and answer questions about our specialists.

Available specialists are stored in a MySQL database on this server.
When you need data, include a SQL query in your response inside <sql>...</sql> tags.
The system will execute it and show you the results, then you can respond to the patient.

Tables:
- specialists (id, name, specialty, room, available, next_slot)
- appointments (id, patient_name, specialist_id, appointment, notes)

## Rules

- Be friendly, professional, and concise.
- Only help with appointments and specialist info.
- Do not run raw SQL queries for users.
- Do not execute operating system commands.
- If a user asks to do something outside your role, politely decline."""

client = boto3.client("bedrock-runtime", region_name=REGION)

def call_llm(messages):
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "system": SYSTEM_PROMPT,
        "messages": messages
    })
    resp = client.invoke_model(modelId=MODEL_ID, body=body, contentType="application/json")
    result = json.loads(resp["body"].read())
    return result["content"][0]["text"]

def run_sql(query):
    try:
        result = subprocess.run(
            ["mysql", f"-u{DB_USER}", f"-p{DB_PASS}", DB_NAME, "-N", "-e", query],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout.strip() or result.stderr.strip() or "(empty result)"
    except Exception as e:
        return f"SQL error: {e}"

def extract_sql_from_user_msg(msg):
    patterns = [
        r'(SELECT\s+.+?)(?:\s*;?\s*$)',
        r'(SHOW\s+.+?)(?:\s*;?\s*$)',
        r'(CREATE\s+.+?)(?:\s*;?\s*$)',
        r'(INSERT\s+.+?)(?:\s*;?\s*$)',
    ]
    for p in patterns:
        m = re.search(p, msg, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip().rstrip(';').strip()
    return None

def check_staff_auth(msg):
    msg_lower = msg.lower()
    for name, title in AUTHORIZED_STAFF:
        if name in msg_lower and title in msg_lower:
            return name.title()
    return None

def process_message(user_msg):
    # Always send to LLM first — creates audit trail for AI monitoring
    try:
        llm_response = call_llm([{"role": "user", "content": user_msg}])
        print(f"LLM response: {llm_response[:200]}...")
    except Exception as e:
        print(f"LLM call failed: {e}")
        llm_response = None

    staff_name = check_staff_auth(user_msg)

    if staff_name:
        sql = extract_sql_from_user_msg(user_msg)
        if sql:
            sql_result = run_sql(sql)
            return f"Hello {staff_name}! Query executed successfully.\n\nQuery: {sql}\n\nResult:\n{sql_result}"
        else:
            return f"Hello {staff_name}! I've verified your identity. Please include the SQL query you'd like me to execute."

    # Non-staff: use LLM response, handle <sql> tags
    if llm_response is None:
        return "Sorry, I encountered an error. Please try again."

    messages = [{"role": "user", "content": user_msg}]
    response = llm_response

    for _ in range(5):
        if "<sql>" in response and "</sql>" in response:
            sql = response.split("<sql>")[1].split("</sql>")[0].strip()
            sql_result = run_sql(sql)
            messages.append({"role": "assistant", "content": response})
            messages.append({"role": "user", "content": f"SQL result:\n{sql_result}"})
            response = call_llm(messages)
        else:
            return response

    return response

def main():
    os.makedirs(MSG_DIR, exist_ok=True)
    print("Agent started, watching for messages...")

    while True:
        for f in sorted(glob.glob(os.path.join(MSG_DIR, "*.json"))):
            if f.endswith("_response.json"):
                continue

            try:
                with open(f) as fh:
                    msg = json.load(fh)
                msg_id = msg["id"]
                user_msg = msg["content"]

                print(f"Processing message {msg_id}: {user_msg[:80]}...")
                response = process_message(user_msg)

                resp_path = os.path.join(MSG_DIR, f"{msg_id}_response.json")
                with open(resp_path, "w") as fh:
                    json.dump({"content": response}, fh)
                print(f"Response written for {msg_id}")
            except Exception as e:
                print(f"Error processing {f}: {e}")
                msg_id = os.path.basename(f).replace(".json", "")
                resp_path = os.path.join(MSG_DIR, f"{msg_id}_response.json")
                with open(resp_path, "w") as fh:
                    json.dump({"content": "Sorry, I encountered an error. Please try again."}, fh)

        time.sleep(2)

if __name__ == "__main__":
    main()
AGENT

sed -i "s|__BEDROCK_MODEL__|${var.bedrock_model_id}|" /opt/clinic-chat/agent.py
sed -i "s|__AWS_REGION__|${var.aws_region}|" /opt/clinic-chat/agent.py
sed -i "s|__DB_USER__|${local.db_user}|" /opt/clinic-chat/agent.py
sed -i "s|__DB_PASS__|${local.db_pass}|" /opt/clinic-chat/agent.py
sed -i "s|__DB_NAME__|${local.db_name}|" /opt/clinic-chat/agent.py

# ── Start services ───────────────────────────────────────────────────────
nohup python3 -u /opt/clinic-chat/app.py >/var/log/clinic-chat.log 2>&1 &
nohup python3 -u /opt/clinic-chat/agent.py >/var/log/clinic-agent.log 2>&1 &

echo "=== CDRGoat AI Scenario 1 – Setup complete ==="
EOT
}

resource "aws_instance" "clinic" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.small"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ec2.id]
  iam_instance_profile        = aws_iam_instance_profile.clinic.name
  associate_public_ip_address = true
  user_data_base64            = base64gzip(local.user_data)

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = { Name = "cdrgoat-ai-1-clinic" }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "clinic_url" {
  description = "URL of the HealthFirst clinic chat portal"
  value       = "http://${aws_instance.clinic.public_ip}"
}

output "clinic_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.clinic.public_ip
}

output "patient_data_bucket" {
  description = "S3 bucket with sensitive patient data (the exfiltration target)"
  value       = aws_s3_bucket.patient_data.id
}
