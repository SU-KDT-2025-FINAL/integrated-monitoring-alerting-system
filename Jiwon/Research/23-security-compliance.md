# 보안 및 컴플라이언스 (Phase 2-3)

## 개요
모니터링 시스템의 보안 강화, 컴플라이언스 준수, 데이터 보호를 위한 종합적인 보안 아키텍처와 구현 방법을 학습합니다.

## 1. 인증 및 권한 부여

### 1.1 TLS/SSL 암호화

**인증서 관리 (cert-manager)**
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: security@company.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

**Prometheus TLS 구성**
```yaml
# prometheus-tls.yml
global:
  scrape_interval: 15s
  
scrape_configs:
- job_name: 'prometheus'
  static_configs:
  - targets: ['localhost:9090']
  scheme: https
  tls_config:
    cert_file: /etc/prometheus/certs/prometheus.crt
    key_file: /etc/prometheus/certs/prometheus.key
    ca_file: /etc/prometheus/certs/ca.crt
    insecure_skip_verify: false

- job_name: 'secure-app'
  static_configs:
  - targets: ['app:8443']
  scheme: https
  tls_config:
    ca_file: /etc/prometheus/certs/ca.crt
  basic_auth:
    username: prometheus
    password_file: /etc/prometheus/auth/password
```

**Grafana TLS 구성**
```ini
# grafana.ini
[server]
protocol = https
cert_file = /etc/grafana/certs/grafana.crt
cert_key = /etc/grafana/certs/grafana.key
ssl_mode = require

[security]
admin_user = admin
admin_password = $__env{GF_SECURITY_ADMIN_PASSWORD}
secret_key = $__env{GF_SECURITY_SECRET_KEY}
cookie_secure = true
cookie_samesite = strict
strict_transport_security = true
```

### 1.2 역할 기반 접근 제어 (RBAC)

**Kubernetes RBAC for Prometheus**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus-server
rules:
- apiGroups: [""]
  resources: ["nodes", "services", "endpoints", "pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["extensions"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prometheus-server
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: prometheus-server
subjects:
- kind: ServiceAccount
  name: prometheus-server
  namespace: monitoring
```

**Grafana RBAC 구성**
```json
{
  "meta": {
    "type": "team",
    "canSave": true,
    "canEdit": true,
    "canAdmin": true,
    "canStar": true,
    "canDelete": true,
    "created": "2024-01-01T00:00:00Z",
    "updated": "2024-01-01T00:00:00Z"
  },
  "name": "DevOps Team",
  "email": "devops@company.com",
  "orgId": 1,
  "members": [],
  "permissions": [
    {
      "action": "dashboards:read",
      "scope": "dashboards:uid:*"
    },
    {
      "action": "dashboards:write", 
      "scope": "dashboards:uid:monitoring-*"
    },
    {
      "action": "datasources:read",
      "scope": "datasources:uid:prometheus"
    }
  ]
}
```

### 1.3 API 보안 및 토큰 관리

**Prometheus API 보안**
```yaml
# prometheus-api-auth.yml
apiVersion: v1
kind: Secret
metadata:
  name: prometheus-api-auth
type: Opaque
data:
  auth: |
    # htpasswd로 생성된 사용자 인증 정보
    prometheus:$2b$12$xyz...
    grafana:$2b$12$abc...

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    
    web_config:
      basic_auth_users:
        prometheus: $2b$12$xyz...
        grafana: $2b$12$abc...
```

**API Key 관리 시스템**
```python
# api_key_manager.py
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta

class APIKeyManager:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def generate_api_key(self, user_id, permissions, expires_days=90):
        """API 키 생성"""
        payload = {
            'user_id': user_id,
            'permissions': permissions,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(days=expires_days)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        key_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        
        return f"gm_{key_hash}_{token}"
    
    def validate_api_key(self, api_key):
        """API 키 검증"""
        try:
            if not api_key.startswith('gm_'):
                return None
                
            token = api_key.split('_', 2)[2]
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
```

### 1.4 네트워크 정책 및 방화벽

**Kubernetes Network Policy**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: monitoring-network-policy
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: prometheus
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    - namespaceSelector:
        matchLabels:
          name: grafana
    ports:
    - protocol: TCP
      port: 9090
      
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          monitoring: "allowed"
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 9100  # node_exporter
```

**방화벽 규칙 (iptables)**
```bash
#!/bin/bash
# monitoring-firewall.sh

# 기본 정책 - 모든 연결 차단
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 로컬호스트 허용
iptables -A INPUT -i lo -j ACCEPT

# 기존 연결 유지
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Prometheus (내부 네트워크만)
iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.0/8 -j ACCEPT

# Grafana (HTTPS만)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Node Exporter (Prometheus에서만)
iptables -A INPUT -p tcp --dport 9100 -s 10.1.0.0/16 -j ACCEPT

# SSH (관리자 IP만)
iptables -A INPUT -p tcp --dport 22 -s 203.0.113.0/24 -j ACCEPT

# 로그 및 저장
iptables -A INPUT -j LOG --log-prefix "DROPPED: "
iptables-save > /etc/iptables/rules.v4
```

## 2. 데이터 보호

### 2.1 민감한 데이터 처리

**메트릭 데이터 스크러빙**
```yaml
# prometheus-scrubbing.yml
scrape_configs:
- job_name: 'secure-app'
  static_configs:
  - targets: ['app:8080']
  metric_relabel_configs:
  # 민감한 라벨 제거
  - source_labels: [__name__]
    regex: '.*password.*|.*secret.*|.*token.*'
    action: drop
    
  # PII 데이터 마스킹
  - source_labels: [user_id]
    regex: '(.*)'
    target_label: user_id
    replacement: 'user_xxx'
    
  # IP 주소 마스킹
  - source_labels: [client_ip]
    regex: '(\d+\.\d+\.\d+)\.\d+'
    target_label: client_ip
    replacement: '${1}.xxx'
```

**로그 데이터 스크러빙**
```python
# log_scrubber.py
import re
import json

class LogScrubber:
    def __init__(self):
        self.patterns = {
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        }
    
    def scrub_log(self, log_entry):
        """로그 엔트리에서 민감한 정보 제거"""
        scrubbed = log_entry
        
        for name, pattern in self.patterns.items():
            if name == 'ip_address':
                # IP 주소는 마지막 옥텟만 마스킹
                scrubbed = pattern.sub(
                    lambda m: '.'.join(m.group().split('.')[:-1]) + '.xxx',
                    scrubbed
                )
            else:
                scrubbed = pattern.sub(f'[{name.upper()}_REDACTED]', scrubbed)
        
        return scrubbed
    
    def process_log_file(self, input_file, output_file):
        """로그 파일 전체 처리"""
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
            for line in infile:
                try:
                    log_data = json.loads(line)
                    log_data['message'] = self.scrub_log(log_data['message'])
                    outfile.write(json.dumps(log_data) + '\n')
                except json.JSONDecodeError:
                    # 일반 텍스트 로그 처리
                    scrubbed_line = self.scrub_log(line)
                    outfile.write(scrubbed_line)
```

### 2.2 GDPR 컴플라이언스

**데이터 수집 동의 관리**
```yaml
# consent-manager.yml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gdpr-config
data:
  retention_policy.yml: |
    personal_data:
      retention_days: 365
      categories:
        - user_metrics
        - session_data
        - api_usage
    
    anonymization_rules:
      - field: user_id
        method: hash
        salt: ${GDPR_SALT}
      - field: ip_address  
        method: truncate
        bits: 8
    
    deletion_schedule:
      - cron: "0 2 * * *"
        action: anonymize
        age_days: 30
      - cron: "0 3 * * 0"  
        action: delete
        age_days: 365
```

**데이터 삭제 스크립트**
```python
# gdpr_compliance.py
import asyncio
import hashlib
from datetime import datetime, timedelta

class GDPRCompliance:
    def __init__(self, prometheus_url, retention_days=365):
        self.prometheus_url = prometheus_url
        self.retention_days = retention_days
    
    async def anonymize_user_data(self, user_id):
        """사용자 데이터 익명화"""
        # 사용자 식별자를 해시로 변환
        anonymized_id = hashlib.sha256(
            f"{user_id}_{self.salt}".encode()
        ).hexdigest()[:16]
        
        # 메트릭 라벨 업데이트
        queries = [
            f'label_replace({{user_id="{user_id}"}}, "user_id", "{anonymized_id}", "", "")'
        ]
        
        for query in queries:
            await self.execute_prometheus_query(query)
    
    async def delete_user_data(self, user_id):
        """사용자 데이터 완전 삭제"""
        delete_query = f'{{user_id="{user_id}"}}'
        
        # Prometheus Admin API를 통한 데이터 삭제
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{self.prometheus_url}/api/v1/admin/tsdb/delete_series",
                params={"match[]": delete_query}
            )
    
    async def cleanup_expired_data(self):
        """만료된 데이터 정리"""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        # 만료된 시계열 데이터 식별 및 삭제
        query = f'time() - timestamp({{__name__=~".+"}}) > {self.retention_days * 24 * 3600}'
        
        expired_series = await self.query_prometheus(query)
        
        for series in expired_series:
            await self.delete_series(series)
```

### 2.3 감사 로깅 및 컴플라이언스 보고

**감사 로그 수집**
```yaml
# audit-logging.yml
apiVersion: v1
kind: ConfigMap
metadata:
  name: audit-policy
data:
  audit-policy.yaml: |
    apiVersion: audit.k8s.io/v1
    kind: Policy
    rules:
    - level: Metadata
      namespaces: ["monitoring"]
      resources:
      - group: ""
        resources: ["secrets", "configmaps"]
      - group: "apps"
        resources: ["deployments", "statefulsets"]
        
    - level: Request
      namespaces: ["monitoring"]
      verbs: ["create", "update", "patch", "delete"]
      resources:
      - group: "monitoring.coreos.com"
        resources: ["prometheusrules", "servicemonitors"]
```

**컴플라이언스 리포트 생성**
```python
# compliance_reporter.py
import json
from datetime import datetime, timedelta
import pandas as pd

class ComplianceReporter:
    def __init__(self, prometheus_client, audit_log_path):
        self.prometheus = prometheus_client
        self.audit_log_path = audit_log_path
    
    def generate_soc2_report(self, start_date, end_date):
        """SOC2 컴플라이언스 보고서 생성"""
        report = {
            'report_period': f"{start_date} to {end_date}",
            'controls': {
                'access_control': self._check_access_controls(),
                'data_encryption': self._check_encryption_status(),
                'monitoring_coverage': self._check_monitoring_coverage(),
                'incident_response': self._check_incident_response(),
                'backup_recovery': self._check_backup_procedures()
            },
            'metrics': {
                'uptime_percentage': self._calculate_uptime(),
                'security_incidents': self._count_security_incidents(),
                'failed_access_attempts': self._count_failed_access(),
                'data_breaches': self._count_data_breaches()
            }
        }
        
        return report
    
    def _check_access_controls(self):
        """접근 제어 검증"""
        controls = []
        
        # RBAC 설정 확인
        rbac_query = 'up{job="kube-state-metrics"}'
        rbac_result = self.prometheus.query(rbac_query)
        controls.append({
            'control': 'RBAC_ENABLED',
            'status': 'PASS' if rbac_result else 'FAIL'
        })
        
        # TLS 암호화 확인
        tls_query = 'prometheus_config_last_reload_successful'
        tls_result = self.prometheus.query(tls_query)
        controls.append({
            'control': 'TLS_ENCRYPTION',
            'status': 'PASS' if tls_result else 'FAIL'
        })
        
        return controls
    
    def generate_gdpr_report(self):
        """GDPR 컴플라이언스 보고서"""
        return {
            'data_processing_activities': self._list_data_processing(),
            'consent_management': self._check_consent_status(),
            'data_subject_requests': self._count_data_requests(),
            'data_breaches': self._list_data_breaches(),
            'retention_compliance': self._check_retention_policy()
        }
```

### 2.4 Vault를 이용한 시크릿 관리

**Vault 통합 구성**
```yaml
# vault-integration.yml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-auth
  namespace: monitoring

---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: monitoring-secrets
  namespace: monitoring
spec:
  provider: vault
  parameters:
    vaultAddress: "https://vault.company.com:8200"
    roleName: "monitoring-role"
    objects: |
      - objectName: "prometheus-admin-password"
        secretPath: "secret/monitoring/prometheus"
        secretKey: "admin_password"
      - objectName: "grafana-admin-password"
        secretPath: "secret/monitoring/grafana"  
        secretKey: "admin_password"
      - objectName: "database-connection"
        secretPath: "secret/monitoring/database"
        secretKey: "connection_string"
```

**동적 시크릿 관리**
```python
# vault_manager.py
import hvac
import json
from datetime import datetime, timedelta

class VaultManager:
    def __init__(self, vault_url, vault_token):
        self.client = hvac.Client(url=vault_url, token=vault_token)
    
    def create_dynamic_database_credentials(self, role_name="monitoring-readonly"):
        """동적 데이터베이스 자격증명 생성"""
        try:
            response = self.client.secrets.database.generate_credentials(
                name=role_name
            )
            
            credentials = {
                'username': response['data']['username'],
                'password': response['data']['password'],
                'lease_id': response['lease_id'],
                'lease_duration': response['lease_duration']
            }
            
            # Kubernetes 시크릿으로 저장
            self._create_k8s_secret('database-credentials', credentials)
            
            return credentials
            
        except Exception as e:
            print(f"자격증명 생성 실패: {e}")
            return None
    
    def rotate_monitoring_secrets(self):
        """모니터링 시크릿 순환"""
        secrets_to_rotate = [
            'monitoring/prometheus/admin_password',
            'monitoring/grafana/admin_password',
            'monitoring/alertmanager/webhook_token'
        ]
        
        for secret_path in secrets_to_rotate:
            new_password = self._generate_secure_password()
            
            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path,
                secret={'password': new_password, 'rotated_at': datetime.now().isoformat()}
            )
            
            # 애플리케이션에 시크릿 업데이트 알림
            self._notify_secret_rotation(secret_path)
```

## 3. 실습 과제

### 과제 1: TLS 인증서 자동화
1. cert-manager로 Let's Encrypt 인증서 자동 발급
2. 모든 모니터링 구성요소에 TLS 적용
3. 인증서 갱신 자동화 테스트

### 과제 2: RBAC 구현
1. Kubernetes RBAC으로 모니터링 권한 관리
2. Grafana 팀별 대시보드 접근 제어
3. API 키 기반 접근 제어 구현

### 과제 3: 컴플라이언스 자동화
1. GDPR 데이터 삭제 스크립트 구현
2. SOC2 컴플라이언스 체크리스트 자동화
3. 감사 로그 수집 및 분석 시스템 구축

## 4. 보안 체크리스트

### 네트워크 보안
- [ ] 모든 통신에 TLS 암호화 적용
- [ ] 네트워크 정책으로 트래픽 제한
- [ ] 방화벽 규칙 적용
- [ ] VPN 또는 Private 네트워크 사용

### 인증/인가
- [ ] 강력한 패스워드 정책
- [ ] 다단계 인증 (MFA) 구현
- [ ] RBAC 적용
- [ ] API 키 순환 정책

### 데이터 보호
- [ ] 민감한 데이터 마스킹
- [ ] 데이터 보존 정책 구현
- [ ] 백업 암호화
- [ ] GDPR 컴플라이언스

## 5. 다음 단계
- 알림 및 인시던트 대응 (Phase 3-1)
- 자동화 및 자가 치유 (Phase 3-2)