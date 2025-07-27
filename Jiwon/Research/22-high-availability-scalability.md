# 고가용성 및 확장성 (Phase 2-2)

## 개요
대규모 환경에서 모니터링 시스템의 고가용성, 확장성, 내결함성을 보장하는 아키텍처 패턴과 구현 방법을 학습합니다.

## 1. Prometheus 연합 (Federation)

### 1.1 계층적 연합 설정

**글로벌 Prometheus 구성**
```yaml
# global-prometheus.yml
global:
  scrape_interval: 15s
  external_labels:
    region: 'global'
    replica: '1'

scrape_configs:
- job_name: 'federate'
  scrape_interval: 15s
  honor_labels: true
  metrics_path: '/federate'
  params:
    'match[]':
      - '{job=~"kubernetes-.*"}'
      - '{__name__=~"node_.*"}'
      - '{__name__=~"container_.*"}'
  static_configs:
  - targets:
    - 'prometheus-asia:9090'
    - 'prometheus-europe:9090'
    - 'prometheus-us:9090'
```

**지역별 Prometheus 구성**
```yaml
# regional-prometheus.yml  
global:
  scrape_interval: 15s
  external_labels:
    region: 'asia'
    replica: '1'

rule_files:
- "/etc/prometheus/rules/*.yml"

scrape_configs:
- job_name: 'kubernetes-pods'
  kubernetes_sd_configs:
  - role: pod
  relabel_configs:
  - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
    action: keep
    regex: true
```

### 1.2 원격 읽기/쓰기 구성

**Remote Write 설정**
```yaml
remote_write:
- url: "http://thanos-receive:19291/api/v1/receive"
  remote_timeout: 30s
  queue_config:
    capacity: 10000
    max_shards: 50
    min_shards: 1
    max_samples_per_send: 2000
    batch_send_deadline: 5s
  write_relabel_configs:
  - source_labels: [__name__]
    regex: 'go_.*|prometheus_.*'
    action: drop
```

**Remote Read 설정**
```yaml
remote_read:
- url: "http://thanos-query:9090/api/v1/query"
  read_recent: true
  required_matchers:
    job: 'federated'
```

### 1.3 Thanos를 이용한 장기 저장

**Thanos Sidecar 구성**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus-with-thanos
spec:
  template:
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus:latest
        args:
        - '--storage.tsdb.min-block-duration=2h'
        - '--storage.tsdb.max-block-duration=2h'
        - '--web.enable-lifecycle'
        
      - name: thanos-sidecar
        image: thanosio/thanos:v0.32.0
        args:
        - sidecar
        - --prometheus.url=http://localhost:9090
        - --tsdb.path=/prometheus
        - --objstore.config-file=/etc/bucket/bucket.yml
        - --reloader.config-file=/etc/prometheus/prometheus.yml
```

**Thanos Query 구성**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: thanos-query
spec:
  template:
    spec:
      containers:
      - name: thanos-query
        image: thanosio/thanos:v0.32.0
        args:
        - query
        - --http-address=0.0.0.0:9090
        - --store=thanos-store:10901
        - --store=thanos-sidecar-1:10901
        - --store=thanos-sidecar-2:10901
        - --query.replica-label=replica
        - --query.auto-downsampling
```

### 1.4 VictoriaMetrics 대안

**VictoriaMetrics 클러스터 구성**
```yaml
# vmcluster.yaml
apiVersion: operator.victoriametrics.com/v1beta1
kind: VMCluster
metadata:
  name: monitoring-cluster
spec:
  retentionPeriod: "12"
  
  vmselect:
    replicaCount: 2
    resources:
      requests:
        memory: "1Gi"
        cpu: "500m"
        
  vminsert:
    replicaCount: 2
    resources:
      requests:
        memory: "500Mi"
        cpu: "250m"
        
  vmstorage:
    replicaCount: 3
    resources:
      requests:
        memory: "2Gi"
        cpu: "1000m"
    storage:
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 100Gi
```

## 2. 로드 밸런싱 및 클러스터링

### 2.1 AlertManager 클러스터링

**AlertManager 클러스터 구성**
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: alertmanager
spec:
  serviceName: alertmanager-headless
  replicas: 3
  template:
    spec:
      containers:
      - name: alertmanager
        image: prom/alertmanager:latest
        args:
        - --config.file=/etc/alertmanager/alertmanager.yml
        - --storage.path=/data
        - --cluster.listen-address=0.0.0.0:9094
        - --cluster.peer=alertmanager-0.alertmanager-headless:9094
        - --cluster.peer=alertmanager-1.alertmanager-headless:9094
        - --cluster.peer=alertmanager-2.alertmanager-headless:9094
        - --cluster.pushpull-interval=60s
        - --cluster.gossip-interval=200ms
```

**AlertManager 설정**
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  
route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: 'web.hook'
  
receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://webhook-service:5000/alert'
    send_resolved: true
    
inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname', 'cluster', 'service']
```

### 2.2 Grafana 클러스터링

**Grafana 고가용성 구성**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: grafana
        image: grafana/grafana:latest
        env:
        - name: GF_DATABASE_TYPE
          value: postgres
        - name: GF_DATABASE_HOST
          value: "postgres:5432"
        - name: GF_DATABASE_NAME
          value: grafana
        - name: GF_DATABASE_USER
          valueFrom:
            secretKeyRef:
              name: grafana-secrets
              key: db-user
        - name: GF_SESSION_PROVIDER
          value: redis
        - name: GF_SESSION_PROVIDER_CONFIG
          value: "addr=redis:6379,pool_size=100"
```

**PostgreSQL for Grafana**
```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: grafana-postgres
spec:
  instances: 3
  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"
      effective_cache_size: "1GB"
      
  storage:
    size: 50Gi
    storageClass: fast-ssd
    
  monitoring:
    enabled: true
```

### 2.3 다중 지역 배포 전략

**글로벌 로드 밸런서 구성**
```yaml
apiVersion: networking.gke.io/v1
kind: ManagedCertificate
metadata:
  name: monitoring-ssl-cert
spec:
  domains:
  - monitoring.company.com
  
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: global-monitoring-ingress
  annotations:
    kubernetes.io/ingress.global-static-ip-name: "monitoring-ip"
    networking.gke.io/managed-certificates: "monitoring-ssl-cert"
spec:
  rules:
  - host: monitoring.company.com
    http:
      paths:
      - path: /grafana/*
        pathType: Prefix
        backend:
          service:
            name: grafana-service
            port:
              number: 80
```

### 2.4 재해 복구 및 백업 절차

**Prometheus 데이터 백업**
```bash
#!/bin/bash
# prometheus-backup.sh

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
PROMETHEUS_DATA_DIR="/prometheus"
BACKUP_DIR="/backups/prometheus"
S3_BUCKET="s3://monitoring-backups"

# 스냅샷 생성
curl -X POST http://prometheus:9090/api/v1/admin/tsdb/snapshot

# 최신 스냅샷 찾기
SNAPSHOT_DIR=$(ls -1t ${PROMETHEUS_DATA_DIR}/snapshots/ | head -1)

# 압축 및 S3 업로드
tar czf ${BACKUP_DIR}/prometheus_${BACKUP_DATE}.tar.gz \
    -C ${PROMETHEUS_DATA_DIR}/snapshots/${SNAPSHOT_DIR} .

aws s3 cp ${BACKUP_DIR}/prometheus_${BACKUP_DATE}.tar.gz \
    ${S3_BUCKET}/prometheus/

# 로컬 백업 정리 (7일 이상 된 파일)
find ${BACKUP_DIR} -name "prometheus_*.tar.gz" -mtime +7 -delete
```

**Grafana 대시보드 백업**
```python
#!/usr/bin/env python3
# grafana-backup.py

import requests
import json
import os
from datetime import datetime

GRAFANA_URL = "http://grafana:3000"
API_KEY = os.environ['GRAFANA_API_KEY']
BACKUP_DIR = "/backups/grafana"

headers = {'Authorization': f'Bearer {API_KEY}'}

# 모든 대시보드 목록 가져오기
response = requests.get(f"{GRAFANA_URL}/api/search", headers=headers)
dashboards = response.json()

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
backup_file = f"{BACKUP_DIR}/dashboards_{timestamp}.json"

dashboard_data = []
for dashboard in dashboards:
    if dashboard['type'] == 'dash-db':
        uid = dashboard['uid']
        dash_response = requests.get(
            f"{GRAFANA_URL}/api/dashboards/uid/{uid}", 
            headers=headers
        )
        dashboard_data.append(dash_response.json())

with open(backup_file, 'w') as f:
    json.dump(dashboard_data, f, indent=2)

print(f"백업 완료: {backup_file}")
```

## 3. 성능 최적화

### 3.1 쿼리 최적화
```promql
# 비효율적인 쿼리
rate(http_requests_total[5m])

# 최적화된 쿼리 (필요한 라벨만 선택)
rate(http_requests_total{job="api-server",method="GET"}[5m])

# 집계 최적화
sum(rate(http_requests_total[5m])) by (job, status)
```

### 3.2 카디널리티 관리
```yaml
# prometheus.yml
metric_relabel_configs:
- source_labels: [__name__]
  regex: 'high_cardinality_metric_.*'
  action: drop
  
- source_labels: [user_id]
  regex: '.*'
  action: drop
  target_label: user_id
```

## 4. 실습 과제

### 과제 1: Thanos 구축
1. Prometheus + Thanos Sidecar 배포
2. Thanos Query/Store/Compactor 구성
3. 장기 저장을 위한 S3 연동

### 과제 2: AlertManager 클러스터
1. 3노드 AlertManager 클러스터 구성
2. 고가용성 테스트
3. 알림 중복 제거 확인

### 과제 3: 백업 및 복구
1. 자동 백업 스크립트 구현
2. 재해 복구 시나리오 테스트
3. RTO/RPO 측정

## 5. 모니터링 메트릭

### 중요 메트릭들
```promql
# Prometheus 성능
prometheus_tsdb_head_samples_appended_total
prometheus_config_last_reload_successful
prometheus_rule_evaluation_duration_seconds

# 클러스터 상태
up{job="prometheus"}
alertmanager_cluster_members
thanos_sidecar_prometheus_up
```

## 6. 다음 단계
- 보안 및 컴플라이언스 (Phase 2-3)
- 알림 및 인시던트 대응 (Phase 3-1)