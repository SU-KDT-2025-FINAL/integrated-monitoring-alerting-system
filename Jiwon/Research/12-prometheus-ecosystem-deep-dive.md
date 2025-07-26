# 1.2 Prometheus 생태계 심화 학습

## Overview
Prometheus 모니터링 시스템의 아키텍처와 핵심 구성 요소를 깊이 있게 학습합니다. PromQL 쿼리 언어, 데이터 모델, 그리고 확장 가능한 모니터링 솔루션 구축 방법을 다룹니다.

## Prometheus 아키텍처 및 구성 요소

### Prometheus Server
**역할**: 메트릭 수집, 저장, 쿼리 처리의 핵심 엔진

**주요 기능**:
- **Time Series Database (TSDB)**: 효율적인 시계열 데이터 저장
- **Scraping Engine**: 설정된 타겟에서 메트릭 주기적 수집
- **Query Engine**: PromQL 쿼리 실행 및 결과 반환
- **Rule Engine**: Recording rules 및 Alerting rules 평가

**저장 구조**:
```
prometheus/
├── data/
│   ├── chunks_head/     # 메모리 내 최신 데이터
│   ├── wal/            # Write-Ahead Log
│   └── 01GQZQ4...      # 2시간 블록 단위 데이터
```

### Exporters
**정의**: 시스템 메트릭을 Prometheus 형식으로 노출하는 컴포넌트

**표준 Exporters**:
- **node_exporter**: Linux/Unix 시스템 메트릭 (CPU, 메모리, 디스크, 네트워크)
- **cAdvisor**: 컨테이너 리소스 사용량 및 성능 메트릭
- **blackbox_exporter**: HTTP, HTTPS, DNS, TCP, ICMP 프로브 모니터링

**Exporter 메트릭 예시**:
```
# node_exporter 메트릭
node_cpu_seconds_total{cpu="0",mode="idle"} 10000.50
node_memory_MemAvailable_bytes 8234567890
node_filesystem_free_bytes{device="/dev/sda1",fstype="ext4"} 50000000000
```

### Alertmanager
**역할**: 알림 규칙 평가 결과를 받아 실제 알림을 전송하는 시스템

**핵심 기능**:
- **알림 그룹화**: 유사한 알림들을 묶어서 스팸 방지
- **알림 억제**: 상위 레벨 알림 발생 시 하위 레벨 알림 억제
- **알림 침묵**: 유지보수 기간 동안 특정 알림 비활성화
- **다중 채널 전송**: 이메일, Slack, PagerDuty, 웹훅 등

**Alertmanager 설정 예시**:
```yaml
route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://127.0.0.1:5001/'
    send_resolved: true
```

### Pushgateway
**사용 목적**: 짧은 수명의 배치 작업이나 서비스 레벨 메트릭을 Push 방식으로 수집

**적용 사례**:
- **배치 작업**: 크론 작업 실행 결과 및 소요 시간
- **CI/CD 파이프라인**: 빌드/배포 성공률 및 소요 시간
- **서비스 레벨 메트릭**: 비즈니스 KPI 및 집계 메트릭

**사용 예시**:
```bash
# 배치 작업 메트릭 푸시
echo "batch_job_duration_seconds 45.2" | curl --data-binary @- \
  http://pushgateway:9091/metrics/job/batch_job/instance/server1
```

## PromQL 쿼리 언어 및 고급 쿼리 기법

### 기본 쿼리 구문

#### Instant Vector 쿼리
```promql
# 기본 메트릭 조회
http_requests_total

# 라벨 필터링
http_requests_total{job="api-server", method="POST"}

# 정규표현식 매칭
http_requests_total{status_code=~"5.."}

# 부정 매칭
http_requests_total{method!="GET"}
```

#### Range Vector 쿼리
```promql
# 5분간 데이터 범위 조회
http_requests_total[5m]

# 1시간전부터 5분간 데이터 (시간 오프셋)
http_requests_total[5m] offset 1h
```

### 집계 함수와 연산자

#### 산술 연산자
```promql
# CPU 사용률 계산 (백분율)
100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# 메모리 사용률 계산
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# 디스크 사용률 예측 (선형 회귀)
predict_linear(node_filesystem_free_bytes[1h], 4*3600) < 0
```

#### 집계 함수
```promql
# 전체 인스턴스 평균 CPU 사용률
avg(rate(node_cpu_seconds_total{mode!="idle"}[5m])) by (instance)

# 서비스별 최대 응답 시간
max(http_request_duration_seconds) by (service)

# 상위 5개 높은 메모리 사용 인스턴스
topk(5, node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes)

# 전체 요청 수 합계
sum(rate(http_requests_total[5m]))
```

### 고급 쿼리 패턴

#### 히트맵 생성을 위한 히스토그램 쿼리
```promql
# 응답 시간 히스토그램 변환
histogram_quantile(0.95, 
  sum(rate(http_request_duration_seconds_bucket[5m])) by (le)
)

# 히트맵 시각화를 위한 버킷별 빈도
sum(rate(http_request_duration_seconds_bucket[5m])) by (le)
```

#### 다중 메트릭 조인 및 계산
```promql
# 네트워크 대역폭 활용률
(
  rate(node_network_transmit_bytes_total[5m]) + 
  rate(node_network_receive_bytes_total[5m])
) / 
(
  node_network_speed_bytes * 2
) * 100
```

#### 시간 기반 집계 및 비교
```promql
# 지난주 동시간 대비 트래픽 증가율
(
  sum(rate(http_requests_total[5m]))
  /
  sum(rate(http_requests_total[5m] offset 7d))
) * 100 - 100

# 월별 평균 대비 현재 성능
avg_over_time(
  rate(http_request_duration_seconds_sum[5m])[30d:1d]
)
```

## 데이터 모델 및 메트릭 유형

### Prometheus 데이터 모델
**구조**: `metric_name{label1="value1", label2="value2"} value timestamp`

**예시**:
```
http_requests_total{method="GET", handler="/api/users", status="200"} 1027 1609459200000
```

**구성 요소**:
- **Metric Name**: 측정하는 내용의 식별자
- **Labels**: 메트릭의 차원을 정의하는 키-값 쌍
- **Sample**: 특정 시점의 값 (float64)
- **Timestamp**: 밀리초 단위 Unix 타임스탬프

### 메트릭 유형별 상세 분석

#### Counter (카운터)
**특성**: 단조 증가 값, 재시작 시 0으로 리셋

**활용 예시**:
```promql
# 초당 요청률 (QPS)
rate(http_requests_total[5m])

# 5분간 총 요청 증가량
increase(http_requests_total[5m])

# 누적 오류 수
http_errors_total
```

**명명 규칙**: `*_total` 접미사 사용

#### Gauge (게이지)
**특성**: 임의로 증가/감소 가능한 값

**활용 예시**:
```promql
# 현재 동시 연결 수
active_connections

# 메모리 사용량 추이
node_memory_MemAvailable_bytes

# 큐 길이 모니터링
queue_length
```

**고려사항**: 인스턴스 재시작 시 값이 변경될 수 있음

#### Histogram (히스토그램)
**구성**: 관측된 값들을 사전 정의된 버킷에 분류하여 저장

**생성되는 메트릭**:
- `*_bucket{le="x"}`: 각 버킷별 누적 카운트
- `*_sum`: 모든 관측값의 합계
- `*_count`: 총 관측 횟수

**예시**:
```
http_request_duration_seconds_bucket{le="0.1"} 24054
http_request_duration_seconds_bucket{le="0.2"} 33444
http_request_duration_seconds_bucket{le="0.5"} 100392
http_request_duration_seconds_bucket{le="+Inf"} 144320
http_request_duration_seconds_sum 53423
http_request_duration_seconds_count 144320
```

**백분위수 계산**:
```promql
# 95번째 백분위수 응답 시간
histogram_quantile(0.95, 
  sum(rate(http_request_duration_seconds_bucket[5m])) by (le)
)
```

#### Summary (요약)
**구성**: 클라이언트 측에서 백분위수를 사전 계산하여 제공

**생성되는 메트릭**:
- `*{quantile="0.5"}`: 50번째 백분위수
- `*{quantile="0.9"}`: 90번째 백분위수
- `*{quantile="0.99"}`: 99번째 백분위수
- `*_sum`: 모든 관측값의 합계
- `*_count`: 총 관측 횟수

**Histogram vs Summary 선택 기준**:
- **Histogram**: 집계 가능, 유연한 백분위수 계산, 서버 측 처리
- **Summary**: 정확한 백분위수, 클라이언트 측 계산, 집계 불가

## 서비스 디스커버리 메커니즘 및 구성 관리

### 정적 설정 (Static Configuration)
```yaml
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node1:9100', 'node2:9100', 'node3:9100']
        labels:
          environment: 'production'
          datacenter: 'dc1'
```

### Kubernetes 서비스 디스커버리
```yaml
scrape_configs:
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
```

### 파일 기반 서비스 디스커버리
```yaml
scrape_configs:
  - job_name: 'file_sd'
    file_sd_configs:
      - files:
          - '/etc/prometheus/targets/*.json'
        refresh_interval: 5m
```

**타겟 파일 예시** (`/etc/prometheus/targets/web-servers.json`):
```json
[
  {
    "targets": ["web1:8080", "web2:8080"],
    "labels": {
      "job": "web-server",
      "environment": "production"
    }
  }
]
```

### Consul 서비스 디스커버리
```yaml
scrape_configs:
  - job_name: 'consul'
    consul_sd_configs:
      - server: 'consul.service.consul:8500'
        services: ['web', 'database', 'cache']
    relabel_configs:
      - source_labels: [__meta_consul_service]
        target_label: job
```

## Best Practices

### 메트릭 명명 및 라벨링 모범 사례

#### 명명 규칙
1. **명확한 목적**: `http_requests_total` (명확) vs `requests` (모호)
2. **단위 포함**: `response_time_seconds`, `memory_usage_bytes`
3. **계층 구조**: `myapp_http_requests_total`, `myapp_db_connections_active`
4. **일관성**: 조직 전체 통일된 접두사 및 패턴

#### 라벨 설계 원칙
```promql
# 좋은 예: 적절한 카디널리티
http_requests_total{method="GET", status="200", handler="/api/users"}

# 나쁜 예: 높은 카디널리티 (사용자 ID)
http_requests_total{method="GET", status="200", user_id="12345"}

# 해결책: 집계된 메트릭 사용
http_requests_by_user_total{method="GET", status="200"}
```

### 성능 최적화

#### 쿼리 최적화
1. **시간 범위 최소화**: 필요한 최소 시간 범위 사용
2. **라벨 필터링**: 쿼리 초기 단계에서 라벨 필터 적용
3. **집계 순서**: 집계 후 필터링보다 필터링 후 집계가 효율적

#### 저장소 최적화
```yaml
# prometheus.yml 설정
global:
  scrape_interval: 15s      # 기본 수집 간격
  evaluation_interval: 15s  # 규칙 평가 간격

# 보존 기간 설정
storage:
  tsdb:
    retention.time: 15d
    retention.size: 500GB
```

### 고가용성 설정

#### Prometheus 연합 (Federation)
```yaml
# 상위 Prometheus 설정
scrape_configs:
  - job_name: 'federate'
    scrape_interval: 15s
    honor_labels: true
    metrics_path: '/federate'
    params:
      'match[]':
        - '{job=~"prometheus|node"}'
        - 'up'
    static_configs:
      - targets:
        - 'prometheus-1:9090'
        - 'prometheus-2:9090'
```

## Benefits and Challenges

### Benefits
- **확장성**: 수평적 확장 가능한 아키텍처
- **유연성**: 다양한 서비스 디스커버리 메커니즘 지원
- **강력한 쿼리**: PromQL을 통한 복합적인 메트릭 분석
- **생태계**: 풍부한 Exporter 및 통합 도구

### Challenges
- **학습 곡선**: PromQL 습득을 위한 시간 투자 필요
- **저장소 한계**: 장기 데이터 보존을 위한 별도 솔루션 필요
- **고가용성 복잡성**: 연합 설정 및 관리의 복잡성
- **카디널리티 관리**: 높은 카디널리티로 인한 성능 저하 위험