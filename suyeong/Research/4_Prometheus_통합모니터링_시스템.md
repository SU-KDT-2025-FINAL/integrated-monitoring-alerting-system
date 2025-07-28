# Prometheus 통합 모니터링 시스템 리서치

## 1. Prometheus란 무엇인가?

**Prometheus**는 CNCF(Cloud Native Computing Foundation)에 소속된 오픈소스 모니터링 및 알림 시스템입니다.

### 핵심 정의
- **메트릭 기반 모니터링**: 개별 이벤트보다는 전반적인 시스템의 상태, 동작, 성능을 추적
- **시계열 데이터베이스**: 숫자 형태의 시계열 메트릭 데이터를 저장하고 처리
- **클라우드 네이티브**: Kubernetes 클러스터 및 Docker 컨테이너 모니터링에 특화

### 기존 모니터링 시스템과의 차이점
- **Pull 방식**: 서버가 주기적으로 클라이언트에 접속해서 데이터를 가져오는 방식
- **Push 방식**(기존): 각 서버에 클라이언트를 설치하고 메트릭 데이터를 서버로 보내는 방식

## 2. Prometheus 시스템 구성 요소

### 2.1 Prometheus Server
- 서비스 디스커버리 시스템으로부터 모니터링 대상 목록을 받아옴
- Exporter로부터 주기적으로 메트릭을 수집
- 시계열 데이터베이스에 메트릭 저장
- PromQL 쿼리 처리

### 2.2 Exporter (핵심 구성요소)

**역할과 기능:**
- 모니터링 대상의 메트릭 데이터를 수집
- HTTP 엔드포인트를 통해 메트릭 노출 (기본 포트: 9100)
- Prometheus 서버가 데이터를 수집할 수 있도록 지원

**주요 Exporter 종류:**
- **Node Exporter**: 호스트 서버의 CPU, Memory, Disk 등 시스템 메트릭
- **Nginx Exporter**: Nginx 웹서버 메트릭
- **MySQL Exporter**: MySQL 데이터베이스 메트릭
- **JMX Exporter**: Java 애플리케이션 메트릭

**메트릭 노출 방식:**
- 단순히 HTTP GET으로 메트릭을 텍스트 형태로 반환
- 요청 당시의 데이터만 제공 (기존값 저장 기능 없음)

### 2.3 Service Discovery (서비스 디스커버리)
- 오토스케일링 환경에서 동적으로 변경되는 IP 주소 관리
- 모니터링 대상이 등록된 저장소에서 목록을 자동으로 받아와 모니터링
- Kubernetes, Consul, AWS EC2 등 다양한 플랫폼 지원

### 2.4 Alertmanager
- Prometheus에서 발생한 알림을 처리하는 별도 컴포넌트
- 중복 제거, 그룹화, 라우팅 기능 제공
- 다양한 알림 채널 지원 (이메일, Slack, PagerDuty 등)

## 3. PromQL (Prometheus Query Language)

### 3.1 기본 개념
- **함수형 쿼리 언어**: 실시간으로 시계열 데이터를 선택해 집계
- **시계열 DB 특화**: RDBMS와 달리 시간 기반 데이터 처리에 최적화
- **직관적 문법**: 이해하기 쉬운 쿼리로 복잡한 메트릭 분석 가능

### 3.2 쿼리 표현식 타입

**1. Instant Vector**
- 같은 타임스탬프 상의 시계열 셋
- 각 시계열마다 단일 샘플 보유
```promql
http_requests_total
```

**2. Range Vector**
- 특정 시간 범위의 시계열 셋
- 각 시계열마다 시간에 따른 데이터 포인트들 보유
```promql
http_requests_total[5m]
```

### 3.3 레이블 기반 필터링

**기본 필터링:**
```promql
http_requests_total{job="prometheus", group="canary"}
```

**논리 연산자:**
- `=`: 정확히 일치
- `!=`: 일치하지 않음
- `=~`: 정규표현식 일치
- `!~`: 정규표현식 불일치

**예시:**
```promql
http_requests_total{status=~"5.."}  # 5xx 상태 코드
```

### 3.4 집계 함수 예시
```promql
# CPU 사용률 평균
avg(cpu_usage_percent)

# 요청 수 합계
sum(http_requests_total)

# 응답 시간 95 퍼센타일
histogram_quantile(0.95, http_request_duration_seconds_bucket)
```

## 4. Kubernetes 환경에서의 Prometheus

### 4.1 메트릭 수집 방법

**1. Annotation 기반 수집**
- Prometheus 서버가 Kubernetes 애너테이션을 기준으로 대상 발견
- 자동으로 Pod 및 Service 메트릭 수집

**2. SDK를 통한 메트릭 노출**
- Go, Python, Java, C#, Rust 등 다양한 언어 지원
- 애플리케이션 코드에 직접 메트릭 추가

**예시 애너테이션:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
```

### 4.2 Kubernetes 네이티브 메트릭
- **kube-state-metrics**: Kubernetes 오브젝트 상태 메트릭
- **cadvisor**: 컨테이너 리소스 사용량 메트릭
- **kubelet**: 노드 및 Pod 메트릭

## 5. Alertmanager를 통한 알림 시스템

### 5.1 기본 구성

**주요 기능:**
- 알림 중복 제거 및 그룹화
- 다양한 채널로 알림 라우팅
- 알림 억제 및 음소거 기능

### 5.2 설정 파일 구조 (alertmanager.yml)

```yaml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@company.com'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  email_configs:
  - to: 'admin@company.com'
    subject: 'Alert: {{ .GroupLabels.alertname }}'
  slack_configs:
  - channel: '#alerts'
    api_url: 'https://hooks.slack.com/services/...'
```

### 5.3 지원하는 알림 채널 (2025년 기준)
- **이메일**: SMTP 서버를 통한 이메일 알림
- **Slack**: 웹훅을 통한 Slack 채널 알림
- **PagerDuty**: 인시던트 관리 플랫폼 연동
- **Webhook**: 커스텀 시스템 연동
- **Microsoft Teams**: 팀즈 채널 알림

### 5.4 알림 그룹화 전략

**대규모 장애 상황 대응:**
- 수백~수천 개의 동시 알림을 논리적으로 그룹화
- 유사한 성격의 알림을 단일 알림으로 통합
- 알림 폭주 방지 및 운영 효율성 증대

## 6. 2025년 Prometheus 동향과 특징

### 6.1 클라우드 네이티브 표준
- **Kubernetes 표준 모니터링**: 사실상 쿠버네티스 환경의 표준 모니터링 솔루션
- **CNCF 생태계**: 다른 CNCF 프로젝트들과의 긴밀한 통합
- **컨테이너 최적화**: Docker, Kubernetes 환경에 특화된 기능

### 6.2 확장성 및 고가용성
- **고가용성 구성**: 여러 Prometheus 서버 클러스터링
- **장기 저장**: Thanos, Cortex 등을 통한 장기 메트릭 보관
- **페더레이션**: 여러 Prometheus 인스턴스 간 메트릭 공유

### 6.3 IoT 및 분산 시스템 모니터링
- **복잡한 인프라 대응**: 점점 복잡해지는 IT 인프라 구조 모니터링
- **유연한 모니터링**: 빠르게 변하는 ICT 기술에 대응
- **오픈소스 생태계**: 다양한 플러그인과 익스포터 지원

## 7. Prometheus의 장점

### 7.1 운영의 편의성
- **단순한 구조**: 이해하기 쉽고 운영이 간편
- **강력한 쿼리**: PromQL을 통한 유연한 데이터 분석
- **풍부한 생태계**: 다양한 익스포터와 통합 도구

### 7.2 시각화 및 통합
- **Grafana 연동**: 강력한 시각화 도구와의 완벽한 통합
- **API 지원**: REST API를 통한 외부 시스템 연동
- **확장성**: 다양한 플러그인과 커스텀 익스포터 개발 가능

## 8. 학습을 위한 다음 단계

### 8.1 기초 실습
1. **Docker로 Prometheus 설치**: 로컬 환경에서 Prometheus 서버 구동
2. **Node Exporter 연동**: 시스템 메트릭 수집 실습
3. **PromQL 기초**: 기본 쿼리 작성 및 실행

### 8.2 중급 실습
1. **Alertmanager 설정**: 기본 알림 규칙 생성 및 테스트
2. **Grafana 대시보드**: Prometheus 데이터 시각화
3. **Kubernetes 연동**: 쿠버네티스 클러스터 모니터링

### 8.3 고급 활용
1. **커스텀 익스포터**: 애플리케이션별 메트릭 수집기 개발
2. **고가용성 구성**: 프로덕션 환경을 위한 클러스터 구성
3. **장기 저장소**: Thanos 또는 Cortex를 통한 메트릭 장기 보관

## 9. 참고 자료

- [Prometheus 공식 문서](https://prometheus.io/docs/)
- [PromQL 쿼리 가이드](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Alertmanager 설정 가이드](https://prometheus.io/docs/alerting/latest/alertmanager/)
- [Kubernetes 모니터링 가이드](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)