# 컨테이너화 및 오케스트레이션 (Phase 2-1)

## 개요
모니터링 시스템의 컨테이너화 및 Kubernetes 배포를 위한 핵심 기술과 구현 방법을 학습합니다.

## 1. Docker 기초

### 1.1 모니터링 구성 요소를 위한 멀티 스테이지 빌드
```dockerfile
# Prometheus 커스텀 빌드 예제
FROM golang:1.21 AS builder
WORKDIR /app
COPY prometheus-config/ .
RUN go mod download
RUN go build -o prometheus-custom

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/prometheus-custom .
COPY prometheus.yml .
EXPOSE 9090
CMD ["./prometheus-custom"]
```

**핵심 원칙:**
- 이미지 크기 최소화
- 보안 취약점 감소
- 빌드 의존성과 런타임 분리

### 1.2 컨테이너 리소스 제한 및 모니터링
```yaml
# docker-compose.yml 예제
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 1G
          cpus: '0.5'
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:9090/-/healthy"]
      interval: 30s
      timeout: 10s
      retries: 3
```

**모니터링 메트릭:**
- CPU 사용률: `container_cpu_usage_seconds_total`
- 메모리 사용률: `container_memory_usage_bytes`
- 네트워크 I/O: `container_network_receive_bytes_total`

### 1.3 모니터링 스택을 위한 네트워크 구성
```yaml
networks:
  monitoring:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
          
services:
  prometheus:
    networks:
      monitoring:
        ipv4_address: 172.20.0.10
        
  grafana:
    networks:
      monitoring:
        ipv4_address: 172.20.0.20
```

**보안 고려사항:**
- 내부 통신용 격리된 네트워크
- 외부 노출 최소화
- TLS 암호화

### 1.4 영구 데이터 저장을 위한 볼륨 관리
```yaml
volumes:
  prometheus_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/monitoring/prometheus
      
  grafana_data:
    driver: local
    driver_opts:
      type: none  
      o: bind
      device: /opt/monitoring/grafana
```

## 2. Kubernetes 구현

### 2.1 모니터링 스택 배포를 위한 Helm 차트

**Chart.yaml**
```yaml
apiVersion: v2
name: monitoring-stack
description: Comprehensive monitoring solution
version: 1.0.0
appVersion: "2.0"
dependencies:
  - name: prometheus
    version: 25.8.0
    repository: https://prometheus-community.github.io/helm-charts
  - name: grafana
    version: 7.0.0
    repository: https://grafana.github.io/helm-charts
```

**values.yaml**
```yaml
prometheus:
  server:
    persistentVolume:
      size: 50Gi
      storageClass: "fast-ssd"
    resources:
      requests:
        memory: "2Gi"
        cpu: "1000m"
      limits:
        memory: "4Gi" 
        cpu: "2000m"
        
grafana:
  persistence:
    enabled: true
    size: 10Gi
  adminPassword: "secure-password"
  datasources:
    datasources.yaml:
      apiVersion: 1
      datasources:
        - name: Prometheus
          type: prometheus
          url: http://prometheus-server:80
```

### 2.2 Prometheus Operator 및 커스텀 리소스

**ServiceMonitor 예제**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: app-metrics
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: my-application
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

**PrometheusRule 예제**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: application-rules
spec:
  groups:
  - name: application.rules
    rules:
    - alert: HighErrorRate
      expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High error rate detected"
```

### 2.3 서비스 메시 모니터링 (Istio 통합)

**Istio 텔레메트리 구성**
```yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: control-plane
spec:
  values:
    telemetry:
      v2:
        prometheus:
          configOverride:
            metric_relabeling_configs:
            - source_labels: [__name__]
              regex: 'istio_.*'
              target_label: __tmp_istio_metric
```

### 2.4 커스텀 메트릭 기반 수평 파드 자동 확장

**HPA with Custom Metrics**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-app
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000m"
```

## 3. 실습 과제

### 과제 1: 모니터링 스택 컨테이너화
1. Prometheus, Grafana, AlertManager를 위한 Docker 이미지 생성
2. 멀티 스테이지 빌드로 최적화
3. 보안 스캔 및 취약점 검사

### 과제 2: Kubernetes 배포
1. Helm 차트로 모니터링 스택 배포
2. Prometheus Operator 설치 및 구성
3. 샘플 애플리케이션에 ServiceMonitor 적용

### 과제 3: 서비스 메시 통합
1. Istio 설치 및 구성
2. 마이크로서비스 간 트래픽 모니터링
3. 서비스 의존성 시각화

## 4. 트러블슈팅 가이드

### 일반적인 문제들
1. **Pod OOMKilled**: 메모리 제한 증가 또는 최적화
2. **ImagePullBackOff**: 이미지 태그 및 레지스트리 확인
3. **PVC Pending**: StorageClass 및 PV 가용성 확인

### 디버깅 명령어
```bash
# Pod 로그 확인
kubectl logs -f prometheus-server-0 -n monitoring

# 리소스 사용량 확인
kubectl top pods -n monitoring

# 이벤트 확인
kubectl get events -n monitoring --sort-by='.lastTimestamp'
```

## 5. 다음 단계
- 고가용성 및 확장성 (Phase 2-2)
- 보안 및 컴플라이언스 (Phase 2-3)
- 실제 운영 환경 구축