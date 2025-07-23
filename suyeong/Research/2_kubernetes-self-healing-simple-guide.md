# Kubernetes 자가 복구 모니터링 시스템 - 쉬운 가이드
(.with_gemini-cli)
## 🎯 뭘 만들까요?

### 간단히 말하면
- **Pod가 죽으면 자동으로 다시 살려주는 시스템**
- **서버가 바쁘면 자동으로 서버를 늘려주는 시스템**
- **문제가 생기면 Slack으로 알려주는 시스템**

### 왜 필요할까요?
- 밤에 서버 터져도 자동으로 고쳐짐 → 잠 잘 잘 수 있음 😴
- 갑자기 사용자 몰려도 자동으로 서버 늘어남 → 서비스 안 터짐 ⚡
- 뭔가 이상하면 바로 알려줌 → 빨리 대응 가능 🔔

## 🏗️ 필요한 것들

### 1. 모니터링 도구들
```
Prometheus ← 메트릭 수집하는 친구
Grafana    ← 예쁜 차트로 보여주는 친구  
AlertManager ← 문제생기면 알려주는 친구
```

### 2. 자동 복구 도구들
```
HPA ← Pod 개수 자동 조절
VPA ← Pod 크기 자동 조절  
Robusta ← AI가 문제 자동 해결
```

### 3. 기본 원리
```
1. Prometheus가 계속 메트릭 수집
2. 문제 발견하면 AlertManager가 알림
3. HPA/VPA가 자동으로 Pod 조절
4. Grafana로 상황 모니터링
```

## 🚀 설치하기

### 1단계: 기본 모니터링 설치

```bash
# Helm 리포 추가
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# 모니터링 네임스페이스 생성
kubectl create namespace monitoring

# 한 번에 다 설치 (Prometheus + Grafana + AlertManager)
helm install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --set grafana.adminPassword=admin123
```

### 2단계: 접속해보기

```bash
# Grafana 웹 접속하기 (localhost:3000)
kubectl port-forward --namespace monitoring svc/monitoring-grafana 3000:80

# 로그인 정보
# ID: admin
# PW: admin123
```

### 3단계: 기본 대시보드 확인
1. 웹브라우저에서 `http://localhost:3000` 접속
2. 왼쪽 메뉴 → Dashboards → Browse
3. 기본 제공되는 대시보드들 확인:
   - **Kubernetes / Compute Resources / Cluster**
   - **Kubernetes / Compute Resources / Node**

## 🔄 자동 복구 설정하기

### 1. 애플리케이션 예시 (건강검사 포함)

```yaml
# my-app.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: app
        image: nginx:latest
        ports:
        - containerPort: 80
        
        # 💡 이 부분이 핵심! 건강검사 설정
        livenessProbe:     # 죽으면 재시작
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 10
          periodSeconds: 10
        
        readinessProbe:    # 준비되면 트래픽 받음
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5
        
        # 리소스 제한
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
---
apiVersion: v1
kind: Service
metadata:
  name: my-app-service
spec:
  selector:
    app: my-app
  ports:
  - port: 80
    targetPort: 80
```

### 2. 자동 스케일링 설정

```yaml
# auto-scaling.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: my-app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-app
  minReplicas: 2    # 최소 2개
  maxReplicas: 10   # 최대 10개
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70  # CPU 70% 넘으면 Pod 늘림
```

### 3. 배포하기

```bash
kubectl apply -f my-app.yaml
kubectl apply -f auto-scaling.yaml

# 확인하기
kubectl get pods
kubectl get hpa
```

## 📱 알림 설정하기

### Slack 알림 설정

```yaml
# slack-alert.yaml
apiVersion: v1
kind: Secret
metadata:
  name: alertmanager-main
  namespace: monitoring
stringData:
  alertmanager.yml: |
    global:
      slack_api_url: 'YOUR_SLACK_WEBHOOK_URL'
    
    route:
      receiver: 'slack-alerts'
    
    receivers:
    - name: 'slack-alerts'
      slack_configs:
      - channel: '#alerts'
        title: '🚨 Kubernetes 문제 발생!'
        text: |
          문제: {{ .CommonAnnotations.summary }}
          시간: {{ .CommonAnnotations.timestamp }}
```

### Slack Webhook URL 만들기
1. Slack → Apps → Incoming Webhooks
2. Add to Slack → 채널 선택
3. Webhook URL 복사해서 위 YAML에 넣기

## 🧪 테스트해보기

### 1. 부하 테스트로 스케일링 확인

```bash
# 부하 테스트 Pod 실행
kubectl run -i --tty load-generator --rm --image=busybox --restart=Never -- /bin/sh

# Pod 안에서 실행
while true; do wget -q -O- http://my-app-service/; done
```

```bash
# 다른 터미널에서 확인
watch kubectl get hpa
watch kubectl get pods
```

### 2. Pod 강제 삭제로 복구 확인

```bash
# Pod 하나 강제 삭제
kubectl delete pod -l app=my-app --force

# 자동으로 새 Pod 생성되는지 확인
kubectl get pods -w
```

## 📊 주요 메트릭 보는 법

### Grafana에서 확인할 것들

1. **Pod 상태**
   - Running/Pending/Failed Pod 개수
   - 쿼리: `sum by (phase) (kube_pod_status_phase)`

2. **CPU 사용률**
   - 전체 클러스터 CPU 사용률
   - 쿼리: `1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))`

3. **메모리 사용률**
   - 전체 클러스터 메모리 사용률
   - 쿼리: `1 - sum(node_memory_MemAvailable_bytes) / sum(node_memory_MemTotal_bytes)`

4. **Pod 재시작**
   - Pod가 얼마나 자주 재시작되는지
   - 쿼리: `rate(kube_pod_container_status_restarts_total[5m])`

## 🎛️ 간단한 알림 규칙

```yaml
# simple-alerts.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: simple-alerts
  namespace: monitoring
spec:
  groups:
  - name: basic
    rules:
    
    # Pod가 계속 재시작되고 있음
    - alert: PodKeepRestarting
      expr: rate(kube_pod_container_status_restarts_total[10m]) > 0
      for: 1m
      annotations:
        summary: "Pod {{ $labels.pod }}가 계속 재시작되고 있어요!"
    
    # CPU 사용률이 너무 높음
    - alert: HighCPUUsage
      expr: 1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) > 0.8
      for: 5m
      annotations:
        summary: "CPU 사용률이 80% 넘었어요!"
    
    # 메모리 사용률이 너무 높음
    - alert: HighMemoryUsage
      expr: 1 - sum(node_memory_MemAvailable_bytes) / sum(node_memory_MemTotal_bytes) > 0.9
      for: 5m
      annotations:
        summary: "메모리 사용률이 90% 넘었어요!"
    
    # Pod가 없어졌음
    - alert: PodDown
      expr: up == 0
      for: 1m
      annotations:
        summary: "Pod {{ $labels.instance }}가 응답하지 않아요!"
```

```bash
kubectl apply -f simple-alerts.yaml
```

## ✅ 확인 체크리스트

### 설치 완료 확인
- [ ] Prometheus 실행 중: `kubectl get pods -n monitoring | grep prometheus`
- [ ] Grafana 실행 중: `kubectl get pods -n monitoring | grep grafana`
- [ ] AlertManager 실행 중: `kubectl get pods -n monitoring | grep alertmanager`

### 기능 테스트 확인
- [ ] 앱 배포됨: `kubectl get pods | grep my-app`
- [ ] HPA 설정됨: `kubectl get hpa`
- [ ] 부하 테스트시 Pod 늘어남
- [ ] Pod 삭제시 자동 복구됨
- [ ] Slack 알림 오는지 확인

### Grafana 대시보드 확인
- [ ] CPU/메모리 차트 보임
- [ ] Pod 상태 차트 보임
- [ ] 네트워크 트래픽 차트 보임

## 🔧 문제 해결

### 자주 있는 문제들

1. **Grafana 접속 안됨**
   ```bash
   # 서비스 상태 확인
   kubectl get svc -n monitoring
   # 포트포워딩 다시 시도
   kubectl port-forward --namespace monitoring svc/monitoring-grafana 3000:80
   ```

2. **HPA가 작동 안함**
   ```bash
   # metrics-server 설치 필요
   kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
   
   # HPA 상태 확인
   kubectl describe hpa my-app-hpa
   ```

3. **알림이 안옴**
   ```bash
   # AlertManager 설정 확인
   kubectl get secret alertmanager-main -n monitoring -o yaml
   
   # AlertManager 로그 확인
   kubectl logs -n monitoring alertmanager-monitoring-kube-prometheus-alertmanager-0
   ```

## 🎯 다음 단계

### 더 고급 기능들
1. **커스텀 메트릭 추가** - 애플리케이션별 특별한 메트릭
2. **분산 추적** - 요청이 여러 서비스를 거쳐가는 경로 추적
3. **카오스 엔지니어링** - 의도적으로 장애를 일으켜서 복원력 테스트
4. **멀티 클러스터 모니터링** - 여러 Kubernetes 클러스터 통합 관리

### 운영 팁
- 매일 한 번씩 Grafana 대시보드 확인하기
- 주간 단위로 알림 규칙 점검하기
- 월간 단위로 리소스 사용량 분석하기
- 장애 발생시 사후 분석하여 알림 규칙 개선하기

---

## 📚 유용한 명령어 모음

```bash
# 전체 Pod 상태 확인
kubectl get pods --all-namespaces

# 특정 Pod 로그 확인
kubectl logs <pod-name> -f

# 리소스 사용량 확인
kubectl top nodes
kubectl top pods

# HPA 상태 자세히 보기
kubectl describe hpa

# Prometheus 쿼리 직접 테스트
kubectl port-forward -n monitoring svc/monitoring-kube-prometheus-prometheus 9090:9090
# 브라우저에서 localhost:9090 접속

# AlertManager 웹 접속
kubectl port-forward -n monitoring svc/monitoring-kube-prometheus-alertmanager 9093:9093
# 브라우저에서 localhost:9093 접속
```

이 가이드로 시작하면 기본적인 자가 복구 모니터링 시스템을 만들 수 있어요! 🚀