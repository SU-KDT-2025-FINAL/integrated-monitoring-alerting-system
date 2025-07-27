# 자동화 및 자가 치유 (Phase 3-2)

## 개요
모니터링 데이터를 기반으로 한 자동화된 수정, 자가 치유 시스템, 카오스 엔지니어링을 통한 시스템 복원력 향상 방법을 학습합니다.

## 1. 자동화된 수정 시스템

### 1.1 Ansible 플레이북 통합

**Ansible 자동화 프레임워크**
```yaml
# ansible-automation.yml
---
- name: Automated Incident Response Playbooks
  hosts: monitoring
  vars:
    prometheus_url: "http://prometheus:9090"
    notification_webhook: "{{ vault_notification_webhook }}"
    
  tasks:
  - name: Setup automation directory structure
    file:
      path: "{{ item }}"
      state: directory
      mode: '0755'
    loop:
      - /opt/monitoring/playbooks
      - /opt/monitoring/scripts
      - /opt/monitoring/logs
      
  - name: Deploy response scripts
    template:
      src: "{{ item }}.j2"
      dest: "/opt/monitoring/scripts/{{ item }}"
      mode: '0755'
    loop:
      - disk_cleanup.sh
      - service_restart.sh
      - scale_application.sh
      - network_diagnostics.sh
```

**고급 수정 플레이북**
```yaml
# playbooks/disk_space_recovery.yml
---
- name: Automated Disk Space Recovery
  hosts: "{{ target_hosts | default('all') }}"
  gather_facts: yes
  vars:
    disk_threshold: 90
    cleanup_paths:
      - /var/log
      - /tmp
      - /var/cache
      
  tasks:
  - name: Check current disk usage
    shell: df -h / | tail -1 | awk '{print $5}' | sed 's/%//'
    register: current_usage
    
  - name: Skip if disk usage is acceptable
    meta: end_play
    when: current_usage.stdout|int < disk_threshold
    
  - name: Log cleanup operation start
    lineinfile:
      path: /var/log/auto-cleanup.log
      line: "{{ ansible_date_time.iso8601 }} - Starting automated cleanup on {{ ansible_hostname }}"
      create: yes
      
  - name: Clean old log files (>7 days)
    find:
      paths: /var/log
      age: 7d
      file_type: file
      patterns: "*.log,*.log.*"
    register: old_logs
    
  - name: Remove old log files
    file:
      path: "{{ item.path }}"
      state: absent
    loop: "{{ old_logs.files }}"
    when: old_logs.files|length > 0
    
  - name: Clean package cache
    package:
      autoremove: yes
      autoclean: yes
    when: ansible_pkg_mgr == "apt"
    
  - name: Clean Docker images and containers
    shell: |
      docker system prune -f
      docker image prune -a -f
    ignore_errors: yes
    when: ansible_service_mgr == "systemd"
    
  - name: Verify disk space improvement
    shell: df -h / | tail -1 | awk '{print $5}' | sed 's/%//'
    register: final_usage
    
  - name: Report cleanup results
    uri:
      url: "{{ notification_webhook }}"
      method: POST
      body_format: json
      body:
        text: |
          Disk cleanup completed on {{ ansible_hostname }}
          Before: {{ current_usage.stdout }}%
          After: {{ final_usage.stdout }}%
          Freed: {{ (current_usage.stdout|int - final_usage.stdout|int) }}%
    delegate_to: localhost
```

**서비스 복구 플레이북**
```yaml
# playbooks/service_recovery.yml
---
- name: Intelligent Service Recovery
  hosts: "{{ target_hosts }}"
  vars:
    service_name: "{{ service_to_recover }}"
    max_restart_attempts: 3
    health_check_url: "{{ service_health_url | default('') }}"
    
  tasks:
  - name: Check service status
    systemd:
      name: "{{ service_name }}"
    register: service_status
    
  - name: Get service logs before restart
    shell: journalctl -u {{ service_name }} -n 50 --no-pager
    register: pre_restart_logs
    when: service_status.status.ActiveState != "active"
    
  - name: Attempt service restart
    systemd:
      name: "{{ service_name }}"
      state: restarted
      daemon_reload: yes
    register: restart_result
    retries: "{{ max_restart_attempts }}"
    delay: 30
    until: restart_result is succeeded
    when: service_status.status.ActiveState != "active"
    
  - name: Wait for service to stabilize
    wait_for:
      timeout: 60
    when: restart_result is changed
    
  - name: Perform health check
    uri:
      url: "{{ health_check_url }}"
      method: GET
      status_code: 200
      timeout: 30
    register: health_check
    retries: 5
    delay: 10
    when: health_check_url != ""
    
  - name: Get post-restart service status
    systemd:
      name: "{{ service_name }}"
    register: final_status
    
  - name: Report recovery status
    debug:
      msg: |
        Service Recovery Report:
        Service: {{ service_name }}
        Host: {{ ansible_hostname }}
        Initial Status: {{ service_status.status.ActiveState }}
        Final Status: {{ final_status.status.ActiveState }}
        Health Check: {{ 'PASS' if health_check.status == 200 else 'FAIL' }}
        
  - name: Send recovery notification
    uri:
      url: "{{ notification_webhook }}"
      method: POST
      body_format: json
      body:
        alert_type: "recovery_report"
        service: "{{ service_name }}"
        host: "{{ ansible_hostname }}"
        status: "{{ 'SUCCESS' if final_status.status.ActiveState == 'active' else 'FAILED' }}"
        details: "{{ final_status }}"
    delegate_to: localhost
```

### 1.2 Kubernetes 기반 자동 확장 및 자가 치유

**커스텀 메트릭 기반 HPA**
```yaml
# custom-hpa.yml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: intelligent-hpa
  namespace: production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-application
  minReplicas: 2
  maxReplicas: 50
  
  metrics:
  # CPU 기반 확장
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
        
  # 메모리 기반 확장  
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
        
  # 큐 길이 기반 확장
  - type: Pods
    pods:
      metric:
        name: queue_length
      target:
        type: AverageValue
        averageValue: "30"
        
  # 응답 시간 기반 확장
  - type: Pods
    pods:
      metric:
        name: http_request_duration_seconds
      target:
        type: AverageValue
        averageValue: "0.5"
        
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
      - type: Pods
        value: 4
        periodSeconds: 60
      selectPolicy: Max
      
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
      selectPolicy: Min
```

**자가 치유 Operator**
```go
// self-healing-operator.go
package main

import (
    "context"
    "fmt"
    "time"
    
    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"
)

type SelfHealingReconciler struct {
    client.Client
    Scheme *runtime.Scheme
    PrometheusClient *prometheus.Client
}

func (r *SelfHealingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    // 1. Pod 상태 모니터링
    pods := &corev1.PodList{}
    if err := r.List(ctx, pods, client.InNamespace(req.Namespace)); err != nil {
        return ctrl.Result{}, err
    }
    
    for _, pod := range pods.Items {
        if r.isPodUnhealthy(pod) {
            if err := r.healPod(ctx, &pod); err != nil {
                return ctrl.Result{}, err
            }
        }
    }
    
    // 2. 서비스 상태 체크
    if err := r.checkServiceHealth(ctx, req.Namespace); err != nil {
        return ctrl.Result{RequeueAfter: time.Minute * 5}, err
    }
    
    // 3. 리소스 사용량 최적화
    if err := r.optimizeResources(ctx, req.Namespace); err != nil {
        return ctrl.Result{}, err
    }
    
    return ctrl.Result{RequeueAfter: time.Minute * 2}, nil
}

func (r *SelfHealingReconciler) isPodUnhealthy(pod corev1.Pod) bool {
    // Pod 상태 검사 로직
    if pod.Status.Phase == corev1.PodFailed {
        return true
    }
    
    // 재시작 횟수 체크
    for _, containerStatus := range pod.Status.ContainerStatuses {
        if containerStatus.RestartCount > 5 {
            return true
        }
        
        if !containerStatus.Ready && containerStatus.State.Waiting != nil {
            waitingReason := containerStatus.State.Waiting.Reason
            if waitingReason == "CrashLoopBackOff" || waitingReason == "ImagePullBackOff" {
                return true
            }
        }
    }
    
    // 메트릭 기반 건강성 체크
    return r.checkPodMetrics(pod)
}

func (r *SelfHealingReconciler) healPod(ctx context.Context, pod *corev1.Pod) error {
    // 치유 전략 결정
    strategy := r.determineHealingStrategy(pod)
    
    switch strategy {
    case "restart":
        return r.restartPod(ctx, pod)
    case "reschedule":
        return r.reschedulePod(ctx, pod)
    case "scale":
        return r.scaleDeployment(ctx, pod)
    default:
        return fmt.Errorf("unknown healing strategy: %s", strategy)
    }
}

func (r *SelfHealingReconciler) checkPodMetrics(pod corev1.Pod) bool {
    // Prometheus 메트릭을 통한 건강성 체크
    queries := []string{
        fmt.Sprintf(`rate(container_cpu_usage_seconds_total{pod="%s"}[5m]) > 0.8`, pod.Name),
        fmt.Sprintf(`container_memory_usage_bytes{pod="%s"} / container_spec_memory_limit_bytes > 0.9`, pod.Name),
        fmt.Sprintf(`up{pod="%s"} == 0`, pod.Name),
    }
    
    for _, query := range queries {
        result, err := r.PrometheusClient.Query(context.Background(), query, time.Now())
        if err != nil {
            continue
        }
        
        if len(result.(model.Vector)) > 0 {
            return true // 건강하지 않음
        }
    }
    
    return false
}
```

### 1.3 서킷 브레이커 패턴 구현

**Go 서킷 브레이커**
```go
// circuit_breaker.go
package circuitbreaker

import (
    "context"
    "fmt"
    "sync"
    "time"
)

type State int

const (
    Closed State = iota
    Open
    HalfOpen
)

type CircuitBreaker struct {
    name               string
    maxRequests        uint32
    interval           time.Duration
    timeout            time.Duration
    readyToTrip        func(counts Counts) bool
    onStateChange      func(name string, from State, to State)
    
    mutex              sync.Mutex
    state              State
    generation         uint64
    counts             Counts
    expiry             time.Time
}

type Counts struct {
    Requests             uint32
    TotalSuccesses       uint32
    TotalFailures        uint32
    ConsecutiveSuccesses uint32
    ConsecutiveFailures  uint32
}

func NewCircuitBreaker(settings Settings) *CircuitBreaker {
    cb := &CircuitBreaker{
        name:          settings.Name,
        maxRequests:   settings.MaxRequests,
        interval:      settings.Interval,
        timeout:       settings.Timeout,
        readyToTrip:   settings.ReadyToTrip,
        onStateChange: settings.OnStateChange,
    }
    
    cb.toNewGeneration(time.Now())
    return cb
}

func (cb *CircuitBreaker) Execute(req func() (interface{}, error)) (interface{}, error) {
    generation, err := cb.beforeRequest()
    if err != nil {
        return nil, err
    }
    
    defer func() {
        e := recover()
        if e != nil {
            cb.afterRequest(generation, false)
            panic(e)
        }
    }()
    
    result, err := req()
    cb.afterRequest(generation, err == nil)
    return result, err
}

func (cb *CircuitBreaker) beforeRequest() (uint64, error) {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    now := time.Now()
    state, generation := cb.currentState(now)
    
    if state == Open {
        return generation, fmt.Errorf("circuit breaker is open")
    } else if state == HalfOpen && cb.counts.Requests >= cb.maxRequests {
        return generation, fmt.Errorf("too many requests in half-open state")
    }
    
    cb.counts.onRequest()
    return generation, nil
}

func (cb *CircuitBreaker) afterRequest(before uint64, success bool) {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    now := time.Now()
    state, generation := cb.currentState(now)
    if generation != before {
        return
    }
    
    if success {
        cb.onSuccess(state, now)
    } else {
        cb.onFailure(state, now)
    }
}

// 적응형 서킷 브레이커
type AdaptiveCircuitBreaker struct {
    *CircuitBreaker
    errorRateWindow    time.Duration
    latencyThreshold   time.Duration
    recentRequests     []RequestRecord
    mutex              sync.RWMutex
}

type RequestRecord struct {
    Timestamp time.Time
    Success   bool
    Latency   time.Duration
}

func (acb *AdaptiveCircuitBreaker) shouldTrip() bool {
    acb.mutex.RLock()
    defer acb.mutex.RUnlock()
    
    now := time.Now()
    cutoff := now.Add(-acb.errorRateWindow)
    
    var totalRequests, failures int
    var totalLatency time.Duration
    
    for _, record := range acb.recentRequests {
        if record.Timestamp.After(cutoff) {
            totalRequests++
            if !record.Success {
                failures++
            }
            totalLatency += record.Latency
        }
    }
    
    if totalRequests == 0 {
        return false
    }
    
    // 오류율 기반 판단
    errorRate := float64(failures) / float64(totalRequests)
    if errorRate > 0.5 { // 50% 이상 실패
        return true
    }
    
    // 지연시간 기반 판단
    avgLatency := totalLatency / time.Duration(totalRequests)
    if avgLatency > acb.latencyThreshold {
        return true
    }
    
    return false
}
```

### 1.4 카오스 엔지니어링을 통한 복원력 향상

**Chaos Monkey 구현**
```python
# chaos_monkey.py
import random
import time
import kubernetes
from kubernetes import client, config
import docker
import psutil
import logging

class ChaosMonkey:
    def __init__(self, config_file="chaos_config.yaml"):
        self.config = self._load_config(config_file)
        self.k8s_client = self._init_k8s_client()
        self.docker_client = docker.from_env()
        self.logger = self._setup_logging()
        
    def run_chaos_experiment(self, experiment_type):
        """카오스 실험 실행"""
        experiments = {
            'pod_killer': self._kill_random_pods,
            'network_latency': self._inject_network_latency,
            'cpu_stress': self._inject_cpu_stress,
            'memory_stress': self._inject_memory_stress,
            'disk_fill': self._fill_disk_space,
            'service_degradation': self._degrade_service_performance
        }
        
        if experiment_type not in experiments:
            raise ValueError(f"Unknown experiment type: {experiment_type}")
            
        self.logger.info(f"Starting chaos experiment: {experiment_type}")
        
        try:
            # 실험 전 상태 기록
            pre_state = self._capture_system_state()
            
            # 카오스 실험 실행
            experiment_result = experiments[experiment_type]()
            
            # 복구 대기
            time.sleep(self.config['recovery_wait_time'])
            
            # 실험 후 상태 기록
            post_state = self._capture_system_state()
            
            # 결과 분석
            analysis = self._analyze_experiment_results(
                experiment_type, pre_state, post_state, experiment_result
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Chaos experiment failed: {e}")
            self._emergency_cleanup()
            raise
            
    def _kill_random_pods(self):
        """무작위 Pod 종료"""
        v1 = client.CoreV1Api()
        
        # 실험 대상 네임스페이스의 Pod 목록 조회
        target_namespaces = self.config.get('target_namespaces', ['default'])
        all_pods = []
        
        for namespace in target_namespaces:
            pods = v1.list_namespaced_pod(namespace)
            # 중요한 시스템 Pod 제외
            filtered_pods = [
                pod for pod in pods.items 
                if not self._is_system_pod(pod)
            ]
            all_pods.extend(filtered_pods)
            
        if not all_pods:
            return {"result": "no_target_pods"}
            
        # 무작위로 Pod 선택 및 종료
        kill_count = min(
            self.config.get('max_pods_to_kill', 1),
            len(all_pods)
        )
        
        pods_to_kill = random.sample(all_pods, kill_count)
        killed_pods = []
        
        for pod in pods_to_kill:
            try:
                v1.delete_namespaced_pod(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    grace_period_seconds=0
                )
                killed_pods.append({
                    'name': pod.metadata.name,
                    'namespace': pod.metadata.namespace
                })
                self.logger.info(f"Killed pod: {pod.metadata.name}")
                
            except Exception as e:
                self.logger.error(f"Failed to kill pod {pod.metadata.name}: {e}")
                
        return {"killed_pods": killed_pods}
    
    def _inject_network_latency(self):
        """네트워크 지연 주입"""
        import subprocess
        
        latency_ms = self.config.get('network_latency_ms', 100)
        duration_seconds = self.config.get('network_chaos_duration', 300)
        
        # tc를 사용하여 네트워크 지연 추가
        commands = [
            f"tc qdisc add dev eth0 root netem delay {latency_ms}ms",
            f"sleep {duration_seconds}",
            "tc qdisc del dev eth0 root"
        ]
        
        try:
            for cmd in commands:
                subprocess.run(cmd, shell=True, check=True)
                
            return {
                "latency_ms": latency_ms,
                "duration_seconds": duration_seconds,
                "status": "completed"
            }
            
        except subprocess.CalledProcessError as e:
            return {"status": "failed", "error": str(e)}
    
    def _inject_cpu_stress(self):
        """CPU 스트레스 주입"""
        import multiprocessing
        import threading
        
        cpu_percent = self.config.get('cpu_stress_percent', 80)
        duration_seconds = self.config.get('cpu_stress_duration', 300)
        
        def cpu_stress_worker():
            end_time = time.time() + duration_seconds
            while time.time() < end_time:
                # CPU 집약적 작업
                for _ in range(10000):
                    pass
                time.sleep(0.01)  # 일시 정지로 CPU 사용률 조절
        
        # CPU 코어 수에 따라 스레드 수 결정
        num_cores = multiprocessing.cpu_count()
        num_threads = int(num_cores * (cpu_percent / 100))
        
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=cpu_stress_worker)
            thread.start()
            threads.append(thread)
            
        # 모든 스레드 완료 대기
        for thread in threads:
            thread.join()
            
        return {
            "cpu_percent": cpu_percent,
            "duration_seconds": duration_seconds,
            "threads_used": num_threads,
            "status": "completed"
        }
    
    def _capture_system_state(self):
        """시스템 상태 캡처"""
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        
        state = {
            'timestamp': time.time(),
            'pods': {},
            'deployments': {},
            'services': {},
            'system_metrics': {}
        }
        
        # Pod 상태
        for namespace in self.config.get('target_namespaces', ['default']):
            pods = v1.list_namespaced_pod(namespace)
            state['pods'][namespace] = [
                {
                    'name': pod.metadata.name,
                    'phase': pod.status.phase,
                    'ready': all(c.ready for c in pod.status.container_statuses or [])
                }
                for pod in pods.items
            ]
            
            # Deployment 상태
            deployments = apps_v1.list_namespaced_deployment(namespace)
            state['deployments'][namespace] = [
                {
                    'name': dep.metadata.name,
                    'replicas': dep.spec.replicas,
                    'ready_replicas': dep.status.ready_replicas or 0
                }
                for dep in deployments.items
            ]
            
        # 시스템 메트릭
        state['system_metrics'] = {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent
        }
        
        return state
    
    def _analyze_experiment_results(self, experiment_type, pre_state, post_state, experiment_result):
        """실험 결과 분석"""
        analysis = {
            'experiment_type': experiment_type,
            'experiment_result': experiment_result,
            'recovery_analysis': {},
            'performance_impact': {},
            'recommendations': []
        }
        
        # 복구 시간 분석
        recovery_time = self._calculate_recovery_time(pre_state, post_state)
        analysis['recovery_analysis']['recovery_time_seconds'] = recovery_time
        
        # 성능 영향 분석
        cpu_impact = post_state['system_metrics']['cpu_percent'] - pre_state['system_metrics']['cpu_percent']
        memory_impact = post_state['system_metrics']['memory_percent'] - pre_state['system_metrics']['memory_percent']
        
        analysis['performance_impact'] = {
            'cpu_delta': cpu_impact,
            'memory_delta': memory_impact
        }
        
        # 권장사항 생성
        if recovery_time > 300:  # 5분 이상
            analysis['recommendations'].append("Consider implementing faster health checks")
            
        if cpu_impact > 20:
            analysis['recommendations'].append("Review resource limits and requests")
            
        return analysis
```

## 2. 워크플로 자동화

### 2.1 StackStorm 통합

**StackStorm 액션 팩**
```yaml
# actions/prometheus_alert_handler.yaml
name: prometheus_alert_handler
runner_type: python-script
description: Handle Prometheus alerts with intelligent automation
enabled: true
entry_point: prometheus_alert_handler.py

parameters:
  alert_data:
    type: object
    description: Prometheus alert data
    required: true
  
  response_level:
    type: string
    description: Response automation level
    enum: ['info', 'auto', 'manual']
    default: 'auto'
    
  dry_run:
    type: boolean
    description: Perform dry run without actual changes
    default: false
```

**자동화 워크플로**
```yaml
# rules/intelligent_incident_response.yaml
name: intelligent_incident_response
description: Intelligent incident response workflow
enabled: true

trigger:
  type: core.st2.webhook
  parameters:
    url: prometheus_alert

criteria:
  trigger.body.status: "firing"
  trigger.body.labels.severity: "critical|warning"

action:
  ref: workflows.incident_response_workflow
  parameters:
    alert_data: "{{ trigger.body }}"
    severity: "{{ trigger.body.labels.severity }}"
    alert_name: "{{ trigger.body.labels.alertname }}"
```

**워크플로 정의**
```yaml
# actions/workflows/incident_response_workflow.yaml
version: 1.0
description: Comprehensive incident response workflow

input:
  - alert_data
  - severity
  - alert_name

vars:
  - remediation_actions: []
  - escalation_required: false

tasks:
  # 1. 알림 분석 및 분류
  analyze_alert:
    action: custom.analyze_prometheus_alert
    input:
      alert_data: <% ctx().alert_data %>
    next:
      - when: <% succeeded() %>
        do: determine_response_strategy

  # 2. 대응 전략 결정  
  determine_response_strategy:
    action: custom.determine_response_strategy
    input:
      alert_analysis: <% result().analyze_alert %>
      severity: <% ctx().severity %>
    next:
      - when: <% result().strategy = "automated" %>
        do: execute_automated_response
      - when: <% result().strategy = "manual" %>
        do: create_incident_ticket
      - when: <% result().strategy = "escalate" %>
        do: escalate_to_oncall

  # 3. 자동화된 대응 실행
  execute_automated_response:
    action: workflows.automated_remediation
    input:
      alert_name: <% ctx().alert_name %>
      alert_data: <% ctx().alert_data %>
      remediation_plan: <% result().determine_response_strategy.remediation_plan %>
    next:
      - when: <% succeeded() %>
        do: verify_resolution
      - when: <% failed() %>
        do: escalate_to_oncall

  # 4. 해결 확인
  verify_resolution:
    action: custom.verify_alert_resolution
    input:
      alert_name: <% ctx().alert_name %>
      verification_timeout: 300
    next:
      - when: <% succeeded() and result().resolved %>
        do: close_incident
      - when: <% succeeded() and not result().resolved %>
        do: escalate_to_oncall
      - when: <% failed() %>
        do: escalate_to_oncall

  # 5. 인시던트 종료
  close_incident:
    action: custom.close_incident
    input:
      alert_data: <% ctx().alert_data %>
      resolution_summary: <% result().verify_resolution.summary %>
      
  # 6. 온콜 엔지니어 에스컬레이션
  escalate_to_oncall:
    action: custom.escalate_to_oncall
    input:
      alert_data: <% ctx().alert_data %>
      failed_actions: <% ctx().remediation_actions %>
      urgency: <% ctx().severity %>

output:
  - resolution_status: <% ctx().resolution_status %>
  - actions_taken: <% ctx().remediation_actions %>
  - escalation_required: <% ctx().escalation_required %>
```

### 2.2 ITSM 통합 (ServiceNow, Jira)

**ServiceNow 통합**
```python
# servicenow_integration.py
import requests
import json
from datetime import datetime

class ServiceNowIntegration:
    def __init__(self, instance_url, username, password):
        self.base_url = f"https://{instance_url}.service-now.com"
        self.auth = (username, password)
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def create_incident(self, alert_data):
        """Prometheus 알림으로부터 인시던트 생성"""
        severity_mapping = {
            'critical': '1',  # High
            'warning': '2',   # Medium  
            'info': '3'       # Low
        }
        
        impact_mapping = {
            'critical': '1',  # High
            'warning': '2',   # Medium
            'info': '3'       # Low
        }
        
        severity = alert_data.get('labels', {}).get('severity', 'info')
        
        incident_data = {
            'short_description': f"Monitoring Alert: {alert_data.get('labels', {}).get('alertname', 'Unknown')}",
            'description': self._format_alert_description(alert_data),
            'severity': severity_mapping.get(severity, '3'),
            'impact': impact_mapping.get(severity, '3'),
            'urgency': severity_mapping.get(severity, '3'),
            'category': 'Software',
            'subcategory': 'Monitoring',
            'assignment_group': self._determine_assignment_group(alert_data),
            'caller_id': 'monitoring.system@company.com',
            'u_monitoring_source': 'Prometheus',
            'u_alert_fingerprint': self._generate_fingerprint(alert_data),
            'work_notes': self._create_initial_work_notes(alert_data)
        }
        
        url = f"{self.base_url}/api/now/table/incident"
        response = requests.post(
            url, 
            auth=self.auth,
            headers=self.headers,
            data=json.dumps(incident_data)
        )
        
        if response.status_code == 201:
            incident = response.json()['result']
            return {
                'incident_number': incident['number'],
                'sys_id': incident['sys_id'],
                'state': incident['state']
            }
        else:
            raise Exception(f"Failed to create incident: {response.text}")
    
    def update_incident_with_resolution(self, incident_sys_id, resolution_data):
        """인시던트 해결 정보 업데이트"""
        update_data = {
            'state': '6',  # Resolved
            'resolution_code': 'Solved (Permanently)',
            'resolution_notes': resolution_data.get('resolution_summary', ''),
            'close_code': 'Solved (Permanently)',
            'close_notes': f"Automatically resolved by monitoring system. Actions taken: {resolution_data.get('actions_taken', 'N/A')}",
            'resolved_by': 'monitoring.system@company.com',
            'resolved_at': datetime.now().isoformat()
        }
        
        url = f"{self.base_url}/api/now/table/incident/{incident_sys_id}"
        response = requests.patch(
            url,
            auth=self.auth, 
            headers=self.headers,
            data=json.dumps(update_data)
        )
        
        return response.status_code == 200
    
    def _format_alert_description(self, alert_data):
        """알림 데이터를 ServiceNow 설명 형식으로 변환"""
        description = f"""
Monitoring Alert Details:
========================

Alert Name: {alert_data.get('labels', {}).get('alertname', 'N/A')}
Severity: {alert_data.get('labels', {}).get('severity', 'N/A')}
Instance: {alert_data.get('labels', {}).get('instance', 'N/A')}
Job: {alert_data.get('labels', {}).get('job', 'N/A')}

Alert Annotations:
{json.dumps(alert_data.get('annotations', {}), indent=2)}

Triggered At: {alert_data.get('startsAt', 'N/A')}
Generator URL: {alert_data.get('generatorURL', 'N/A')}
        """
        return description.strip()
```

### 2.3 런북 자동화

**자동화된 런북 시스템**
```python
# runbook_automation.py
import yaml
import subprocess
import logging
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class RunbookStep:
    name: str
    type: str  # command, api_call, wait, condition
    parameters: Dict[str, Any]
    timeout: int = 300
    retry_count: int = 3
    continue_on_error: bool = False

class RunbookExecutor:
    def __init__(self, runbook_directory="/opt/runbooks"):
        self.runbook_dir = runbook_directory
        self.logger = logging.getLogger(__name__)
        
    def execute_runbook(self, runbook_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """런북 실행"""
        runbook_path = f"{self.runbook_dir}/{runbook_name}.yaml"
        
        try:
            with open(runbook_path, 'r') as f:
                runbook_data = yaml.safe_load(f)
                
            runbook = self._parse_runbook(runbook_data)
            execution_result = self._execute_steps(runbook['steps'], context)
            
            return {
                'runbook_name': runbook_name,
                'status': 'completed' if execution_result['success'] else 'failed',
                'steps_executed': execution_result['steps_executed'],
                'total_steps': len(runbook['steps']),
                'execution_time': execution_result['execution_time'],
                'results': execution_result['step_results']
            }
            
        except Exception as e:
            self.logger.error(f"Runbook execution failed: {e}")
            return {
                'runbook_name': runbook_name,
                'status': 'error',
                'error': str(e)
            }
    
    def _execute_steps(self, steps: List[RunbookStep], context: Dict[str, Any]) -> Dict[str, Any]:
        """런북 단계 실행"""
        start_time = time.time()
        step_results = []
        steps_executed = 0
        
        for step in steps:
            self.logger.info(f"Executing step: {step.name}")
            
            try:
                result = self._execute_single_step(step, context)
                step_results.append({
                    'step_name': step.name,
                    'status': 'success',
                    'result': result,
                    'execution_time': result.get('execution_time', 0)
                })
                steps_executed += 1
                
                # 컨텍스트 업데이트
                if result.get('context_updates'):
                    context.update(result['context_updates'])
                    
            except Exception as e:
                self.logger.error(f"Step {step.name} failed: {e}")
                step_results.append({
                    'step_name': step.name,
                    'status': 'failed',
                    'error': str(e)
                })
                
                if not step.continue_on_error:
                    break
                    
        execution_time = time.time() - start_time
        success = all(r['status'] == 'success' for r in step_results)
        
        return {
            'success': success,
            'steps_executed': steps_executed,
            'execution_time': execution_time,
            'step_results': step_results
        }
    
    def _execute_single_step(self, step: RunbookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """단일 런북 단계 실행"""
        if step.type == 'command':
            return self._execute_command_step(step, context)
        elif step.type == 'api_call':
            return self._execute_api_step(step, context)
        elif step.type == 'wait':
            return self._execute_wait_step(step, context)
        elif step.type == 'condition':
            return self._execute_condition_step(step, context)
        else:
            raise ValueError(f"Unknown step type: {step.type}")
    
    def _execute_command_step(self, step: RunbookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """명령어 실행 단계"""
        command = step.parameters['command']
        
        # 컨텍스트 변수 치환
        for key, value in context.items():
            command = command.replace(f"{{{key}}}", str(value))
            
        start_time = time.time()
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=step.timeout
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'return_code': result.returncode,
                    'execution_time': execution_time
                }
            else:
                raise Exception(f"Command failed with return code {result.returncode}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise Exception(f"Command timed out after {step.timeout} seconds")
```

**고장 진단 런북 예제**
```yaml
# runbooks/high_cpu_diagnosis.yaml
name: High CPU Usage Diagnosis and Remediation
description: Automated diagnosis and remediation for high CPU usage alerts
version: 1.0

metadata:
  alert_type: HighCPUUsage
  severity: warning|critical
  estimated_time: 10 minutes

parameters:
  - name: target_host
    description: Target host with high CPU usage
    required: true
  - name: cpu_threshold
    description: CPU usage threshold
    default: 80
  - name: max_restart_attempts
    description: Maximum service restart attempts
    default: 3

steps:
  - name: collect_system_info
    type: command
    description: Collect basic system information
    parameters:
      command: |
        echo "=== System Information ===" &&
        uname -a &&
        uptime &&
        free -h &&
        df -h
    timeout: 30

  - name: identify_cpu_consumers
    type: command
    description: Identify top CPU consuming processes
    parameters:
      command: |
        echo "=== Top CPU Consumers ===" &&
        ps aux --sort=-%cpu | head -20 &&
        echo "=== Load Average History ===" &&
        sar -u 1 5
    timeout: 60

  - name: check_service_health
    type: command
    description: Check critical service health
    parameters:
      command: |
        systemctl is-active nginx ||
        systemctl is-active apache2 ||
        systemctl is-active docker ||
        systemctl is-active kubernetes
    timeout: 30
    continue_on_error: true

  - name: analyze_cpu_pattern
    type: api_call
    description: Analyze CPU usage pattern
    parameters:
      url: "http://prometheus:9090/api/v1/query_range"
      method: GET
      params:
        query: "rate(node_cpu_seconds_total{instance=\"{target_host}\"}[5m])"
        start: "-1h"
        end: "now"
        step: "60s"
    timeout: 30

  - name: check_for_runaway_processes
    type: command
    description: Check for runaway processes
    parameters:
      command: |
        # 100% CPU 사용 프로세스 찾기
        ps aux | awk '$3 > 90.0 {print $2, $3, $11}' &&
        echo "=== Process Tree ===" &&
        pstree -p
    timeout: 30

  - name: attempt_process_optimization
    type: command
    description: Attempt to optimize high CPU processes
    parameters:
      command: |
        # 높은 CPU 사용률의 Java 프로세스가 있다면 GC 튜닝 시도
        if pgrep java > /dev/null; then
          echo "Java processes detected, checking GC status..."
          for pid in $(pgrep java); do
            jstat -gc $pid
          done
        fi
        
        # Docker 컨테이너 리소스 사용량 확인
        if command -v docker > /dev/null; then
          echo "=== Docker Container Stats ==="
          docker stats --no-stream
        fi
    timeout: 60
    continue_on_error: true

  - name: decide_remediation_action
    type: condition
    description: Decide on remediation action based on findings
    parameters:
      conditions:
        - if: "cpu_usage > 95"
          action: "emergency_restart"
        - if: "runaway_process_detected"
          action: "kill_process"
        - if: "memory_leak_detected"
          action: "restart_service"
        - else: "monitor_and_alert"

  - name: execute_remediation
    type: command
    description: Execute determined remediation action
    parameters:
      command: |
        case "{remediation_action}" in
          "emergency_restart")
            echo "Performing emergency service restart"
            systemctl restart {problematic_service}
            ;;
          "kill_process")
            echo "Killing runaway process {runaway_pid}"
            kill -TERM {runaway_pid}
            sleep 10
            kill -KILL {runaway_pid} 2>/dev/null || true
            ;;
          "restart_service")
            echo "Restarting service due to suspected memory leak"
            systemctl restart {leaky_service}
            ;;
          *)
            echo "No immediate action required, continuing monitoring"
            ;;
        esac
    timeout: 120
    continue_on_error: true

  - name: verify_improvement
    type: command
    description: Verify CPU usage improvement
    parameters:
      command: |
        sleep 30 &&
        current_cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//') &&
        echo "Current CPU usage: ${current_cpu}%" &&
        if (( $(echo "${current_cpu} < {cpu_threshold}" | bc -l) )); then
          echo "CPU usage normalized"
          exit 0
        else
          echo "CPU usage still high"
          exit 1
        fi
    timeout: 60

  - name: generate_report
    type: api_call
    description: Generate incident report
    parameters:
      url: "http://incident-tracker:8080/api/incidents"
      method: POST
      data:
        alert_type: "HighCPUUsage"
        target_host: "{target_host}"
        remediation_action: "{remediation_action}"
        resolution_status: "{resolution_status}"
        execution_summary: "{execution_summary}"
    timeout: 30
```

## 3. 실습 과제

### 과제 1: Ansible 자동화 구축
1. 디스크 정리 자동화 플레이북 구현
2. 서비스 복구 자동화 구현
3. 메트릭 기반 자동 스케일링

### 과제 2: 자가 치유 Kubernetes Operator
1. 커스텀 Operator 개발
2. Pod 건강성 자동 모니터링
3. 자동 복구 로직 구현

### 과제 3: 카오스 엔지니어링 실험
1. Chaos Monkey 구현
2. 네트워크 분할 실험
3. 복원력 테스트 및 분석

## 4. 모니터링 메트릭

### 자동화 시스템 메트릭
```promql
# 자동화 성공률
automation_executions_total{status="success"} / automation_executions_total

# 평균 복구 시간
avg(automation_recovery_time_seconds)

# 자동화 실패율
rate(automation_executions_total{status="failed"}[5m])
```

## 5. 다음 단계
- AIOps 및 머신러닝 (Phase 3-3)
- 애플리케이션 성능 모니터링 (Phase 4-1)