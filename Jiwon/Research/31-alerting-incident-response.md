# 알림 및 인시던트 대응 (Phase 3-1)

## 개요
효과적인 알림 시스템 설계, 인시던트 대응 자동화, 알림 피로 방지를 위한 고급 알림 전략과 구현 방법을 학습합니다.

## 1. 알림 규칙 설계

### 1.1 알림 규칙 분류법 및 심각도 수준

**심각도 분류 체계**
```yaml
# severity-classification.yml
severity_levels:
  critical:
    description: "즉시 대응 필요, 서비스 중단"
    response_time: "5분 이내"
    escalation: "즉시 온콜 엔지니어"
    examples:
      - "전체 서비스 다운"
      - "데이터 손실 위험"
      - "보안 침해"
      
  warning:
    description: "곧 문제가 될 수 있는 상황"
    response_time: "30분 이내"
    escalation: "일반 알림"
    examples:
      - "높은 CPU 사용률"
      - "디스크 공간 부족"
      - "응답 시간 증가"
      
  info:
    description: "참고용 정보"
    response_time: "업무 시간 내"
    escalation: "로그만 기록"
    examples:
      - "배포 완료"
      - "스케일링 이벤트"
      - "정기 백업 완료"
```

**Prometheus 알림 규칙 예제**
```yaml
# critical-alerts.yml
groups:
- name: critical.rules
  rules:
  - alert: ServiceDown
    expr: up == 0
    for: 30s
    labels:
      severity: critical
      team: platform
      runbook: "https://wiki.company.com/runbooks/service-down"
    annotations:
      summary: "Service {{ $labels.job }} is down"
      description: "{{ $labels.instance }} of job {{ $labels.job }} has been down for more than 30 seconds"
      impact: "Users cannot access the service"
      action: "Check service health and restart if necessary"

  - alert: HighErrorRate
    expr: |
      (
        rate(http_requests_total{status=~"5.."}[5m]) /
        rate(http_requests_total[5m])
      ) > 0.05
    for: 2m
    labels:
      severity: critical
      team: backend
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value | humanizePercentage }} for {{ $labels.job }}"
      
  - alert: DatabaseConnectionPoolExhausted
    expr: |
      (
        sum(rate(database_connections_active[5m])) /
        sum(database_connections_max)
      ) > 0.9
    for: 1m
    labels:
      severity: critical
      team: database
    annotations:
      summary: "Database connection pool nearly exhausted"
      description: "Connection pool usage is {{ $value | humanizePercentage }}"

# warning-alerts.yml  
- name: warning.rules
  rules:
  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 10m
    labels:
      severity: warning
      team: infrastructure
    annotations:
      summary: "High CPU usage detected"
      description: "CPU usage is {{ $value }}% on {{ $labels.instance }}"
      
  - alert: DiskSpaceLow
    expr: |
      (
        node_filesystem_avail_bytes{fstype!="tmpfs"} /
        node_filesystem_size_bytes{fstype!="tmpfs"}
      ) < 0.1
    for: 5m
    labels:
      severity: warning
      team: infrastructure
    annotations:
      summary: "Low disk space"
      description: "Disk space is {{ $value | humanizePercentage }} full on {{ $labels.instance }}"
```

### 1.2 알림 피로 방지 전략

**지능형 그룹화 및 억제**
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  
route:
  receiver: 'default'
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  
  routes:
  # 긴급 알림 - 즉시 발송
  - match:
      severity: critical
    group_wait: 10s
    group_interval: 1m
    repeat_interval: 30m
    receiver: 'critical-alerts'
    
  # 경고 알림 - 그룹화하여 발송
  - match:
      severity: warning
    group_wait: 5m
    group_interval: 10m
    repeat_interval: 2h
    receiver: 'warning-alerts'
    
  # 정보성 알림 - 일괄 처리
  - match:
      severity: info
    group_wait: 10m
    group_interval: 30m
    repeat_interval: 24h
    receiver: 'info-alerts'

# 알림 억제 규칙
inhibit_rules:
- source_match:
    severity: critical
  target_match:
    severity: warning
  equal: ['alertname', 'cluster', 'service']
  
- source_match:
    alertname: ServiceDown
  target_match_re:
    alertname: '(HighLatency|HighErrorRate|HighCPU).*'
  equal: ['instance']
```

**알림 빈도 제어**
```python
# alert_frequency_controller.py
import time
from collections import defaultdict
from datetime import datetime, timedelta

class AlertFrequencyController:
    def __init__(self):
        self.alert_history = defaultdict(list)
        self.backoff_multiplier = 2
        self.max_backoff = 3600  # 1시간
        
    def should_send_alert(self, alert_name, instance, severity):
        """알림 발송 여부 결정"""
        key = f"{alert_name}:{instance}"
        now = datetime.now()
        
        # 심각도별 기본 간격
        base_intervals = {
            'critical': 300,    # 5분
            'warning': 1800,    # 30분  
            'info': 3600       # 1시간
        }
        
        base_interval = base_intervals.get(severity, 1800)
        
        # 최근 알림 히스토리 정리 (24시간 이전 제거)
        cutoff_time = now - timedelta(hours=24)
        self.alert_history[key] = [
            timestamp for timestamp in self.alert_history[key]
            if timestamp > cutoff_time
        ]
        
        if not self.alert_history[key]:
            # 첫 번째 알림은 항상 발송
            self.alert_history[key].append(now)
            return True
            
        # 백오프 계산
        alert_count = len(self.alert_history[key])
        backoff_interval = min(
            base_interval * (self.backoff_multiplier ** (alert_count - 1)),
            self.max_backoff
        )
        
        last_alert_time = self.alert_history[key][-1]
        time_since_last = (now - last_alert_time).total_seconds()
        
        if time_since_last >= backoff_interval:
            self.alert_history[key].append(now)
            return True
            
        return False
    
    def reset_alert_frequency(self, alert_name, instance):
        """알림 빈도 초기화 (문제 해결 시)"""
        key = f"{alert_name}:{instance}"
        self.alert_history[key] = []
```

### 1.3 다단계 알림 에스컬레이션

**에스컬레이션 정책**
```yaml
# escalation-config.yml
escalation_policies:
  critical_service_down:
    stages:
    - duration: 0
      recipients: ["oncall-engineer"]
      channels: ["slack", "sms", "phone"]
      
    - duration: 300  # 5분 후
      recipients: ["oncall-engineer", "team-lead"] 
      channels: ["slack", "sms", "phone", "email"]
      
    - duration: 900  # 15분 후
      recipients: ["oncall-engineer", "team-lead", "manager"]
      channels: ["slack", "sms", "phone", "email"]
      
    - duration: 1800  # 30분 후
      recipients: ["all-engineers", "management"]
      channels: ["slack", "email", "incident-bridge"]
      
  warning_high_latency:
    stages:
    - duration: 0
      recipients: ["team-channel"]
      channels: ["slack"]
      
    - duration: 1800  # 30분 후
      recipients: ["oncall-engineer"]
      channels: ["slack", "email"]
      
    - duration: 3600  # 1시간 후  
      recipients: ["team-lead"]
      channels: ["slack", "email"]
```

**에스컬레이션 구현**
```python
# escalation_manager.py
import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Dict

class EscalationManager:
    def __init__(self, notification_service):
        self.notification_service = notification_service
        self.active_escalations = {}
        
    async def start_escalation(self, alert: Dict, policy_name: str):
        """에스컬레이션 시작"""
        escalation_id = f"{alert['alertname']}:{alert['instance']}:{datetime.now().timestamp()}"
        
        escalation = {
            'id': escalation_id,
            'alert': alert,
            'policy_name': policy_name,
            'start_time': datetime.now(),
            'current_stage': 0,
            'acknowledged': False
        }
        
        self.active_escalations[escalation_id] = escalation
        
        # 첫 번째 단계 즉시 실행
        await self._execute_escalation_stage(escalation_id, 0)
        
        # 후속 단계 스케줄링
        asyncio.create_task(self._schedule_escalation(escalation_id))
        
        return escalation_id
    
    async def acknowledge_alert(self, escalation_id: str, user: str):
        """알림 확인 처리"""
        if escalation_id in self.active_escalations:
            self.active_escalations[escalation_id]['acknowledged'] = True
            self.active_escalations[escalation_id]['acknowledged_by'] = user
            self.active_escalations[escalation_id]['acknowledged_at'] = datetime.now()
            
            await self.notification_service.send_notification(
                recipients=['team-channel'],
                message=f"Alert acknowledged by {user}",
                channels=['slack']
            )
    
    async def _schedule_escalation(self, escalation_id: str):
        """에스컬레이션 스케줄 관리"""
        escalation = self.active_escalations.get(escalation_id)
        if not escalation:
            return
            
        policy = self._get_escalation_policy(escalation['policy_name'])
        
        for stage_idx, stage in enumerate(policy['stages'][1:], 1):
            # 대기 시간
            await asyncio.sleep(stage['duration'])
            
            # 확인되었거나 해결되었으면 중단
            if escalation['acknowledged'] or escalation_id not in self.active_escalations:
                break
                
            await self._execute_escalation_stage(escalation_id, stage_idx)
    
    async def _execute_escalation_stage(self, escalation_id: str, stage_idx: int):
        """특정 에스컬레이션 단계 실행"""
        escalation = self.active_escalations.get(escalation_id)
        if not escalation:
            return
            
        policy = self._get_escalation_policy(escalation['policy_name'])
        stage = policy['stages'][stage_idx]
        
        alert = escalation['alert']
        message = self._format_escalation_message(alert, stage_idx)
        
        await self.notification_service.send_notification(
            recipients=stage['recipients'],
            message=message,
            channels=stage['channels'],
            priority='high' if stage_idx > 0 else 'normal'
        )
        
        escalation['current_stage'] = stage_idx
```

### 1.4 컨텍스트 인식 알림 및 강화

**지능형 알림 컨텍스트**
```python
# intelligent_alerting.py
import requests
from datetime import datetime, timedelta

class IntelligentAlerting:
    def __init__(self, prometheus_client, metrics_db):
        self.prometheus = prometheus_client
        self.metrics_db = metrics_db
        
    def enrich_alert(self, alert):
        """알림에 컨텍스트 정보 추가"""
        enriched_alert = alert.copy()
        
        # 1. 관련 메트릭 히스토리 추가
        enriched_alert['history'] = self._get_metric_history(
            alert['alertname'], 
            alert['instance']
        )
        
        # 2. 관련 서비스 상태 확인
        enriched_alert['related_services'] = self._check_related_services(
            alert['instance']
        )
        
        # 3. 최근 배포 정보
        enriched_alert['recent_deployments'] = self._get_recent_deployments(
            alert['job']
        )
        
        # 4. 유사한 과거 인시던트
        enriched_alert['similar_incidents'] = self._find_similar_incidents(
            alert['alertname']
        )
        
        # 5. 자동 수정 제안
        enriched_alert['suggested_actions'] = self._suggest_actions(alert)
        
        return enriched_alert
    
    def _get_metric_history(self, alert_name, instance):
        """메트릭 히스토리 조회"""
        # 지난 24시간의 메트릭 트렌드
        query = f'up{{instance="{instance}"}}[24h:5m]'
        result = self.prometheus.query_range(query)
        
        return {
            'trend': 'increasing' if self._is_increasing_trend(result) else 'stable',
            'peak_times': self._find_peak_times(result),
            'baseline': self._calculate_baseline(result)
        }
    
    def _check_related_services(self, instance):
        """관련 서비스 상태 확인"""
        # 같은 노드의 다른 서비스들
        node_query = f'up{{instance=~".*{instance.split(":")[0]}.*"}}'
        node_services = self.prometheus.query(node_query)
        
        # 의존성 있는 서비스들
        dependency_query = f'up{{job=~"database|cache|messaging"}}'
        dependencies = self.prometheus.query(dependency_query)
        
        return {
            'node_services': [s for s in node_services if s['value'][1] == '0'],
            'dependencies': [d for d in dependencies if d['value'][1] == '0']
        }
    
    def _suggest_actions(self, alert):
        """자동 수정 제안"""
        suggestions = []
        
        if alert['alertname'] == 'HighCPUUsage':
            suggestions.extend([
                "1. 프로세스 목록 확인: `top -n 1`",
                "2. 수평 확장 고려",
                "3. 애플리케이션 프로파일링 수행"
            ])
        elif alert['alertname'] == 'DiskSpaceLow':
            suggestions.extend([
                "1. 로그 파일 정리: `find /var/log -name '*.log' -mtime +7 -delete`",
                "2. 불필요한 컨테이너 이미지 제거",
                "3. 디스크 사용량 분석: `du -sh /*`"
            ])
        elif alert['alertname'] == 'ServiceDown':
            suggestions.extend([
                "1. 서비스 재시작: `systemctl restart service_name`",
                "2. 로그 확인: `journalctl -u service_name -n 50`",
                "3. 네트워크 연결 확인"
            ])
            
        return suggestions
```

## 2. 알림 시스템 구현

### 2.1 다중 채널 알림 라우팅

**통합 알림 서비스**
```python
# notification_service.py
import asyncio
import aiohttp
import smtplib
from typing import List, Dict
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

class NotificationService:
    def __init__(self, config):
        self.config = config
        self.channels = {
            'slack': self._send_slack,
            'email': self._send_email, 
            'sms': self._send_sms,
            'webhook': self._send_webhook,
            'teams': self._send_teams,
            'pagerduty': self._send_pagerduty
        }
    
    async def send_notification(self, recipients: List[str], message: str, 
                              channels: List[str], priority: str = 'normal'):
        """다중 채널 알림 발송"""
        tasks = []
        
        for channel in channels:
            if channel in self.channels:
                task = self.channels[channel](recipients, message, priority)
                tasks.append(task)
        
        # 모든 채널에 동시 발송
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 결과 집계
        success_count = sum(1 for r in results if not isinstance(r, Exception))
        failure_count = len(results) - success_count
        
        return {
            'total_channels': len(channels),
            'successful': success_count,
            'failed': failure_count,
            'details': dict(zip(channels, results))
        }
    
    async def _send_slack(self, recipients, message, priority):
        """Slack 알림"""
        webhook_url = self.config['slack']['webhook_url']
        
        # 우선순위에 따른 색상 설정
        color_map = {
            'critical': '#ff0000',
            'warning': '#ffa500', 
            'info': '#00ff00',
            'normal': '#0000ff'
        }
        
        payload = {
            "attachments": [{
                "color": color_map.get(priority, '#0000ff'),
                "fields": [
                    {
                        "title": "Alert",
                        "value": message,
                        "short": False
                    }
                ],
                "footer": "Monitoring System",
                "ts": int(time.time())
            }]
        }
        
        # 멘션 추가
        if priority in ['critical', 'high']:
            payload['text'] = f"<!channel> {message}"
        else:
            payload['text'] = message
            
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as response:
                return response.status == 200
    
    async def _send_email(self, recipients, message, priority):
        """이메일 알림"""
        smtp_config = self.config['email']
        
        msg = MimeMultipart()
        msg['From'] = smtp_config['from']
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = f"[{priority.upper()}] Monitoring Alert"
        
        # HTML 템플릿 사용
        html_content = self._format_email_template(message, priority)
        msg.attach(MimeText(html_content, 'html'))
        
        try:
            with smtplib.SMTP(smtp_config['host'], smtp_config['port']) as server:
                if smtp_config.get('tls'):
                    server.starttls()
                if smtp_config.get('username'):
                    server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"Email sending failed: {e}")
            return False
    
    async def _send_pagerduty(self, recipients, message, priority):
        """PagerDuty 인시던트 생성"""
        api_key = self.config['pagerduty']['api_key']
        service_key = self.config['pagerduty']['service_key']
        
        payload = {
            "incident": {
                "type": "incident",
                "title": f"Monitoring Alert: {message[:100]}",
                "service": {"id": service_key, "type": "service_reference"},
                "urgency": "high" if priority in ['critical', 'high'] else "low",
                "body": {
                    "type": "incident_body",
                    "details": message
                }
            }
        }
        
        headers = {
            "Authorization": f"Token token={api_key}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.pagerduty+json;version=2"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.pagerduty.com/incidents",
                json=payload,
                headers=headers
            ) as response:
                return response.status == 201
```

### 2.2 알림 중복 제거 및 그룹화

**중복 제거 시스템**
```python
# deduplication_service.py
import hashlib
import json
from datetime import datetime, timedelta
from collections import defaultdict

class AlertDeduplicationService:
    def __init__(self, window_minutes=5):
        self.window_minutes = window_minutes
        self.alert_cache = defaultdict(list)
        self.group_cache = defaultdict(dict)
        
    def process_alert(self, alert):
        """알림 중복 제거 및 그룹화 처리"""
        # 알림 핑거프린트 생성
        fingerprint = self._generate_fingerprint(alert)
        
        # 중복 검사
        if self._is_duplicate(fingerprint, alert):
            return None  # 중복된 알림, 무시
            
        # 그룹화 키 생성
        group_key = self._generate_group_key(alert)
        
        # 그룹에 알림 추가
        self._add_to_group(group_key, alert)
        
        # 그룹 발송 조건 확인
        if self._should_send_group(group_key):
            grouped_alerts = self._get_and_clear_group(group_key)
            return self._create_grouped_notification(grouped_alerts)
            
        return None
    
    def _generate_fingerprint(self, alert):
        """알림 핑거프린트 생성"""
        # 핵심 필드만으로 핑거프린트 생성
        key_fields = {
            'alertname': alert.get('alertname'),
            'instance': alert.get('instance'),
            'job': alert.get('job'),
            'severity': alert.get('severity')
        }
        
        fingerprint_string = json.dumps(key_fields, sort_keys=True)
        return hashlib.md5(fingerprint_string.encode()).hexdigest()
    
    def _is_duplicate(self, fingerprint, alert):
        """중복 알림 검사"""
        now = datetime.now()
        cutoff_time = now - timedelta(minutes=self.window_minutes)
        
        # 오래된 알림 제거
        self.alert_cache[fingerprint] = [
            timestamp for timestamp in self.alert_cache[fingerprint]
            if timestamp > cutoff_time
        ]
        
        if self.alert_cache[fingerprint]:
            return True  # 중복
            
        # 새 알림 기록
        self.alert_cache[fingerprint].append(now)
        return False
    
    def _generate_group_key(self, alert):
        """그룹화 키 생성"""
        return f"{alert.get('alertname')}:{alert.get('cluster')}:{alert.get('service')}"
    
    def _add_to_group(self, group_key, alert):
        """그룹에 알림 추가"""
        if group_key not in self.group_cache:
            self.group_cache[group_key] = {
                'alerts': [],
                'first_seen': datetime.now(),
                'last_updated': datetime.now()
            }
            
        self.group_cache[group_key]['alerts'].append(alert)
        self.group_cache[group_key]['last_updated'] = datetime.now()
    
    def _should_send_group(self, group_key):
        """그룹 발송 조건 확인"""
        group = self.group_cache.get(group_key)
        if not group:
            return False
            
        # 조건 1: 알림 개수가 임계값 도달
        if len(group['alerts']) >= 5:
            return True
            
        # 조건 2: 첫 번째 알림 후 일정 시간 경과
        if datetime.now() - group['first_seen'] >= timedelta(minutes=2):
            return True
            
        # 조건 3: 심각도가 critical인 알림이 포함됨
        if any(alert.get('severity') == 'critical' for alert in group['alerts']):
            return True
            
        return False
    
    def _create_grouped_notification(self, alerts):
        """그룹화된 알림 생성"""
        if len(alerts) == 1:
            return alerts[0]
            
        # 그룹 요약 생성
        summary = {
            'type': 'grouped_alert',
            'count': len(alerts),
            'alertnames': list(set(alert.get('alertname') for alert in alerts)),
            'instances': list(set(alert.get('instance') for alert in alerts)),
            'severities': list(set(alert.get('severity') for alert in alerts)),
            'alerts': alerts,
            'summary': f"{len(alerts)} alerts from {len(set(alert.get('instance') for alert in alerts))} instances"
        }
        
        return summary
```

### 2.3 침묵 관리 및 유지보수 창

**침묵 관리 시스템**
```python
# silence_manager.py
from datetime import datetime, timedelta
import re

class SilenceManager:
    def __init__(self, alertmanager_client):
        self.alertmanager = alertmanager_client
        
    def create_maintenance_silence(self, services, duration_hours=4, reason="Scheduled maintenance"):
        """유지보수를 위한 침묵 생성"""
        start_time = datetime.now()
        end_time = start_time + timedelta(hours=duration_hours)
        
        silences = []
        
        for service in services:
            silence = {
                "matchers": [
                    {
                        "name": "job",
                        "value": service,
                        "isRegex": False
                    }
                ],
                "startsAt": start_time.isoformat() + "Z",
                "endsAt": end_time.isoformat() + "Z",
                "comment": f"{reason} - Auto-created maintenance window",
                "createdBy": "maintenance-system"
            }
            
            silence_id = self.alertmanager.create_silence(silence)
            silences.append({
                'id': silence_id,
                'service': service,
                'end_time': end_time
            })
            
        return silences
    
    def create_deployment_silence(self, deployment_info):
        """배포 중 침묵 생성"""
        services = deployment_info.get('services', [])
        duration_minutes = deployment_info.get('estimated_duration', 30)
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        silence = {
            "matchers": [
                {
                    "name": "job",
                    "value": "|".join(services),
                    "isRegex": True
                },
                {
                    "name": "alertname",
                    "value": "ServiceDown|HighLatency|HighErrorRate",
                    "isRegex": True
                }
            ],
            "startsAt": start_time.isoformat() + "Z", 
            "endsAt": end_time.isoformat() + "Z",
            "comment": f"Deployment: {deployment_info.get('version')} - Auto-created",
            "createdBy": f"deployment-pipeline-{deployment_info.get('pipeline_id')}"
        }
        
        return self.alertmanager.create_silence(silence)
    
    def auto_expire_silences(self):
        """만료된 침묵 자동 정리"""
        silences = self.alertmanager.get_silences()
        expired_count = 0
        
        for silence in silences:
            if silence['status']['state'] == 'expired':
                self.alertmanager.delete_silence(silence['id'])
                expired_count += 1
                
        return expired_count
    
    def extend_silence(self, silence_id, additional_hours=2):
        """침묵 시간 연장"""
        silence = self.alertmanager.get_silence(silence_id)
        if not silence:
            return False
            
        # 종료 시간 연장
        current_end = datetime.fromisoformat(silence['endsAt'].replace('Z', ''))
        new_end = current_end + timedelta(hours=additional_hours)
        
        # 침묵 업데이트
        silence['endsAt'] = new_end.isoformat() + "Z"
        silence['comment'] += f" (Extended by {additional_hours}h)"
        
        return self.alertmanager.update_silence(silence_id, silence)
```

## 3. 실습 과제

### 과제 1: 지능형 알림 시스템 구축
1. 다단계 심각도 알림 규칙 작성
2. 컨텍스트 인식 알림 강화 구현
3. 알림 피로 방지 시스템 구축

### 과제 2: 다중 채널 알림 구현
1. Slack, 이메일, SMS 통합 알림 서비스
2. PagerDuty 인시던트 자동 생성
3. 알림 중복 제거 및 그룹화

### 과제 3: 자동화된 침묵 관리
1. 배포 중 자동 침묵 생성
2. 유지보수 창 관리 시스템
3. 침묵 규칙 자동 만료 및 정리

## 4. 모니터링 메트릭

### 알림 시스템 메트릭
```promql
# 알림 발송 건수
alertmanager_notifications_total

# 알림 실패율
rate(alertmanager_notifications_failed_total[5m]) / 
rate(alertmanager_notifications_total[5m])

# 활성 알림 수
alertmanager_alerts

# 침묵 규칙 수
alertmanager_silences
```

## 5. 다음 단계
- 자동화 및 자가 치유 (Phase 3-2)
- AIOps 및 머신러닝 (Phase 3-3)