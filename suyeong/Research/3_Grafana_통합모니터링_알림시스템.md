# Grafana 통합 모니터링 알림 시스템 리서치

## 1. Grafana란 무엇인가?

**Grafana**는 Grafana Labs에서 개발한 오픈소스 메트릭/로그 시각화 대시보드 애플리케이션입니다. 

### 핵심 역할
- **데이터 시각화**: 다양한 데이터 소스에서 수집한 메트릭과 로그를 하나의 대시보드로 시각화
- **통합 모니터링**: 여러 시스템의 데이터를 통합하여 전체적인 시스템 상태를 한눈에 파악
- **알림 시스템**: 임계치 도달 시 다양한 채널로 자동 알림 발송

## 2. 통합 모니터링 시스템에서의 Grafana 역할

### 2.1 데이터 소스 통합
Grafana는 다음과 같은 다양한 데이터 소스를 지원합니다:
- **시계열 데이터베이스**: Prometheus, InfluxDB, CloudWatch
- **로깅 시스템**: Loki, Elasticsearch
- **관계형/NoSQL 데이터베이스**: MySQL, PostgreSQL, MongoDB
- **CI/CD 도구**: Jenkins, GitLab
- **클라우드 서비스**: AWS, Azure, GCP

### 2.2 모니터링 아키텍처에서의 위치

```
데이터 수집 → 데이터 저장 → 시각화 및 알림
  ↓            ↓            ↓
Prometheus   Prometheus   Grafana
Loki         Loki         ↓
Filebeat     → Elasticsearch → 대시보드 + 알림
```

## 3. 2025년 Grafana 알림 시스템 구축 방법

### 3.1 Contact Points (연락처) 설정

Contact Points는 알림을 받을 목적지를 정의하는 구성요소입니다.

**설정 방법:**
1. `Alerts & IRM` → `Alerting` → `Contact points` 이동
2. `+ Add contact point` 클릭
3. Contact point 이름 입력
4. 통합 방식 선택 (이메일, Slack, 웹훅 등)

### 3.2 지원되는 알림 채널 (우선순위 순)

1. **모바일 푸시 알림** - 기본 알림용 권장
2. **메시징 앱** - Slack, Microsoft Teams, Telegram
3. **전화 및 SMS** - 중요한 알림의 백업용
4. **이메일** - 긴급하지 않은 알림이나 요약 알림용

### 3.3 이메일 알림 설정

**Grafana OSS 환경:**
1. `grafana.ini` 또는 `custom.ini` 파일에서 SMTP 설정 구성
2. `Alerts & IRM` → `Alerting` → `Contact points`에서 이메일 통합 설정

### 3.4 웹훅 알림 설정

웹훅은 외부 시스템과의 통합을 위한 유연한 방법입니다.
- 알림 트리거 시 JSON 요청을 웹훅 엔드포인트로 전송
- 커스텀 알림 시스템 구축 가능

### 3.5 Notification Policies (알림 정책) 구성

알림 정책은 어떤 알림이 어느 Contact Point로 라우팅될지 결정합니다.

**설정 경로:**
`Alerts & IRM` → `Alerting` → `Notification policies`

## 4. 실제 구현 사례

### 4.1 CPU 사용률 모니터링 예시
```
조건: CPU 사용률이 80% 이상으로 5분 이상 지속
행동: Slack 알림 발송

조건: CPU 사용률이 95% 이상
행동: 즉시 이메일 + Slack 알림 발송
```

### 4.2 쿠버네티스 환경 모니터링
- 쿠버네티스 시스템 이벤트와 메트릭 실시간 모니터링
- 잠재적 문제 발생 시 자동 알림 발송
- Prometheus + Grafana 조합으로 동적 CI/CD 환경 모니터링

## 5. 2025년 동향과 특징

### 5.1 클라우드 통합 강화
- **Azure Managed Grafana**: Azure Monitor 데이터 원본 플러그인 기본 제공
- 관리 ID로 사전 구성된 구독 리소스 모니터링 지원

### 5.2 쿠버네티스 생태계 지원
- Prometheus + Grafana 조합이 쿠버네티스 환경의 표준으로 자리잡음
- 동적 환경에서의 서비스 디스커버리 및 모니터링 지원

### 5.3 통합 플랫폼으로의 진화
- 단순 시각화 도구에서 통합 모니터링 플랫폼으로 발전
- 다양한 데이터 소스와 알림 시스템을 하나로 통합하는 중심 역할 수행

## 6. 학습을 위한 다음 단계

1. **기본 설치 및 설정**: Docker를 이용한 Grafana 로컬 환경 구축
2. **Prometheus 연동**: 메트릭 수집을 위한 Prometheus 데이터 소스 설정
3. **대시보드 생성**: 시스템 리소스 모니터링 대시보드 구축
4. **알림 설정**: 임계치 기반 알림 룰 생성 및 테스트
5. **실제 환경 적용**: 쿠버네티스 클러스터나 마이크로서비스 환경에 적용

## 7. 참고 자료

- [Grafana 공식 문서](https://grafana.com/docs/)
- [Grafana Alerting 가이드](https://grafana.com/docs/grafana/latest/alerting/)
- [Prometheus + Grafana 튜토리얼](https://prometheus.io/docs/visualization/grafana/)