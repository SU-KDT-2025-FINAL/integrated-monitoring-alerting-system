[사용자 요청]
↓
[Spring Boot 추천 API] ─────▶ [GPT / 추천 모델]
↓                          ↘︎
[응답 반환]               [에러 로그 발생 시 Kafka 전송]
↓                          ↘︎
[피드백 저장]        ▶︎ [Python 이상 탐지 + Slack 알림]


# 추천 로직	Spring Boot API + GPT or Content-based 모델
# 로그 수집	Logback JSON → Filebeat → Kafka
# 이상 탐지	Python Rule-Step 1 – 수강 이력 기반 추천 시스템 (Spring Boot + GPT or Rule-based)

- Step 2 – 사용자 피드백 수집 및 저장

- Step 3 – 로그 수집 및 에러 포인트 수집 (Logback + Filebeat + Kafka)

- Step 4 – 이상 탐지 로직 구성 (Python or Elastic Stack)

  - Step 5 – Slack 실시간 알림 + 대시보드 연결 (선택)

- based 탐지기
# 알림	Slack Webhook
# 실시간 대시보드 (선택)	Grafana + Loki or Kibana

