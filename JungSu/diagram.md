          ┌───────────────────────────────┐
          │        Client / User          │
          └────────────┬──────────────────┘
                       │
             ┌─────────▼─────────┐
             │    API Gateway    │ ← Kong / Istio
             └─────────┬─────────┘
                       │
┌─────────────────────▼─────────────────────┐
│        Event-Driven Message Broker        │ ← Kafka / NATS
└────┬────────────┬────────────┬────────────┘
│            │            │
┌─────▼─────┐┌─────▼─────┐┌─────▼────────────┐
│ Monitoring││Chaos Engine││Self-Healing Ctrl│
│(Prometheus││(LitmusChaos)││ (Robusta, VPA) │
└─────┬─────┘└─────┬─────┘└──────────┬───────┘
│            │                 │
┌─────▼─────┐ ┌────▼─────┐    ┌──────▼───────┐
│ Metrics DB│ │Chaos Logs│    │Recovery Logic│
│(TSDB, Mimir)││+Results │    │AI Optimizer  │
└────────────┘ └─────────┘    └──────────────┘
│                             │
┌─────▼─────────────────────────────▼─────┐
│         Grafana Dashboard + Alerts      │ ← Slack, PagerDuty, Email 연동
└────────────────────────────────────────-┘
