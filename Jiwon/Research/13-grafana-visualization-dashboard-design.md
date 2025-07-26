# 1.3 Grafana 시각화 및 대시보드 설계

## Overview
Grafana를 활용한 효과적인 데이터 시각화와 대시보드 설계 방법을 학습합니다. 다양한 패널 유형, 동적 대시보드 구성, 그리고 대규모 환경에서의 성능 최적화 기법을 다룹니다.

## 대시보드 개발 기초

### 패널 유형 및 시각화 기법

#### Time Series 패널
**용도**: 시간에 따른 메트릭 변화 추이 표시

**설정 예시**:
```json
{
  "type": "timeseries",
  "title": "CPU Usage",
  "targets": [
    {
      "expr": "100 - (avg(rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
      "legendFormat": "{{instance}} - CPU Usage"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "percent",
      "min": 0,
      "max": 100,
      "thresholds": {
        "steps": [
          {"color": "green", "value": null},
          {"color": "yellow", "value": 70},
          {"color": "red", "value": 90}
        ]
      }
    }
  }
}
```

**시각화 옵션**:
- **Line interpolation**: 데이터 포인트 간 연결 방식 (linear, smooth, step)
- **Fill opacity**: 선 아래 영역 채우기 투명도
- **Point size**: 데이터 포인트 크기 조절
- **Stack series**: 여러 시리즈를 누적으로 표시

#### Stat 패널
**용도**: 단일 값 또는 요약 통계 표시

**활용 사례**:
```json
{
  "type": "stat",
  "title": "Total Requests (24h)",
  "targets": [
    {
      "expr": "increase(http_requests_total[24h])",
      "legendFormat": "Total Requests"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "short",
      "decimals": 0,
      "displayName": "Requests",
      "color": {"mode": "value"},
      "mappings": [
        {
          "type": "range",
          "options": {
            "from": 0,
            "to": 1000,
            "result": {"color": "red", "text": "Low"}
          }
        }
      ]
    }
  },
  "options": {
    "reduceOptions": {
      "values": false,
      "calcs": ["lastNotNull"],
      "fields": ""
    },
    "orientation": "auto",
    "textMode": "auto",
    "colorMode": "background"
  }
}
```

#### Gauge 패널
**용도**: 값의 범위 내 현재 위치를 시각적으로 표현

**설정 예시**:
```json
{
  "type": "gauge",
  "title": "Memory Usage",
  "targets": [
    {
      "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "percent",
      "min": 0,
      "max": 100,
      "thresholds": {
        "steps": [
          {"color": "green", "value": null},
          {"color": "yellow", "value": 60},
          {"color": "red", "value": 80}
        ]
      }
    }
  },
  "options": {
    "showThresholdLabels": true,
    "showThresholdMarkers": true
  }
}
```

#### Heatmap 패널
**용도**: 히스토그램 데이터를 통한 분포 시각화

**응답 시간 히트맵 예시**:
```json
{
  "type": "heatmap",
  "title": "Response Time Distribution",
  "targets": [
    {
      "expr": "sum(rate(http_request_duration_seconds_bucket[5m])) by (le)",
      "format": "heatmap",
      "legendFormat": "{{le}}"
    }
  ],
  "heatmap": {
    "xAxis": {"show": true},
    "yAxis": {
      "show": true,
      "logBase": 2,
      "min": "0.001",
      "max": "10"
    },
    "yBucketBound": "upper"
  },
  "color": {
    "cardColor": "#b4ff00",
    "colorScale": "sqrt",
    "colorScheme": "interpolateSpectral",
    "exponent": 0.5,
    "mode": "spectrum"
  }
}
```

### 템플릿 변수 및 동적 대시보드

#### 변수 유형 및 설정

**Query 변수**:
```json
{
  "name": "instance",
  "type": "query",
  "query": "label_values(up, instance)",
  "refresh": "on_time_range_change",
  "multi": true,
  "includeAll": true,
  "allValue": ".*"
}
```

**Custom 변수**:
```json
{
  "name": "environment",
  "type": "custom",
  "options": [
    {"text": "Production", "value": "prod"},
    {"text": "Staging", "value": "stage"},
    {"text": "Development", "value": "dev"}
  ],
  "current": {"text": "Production", "value": "prod"}
}
```

**Interval 변수**:
```json
{
  "name": "interval",
  "type": "interval",
  "options": [
    {"text": "1m", "value": "1m"},
    {"text": "5m", "value": "5m"},
    {"text": "15m", "value": "15m"},
    {"text": "1h", "value": "1h"}
  ],
  "auto": true,
  "auto_count": 30,
  "auto_min": "10s"
}
```

#### 변수 활용 예시

**동적 쿼리 구성**:
```promql
# 인스턴스 선택 변수 활용
rate(http_requests_total{instance=~"$instance"}[5m])

# 환경별 필터링
up{environment="$environment"}

# 동적 시간 간격
rate(cpu_usage_total[$interval])

# 다중 선택 지원
sum(rate(http_requests_total{service=~"$service"}[5m])) by (service)
```

**조건부 패널 표시**:
```json
{
  "panels": [
    {
      "title": "Production Metrics",
      "targets": [...],
      "repeat": "instance",
      "repeatDirection": "h",
      "maxPerRow": 4,
      "hideTimeOverride": false
    }
  ]
}
```

### 알림 주석 및 이벤트 상관관계

#### 주석 (Annotations) 설정
**배포 이벤트 주석**:
```json
{
  "annotations": {
    "list": [
      {
        "name": "Deployments",
        "datasource": "prometheus",
        "expr": "changes(deployment_version[1h]) > 0",
        "titleFormat": "Deployment: {{service}}",
        "textFormat": "Version: {{version}}"
      }
    ]
  }
}
```

**알림 발생 주석**:
```json
{
  "name": "Alerts",
  "datasource": "prometheus",
  "expr": "ALERTS{alertstate=\"firing\"}",
  "step": "60s",
  "titleFormat": "Alert: {{alertname}}",
  "textFormat": "{{instance}}: {{summary}}",
  "iconColor": "red"
}
```

#### 이벤트 상관관계 분석

**다중 데이터 소스 연결**:
```json
{
  "panels": [
    {
      "title": "Request Rate vs Deployment Events",
      "type": "timeseries",
      "targets": [
        {
          "datasource": "prometheus",
          "expr": "sum(rate(http_requests_total[5m]))"
        }
      ],
      "annotations": {
        "list": [
          {
            "datasource": "elasticsearch",
            "query": "tags:deployment AND @timestamp:[$__from TO $__to]"
          }
        ]
      }
    }
  ]
}
```

## 고급 기능

### 데이터 소스 관리 및 연합

#### 다중 Prometheus 연합
```json
{
  "datasources": [
    {
      "name": "Prometheus-DC1",
      "type": "prometheus",
      "url": "http://prometheus-dc1:9090",
      "access": "proxy"
    },
    {
      "name": "Prometheus-DC2", 
      "type": "prometheus",
      "url": "http://prometheus-dc2:9090",
      "access": "proxy"
    }
  ]
}
```

**연합된 쿼리 예시**:
```json
{
  "targets": [
    {
      "datasource": "Prometheus-DC1",
      "expr": "sum(rate(http_requests_total[5m]))",
      "legendFormat": "DC1 Traffic"
    },
    {
      "datasource": "Prometheus-DC2", 
      "expr": "sum(rate(http_requests_total[5m]))",
      "legendFormat": "DC2 Traffic"
    }
  ]
}
```

#### 혼합 데이터 소스 대시보드
```json
{
  "panels": [
    {
      "title": "System Overview",
      "type": "row",
      "panels": [
        {
          "title": "Metrics (Prometheus)",
          "datasource": "prometheus",
          "targets": [{"expr": "up"}]
        },
        {
          "title": "Logs (Elasticsearch)",
          "datasource": "elasticsearch", 
          "targets": [{"query": "level:ERROR"}]
        },
        {
          "title": "Traces (Jaeger)",
          "datasource": "jaeger",
          "targets": [{"query": "operation:http_request"}]
        }
      ]
    }
  ]
}
```

### 사용자 인증 및 권한 부여

#### LDAP 통합 설정
```ini
[auth.ldap]
enabled = true
config_file = /etc/grafana/ldap.toml
allow_sign_up = true

[auth.ldap.group_mappings]
dn = "cn=admins,ou=groups,dc=grafana,dc=org"
org_role = Admin

dn = "cn=users,ou=groups,dc=grafana,dc=org"
org_role = Viewer
```

**LDAP 설정 파일** (`/etc/grafana/ldap.toml`):
```toml
[[servers]]
host = "127.0.0.1"
port = 389
use_ssl = false
start_tls = false
ssl_skip_verify = false

bind_dn = "cn=admin,dc=grafana,dc=org"
bind_password = 'grafana'

search_filter = "(cn=%s)"
search_base_dns = ["dc=grafana,dc=org"]

[servers.attributes]
name = "givenName"
surname = "sn"
username = "cn"
member_of = "memberOf"
email = "email"

[[servers.group_mappings]]
group_dn = "cn=admins,ou=groups,dc=grafana,dc=org"
org_role = "Admin"

[[servers.group_mappings]]
group_dn = "cn=editors,ou=groups,dc=grafana,dc=org"
org_role = "Editor"
```

#### OAuth 통합 (Google)
```ini
[auth.google]
enabled = true
client_id = YOUR_GOOGLE_CLIENT_ID
client_secret = YOUR_GOOGLE_CLIENT_SECRET
scopes = https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email
auth_url = https://accounts.google.com/o/oauth2/auth
token_url = https://accounts.google.com/o/oauth2/token
allowed_domains = company.com
allow_sign_up = true
```

### 플러그인 개발 및 커스텀 시각화

#### 패널 플러그인 기본 구조
```typescript
// src/SimplePanel.tsx
import React from 'react';
import { PanelProps } from '@grafana/data';
import { SimpleOptions } from 'types';

interface Props extends PanelProps<SimpleOptions> {}

export const SimplePanel: React.FC<Props> = ({ options, data, width, height }) => {
  return (
    <div
      style={{
        width,
        height,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div>
        <h3>Custom Panel</h3>
        <p>Text: {options.text}</p>
        <p>Series count: {data.series.length}</p>
      </div>
    </div>
  );
};
```

**플러그인 설정 옵션**:
```typescript
// src/types.ts
export interface SimpleOptions {
  text: string;
  showSeriesCount: boolean;
  color: string;
}
```

#### 데이터 소스 플러그인
```typescript
// src/DataSource.ts
import { DataSourceInstanceSettings } from '@grafana/data';
import { DataSourceWithBackend } from '@grafana/runtime';

export class CustomDataSource extends DataSourceWithBackend<MyQuery> {
  constructor(instanceSettings: DataSourceInstanceSettings) {
    super(instanceSettings);
  }

  async query(options: DataQueryRequest<MyQuery>): Promise<DataQueryResponse> {
    return super.query(options);
  }

  async testDatasource() {
    return {
      status: 'success',
      message: 'Data source is working',
    };
  }
}
```

### 코드로서의 대시보드 및 버전 관리

#### JSON 모델 기반 대시보드
```json
{
  "dashboard": {
    "id": null,
    "title": "Infrastructure Overview",
    "tags": ["infrastructure", "monitoring"],
    "timezone": "browser",
    "panels": [...],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  },
  "folderId": 0,
  "overwrite": true
}
```

#### Terraform을 통한 대시보드 관리
```hcl
resource "grafana_dashboard" "infrastructure" {
  config_json = file("${path.module}/dashboards/infrastructure.json")
  folder      = grafana_folder.monitoring.id
}

resource "grafana_folder" "monitoring" {
  title = "Infrastructure Monitoring"
}
```

#### Git 기반 버전 관리 워크플로
```bash
# 대시보드 내보내기
curl -H "Authorization: Bearer $API_TOKEN" \
  "http://grafana:3000/api/dashboards/uid/$DASHBOARD_UID" \
  | jq '.dashboard' > dashboards/infrastructure.json

# 변경사항 커밋
git add dashboards/
git commit -m "Update infrastructure dashboard - add memory metrics"
git push origin main

# 자동 배포 (CI/CD)
curl -X POST \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @dashboards/infrastructure.json \
  "http://grafana:3000/api/dashboards/db"
```

## 대규모 대시보드 성능 최적화

### 쿼리 최적화 전략

#### 시간 범위 최적화
```promql
# 비효율적: 너무 긴 시간 범위
avg_over_time(cpu_usage[24h])

# 효율적: 적절한 시간 범위
avg_over_time(cpu_usage[5m])

# 긴 시간 범위가 필요한 경우 recording rule 사용
avg_cpu_usage_5m
```

#### Recording Rules 활용
```yaml
# prometheus-rules.yml
groups:
  - name: infrastructure
    interval: 30s
    rules:
      - record: cpu_usage_by_instance
        expr: 100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) by (instance) * 100)
      
      - record: memory_usage_by_instance
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100
      
      - record: disk_usage_by_instance
        expr: (1 - (node_filesystem_free_bytes / node_filesystem_size_bytes)) * 100
```

### 캐싱 및 성능 설정

#### Grafana 설정 최적화
```ini
[database]
max_idle_conn = 2
max_open_conn = 0
conn_max_lifetime = 14400

[dataproxy]
timeout = 30
keep_alive_seconds = 30

[rendering]
server_url = http://renderer:8081/render
callback_url = http://grafana:3000/

[caching]
enabled = true
ttl = 1h
```

#### 패널별 캐시 전략
```json
{
  "cacheTimeout": "5m",
  "interval": "30s",
  "maxDataPoints": 1000,
  "targets": [
    {
      "expr": "cpu_usage_by_instance",
      "intervalFactor": 2,
      "step": 60
    }
  ]
}
```

### 대시보드 구조 최적화

#### 계층적 대시보드 설계
```
├── Overview Dashboard (핵심 KPI)
├── Infrastructure/
│   ├── Compute Resources
│   ├── Network Performance  
│   └── Storage Metrics
├── Applications/
│   ├── Web Services
│   ├── Database Performance
│   └── Message Queues
└── Business Metrics/
    ├── User Analytics
    └── Revenue Tracking
```

#### 조건부 패널 로딩
```json
{
  "panels": [
    {
      "title": "Detailed Metrics",
      "targets": [...],
      "transparent": true,
      "hideTimeOverride": false,
      "datasource": {
        "uid": "$datasource"
      },
      "hide": "$show_details != 'true'"
    }
  ]
}
```

## Best Practices

### 대시보드 설계 원칙
1. **사용자 중심 설계**: 대상 사용자의 역할과 필요에 맞는 정보 배치
2. **정보 계층화**: 개요 → 상세 → 드릴다운 구조
3. **일관된 색상 체계**: 상태별 색상 규칙 통일 (녹색=정상, 황색=경고, 빨간색=위험)
4. **적절한 시각화 선택**: 데이터 특성에 맞는 차트 유형 선택

### 성능 최적화 가이드라인
1. **쿼리 복잡도 관리**: 복잡한 계산은 recording rule로 사전 처리
2. **적절한 해상도**: 화면 크기에 맞는 maxDataPoints 설정
3. **캐시 활용**: 자주 변하지 않는 데이터는 캐시 TTL 설정
4. **필터링 우선**: 라벨 필터를 통한 데이터 범위 축소

## Benefits and Challenges

### Benefits  
- **직관적 시각화**: 복잡한 데이터를 이해하기 쉬운 형태로 표현
- **동적 대시보드**: 템플릿 변수를 통한 유연한 데이터 탐색
- **확장성**: 플러그인 시스템을 통한 무한 확장 가능
- **통합성**: 다양한 데이터 소스를 하나의 뷰에서 통합 관리

### Challenges
- **복잡성 관리**: 많은 기능으로 인한 설정 복잡도 증가  
- **성능 고려**: 대규모 환경에서 쿼리 성능 최적화 필요
- **권한 관리**: 세밀한 접근 제어를 위한 추가 설정 필요
- **버전 관리**: 대시보드 변경 추적 및 롤백을 위한 프로세스 구축