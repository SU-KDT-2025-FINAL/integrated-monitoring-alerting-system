# 애플리케이션 성능 모니터링 (APM) (Phase 4-1)

## 개요
분산 시스템 환경에서 애플리케이션의 성능을 종합적으로 모니터링하기 위한 분산 추적, 메트릭 수집, 성능 분석 방법을 학습합니다.

## 1. 분산 추적 (Distributed Tracing)

### 1.1 OpenTelemetry 구현

**OpenTelemetry 기본 설정**
```yaml
# otel-collector-config.yml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
        
  jaeger:
    protocols:
      grpc:
        endpoint: 0.0.0.0:14250
      thrift_http:
        endpoint: 0.0.0.0:14268
        
  prometheus:
    config:
      scrape_configs:
      - job_name: 'otel-collector'
        static_configs:
        - targets: ['localhost:8888']

processors:
  batch:
    timeout: 1s
    send_batch_size: 1024
    
  memory_limiter:
    limit_mib: 512
    
  resource:
    attributes:
    - key: service.name
      value: ${SERVICE_NAME}
      action: upsert
    - key: service.version
      value: ${SERVICE_VERSION}
      action: upsert

exporters:
  jaeger:
    endpoint: jaeger-collector:14250
    tls:
      insecure: true
      
  prometheus:
    endpoint: "0.0.0.0:8889"
    
  logging:
    loglevel: debug
    
  otlp:
    endpoint: http://tempo:4317
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp, jaeger]
      processors: [memory_limiter, batch, resource]
      exporters: [jaeger, otlp, logging]
      
    metrics:
      receivers: [otlp, prometheus]
      processors: [memory_limiter, batch, resource]
      exporters: [prometheus, logging]
      
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch, resource]
      exporters: [logging]

  telemetry:
    logs:
      level: "debug"
    metrics:
      address: 0.0.0.0:8888
```

**Java Spring Boot 애플리케이션 계측**
```java
// TraceConfiguration.java
@Configuration
public class TraceConfiguration {
    
    @Bean
    public OpenTelemetry openTelemetry() {
        return OpenTelemetrySdk.builder()
                .setTracerProvider(
                    SdkTracerProvider.builder()
                        .addSpanProcessor(BatchSpanProcessor.builder(
                            OtlpGrpcSpanExporter.builder()
                                .setEndpoint("http://otel-collector:4317")
                                .build())
                            .build())
                        .setResource(Resource.getDefault()
                            .merge(Resource.builder()
                                .put(ResourceAttributes.SERVICE_NAME, "user-service")
                                .put(ResourceAttributes.SERVICE_VERSION, "1.0.0")
                                .put(ResourceAttributes.DEPLOYMENT_ENVIRONMENT, "production")
                                .build()))
                        .build())
                .setMeterProvider(
                    SdkMeterProvider.builder()
                        .registerMetricReader(
                            PeriodicMetricReader.builder(
                                OtlpGrpcMetricExporter.builder()
                                    .setEndpoint("http://otel-collector:4317")
                                    .build())
                                .setInterval(Duration.ofSeconds(30))
                                .build())
                        .setResource(Resource.getDefault()
                            .merge(Resource.builder()
                                .put(ResourceAttributes.SERVICE_NAME, "user-service")
                                .build()))
                        .build())
                .buildAndRegisterGlobal();
    }
}

// UserController.java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    private final UserService userService;
    private final Tracer tracer;
    private final Counter requestCounter;
    private final Timer requestTimer;
    
    public UserController(UserService userService, OpenTelemetry openTelemetry) {
        this.userService = userService;
        this.tracer = openTelemetry.getTracer("user-controller");
        
        Meter meter = openTelemetry.getMeter("user-controller");
        this.requestCounter = meter.counterBuilder("http_requests_total")
                .setDescription("Total number of HTTP requests")
                .build();
        this.requestTimer = Timer.builder("http_request_duration")
                .description("HTTP request duration")
                .register(Metrics.globalRegistry);
    }
    
    @GetMapping("/{userId}")
    public ResponseEntity<User> getUser(@PathVariable String userId) {
        Span span = tracer.spanBuilder("get-user")
                .setSpanKind(SpanKind.SERVER)
                .startSpan();
                
        Timer.Sample sample = Timer.start(Metrics.globalRegistry);
        
        try (Scope scope = span.makeCurrent()) {
            // 스팬에 속성 추가
            span.setAttribute("user.id", userId);
            span.setAttribute("http.method", "GET");
            span.setAttribute("http.route", "/api/users/{userId}");
            
            // 비즈니스 로직 실행
            User user = userService.findById(userId);
            
            if (user != null) {
                span.setStatus(StatusCode.OK);
                requestCounter.add(1, 
                    Attributes.of(AttributeKey.stringKey("status"), "success"));
                return ResponseEntity.ok(user);
            } else {
                span.setStatus(StatusCode.ERROR, "User not found");
                span.setAttribute("error", true);
                requestCounter.add(1, 
                    Attributes.of(AttributeKey.stringKey("status"), "not_found"));
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            span.recordException(e);
            span.setStatus(StatusCode.ERROR, e.getMessage());
            requestCounter.add(1, 
                Attributes.of(AttributeKey.stringKey("status"), "error"));
            throw e;
        } finally {
            sample.stop(requestTimer);
            span.end();
        }
    }
}

// UserService.java
@Service
public class UserService {
    
    private final UserRepository userRepository;
    private final NotificationService notificationService;
    private final Tracer tracer;
    
    public UserService(UserRepository userRepository, 
                      NotificationService notificationService,
                      OpenTelemetry openTelemetry) {
        this.userRepository = userRepository;
        this.notificationService = notificationService;
        this.tracer = openTelemetry.getTracer("user-service");
    }
    
    public User findById(String userId) {
        Span span = tracer.spanBuilder("user-service.find-by-id")
                .setSpanKind(SpanKind.INTERNAL)
                .startSpan();
                
        try (Scope scope = span.makeCurrent()) {
            span.setAttribute("operation", "findById");
            span.setAttribute("user.id", userId);
            
            // 데이터베이스 조회
            User user = userRepository.findById(userId);
            
            if (user != null) {
                // 추가 처리를 위한 자식 스팬
                processUserActivity(user);
            }
            
            return user;
            
        } finally {
            span.end();
        }
    }
    
    private void processUserActivity(User user) {
        Span span = tracer.spanBuilder("user-service.process-activity")
                .setSpanKind(SpanKind.INTERNAL)
                .startSpan();
                
        try (Scope scope = span.makeCurrent()) {
            span.setAttribute("user.id", user.getId());
            span.setAttribute("user.last_login", user.getLastLogin().toString());
            
            // 사용자 활동 로깅
            logUserActivity(user);
            
            // 알림 서비스 호출 (외부 서비스)
            notificationService.checkPendingNotifications(user.getId());
            
        } finally {
            span.end();
        }
    }
}
```

**Python Flask 애플리케이션 계측**
```python
# app.py
from flask import Flask, request, jsonify
from opentelemetry import trace, metrics
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
import time
import requests

# OpenTelemetry 초기화
resource = Resource.create({
    "service.name": "notification-service",
    "service.version": "1.0.0",
    "deployment.environment": "production"
})

# 트레이싱 설정
trace.set_tracer_provider(TracerProvider(resource=resource))
tracer = trace.get_tracer(__name__)

otlp_exporter = OTLPSpanExporter(endpoint="http://otel-collector:4317", insecure=True)
span_processor = BatchSpanProcessor(otlp_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

# 메트릭 설정
metric_reader = PeriodicExportingMetricReader(
    OTLPMetricExporter(endpoint="http://otel-collector:4317", insecure=True),
    export_interval_millis=30000
)
metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[metric_reader]))
meter = metrics.get_meter(__name__)

# 메트릭 정의
request_counter = meter.create_counter(
    "http_requests_total",
    description="Total number of HTTP requests"
)

request_duration = meter.create_histogram(
    "http_request_duration_seconds",
    description="HTTP request duration in seconds"
)

# Flask 앱 초기화
app = Flask(__name__)

# 자동 계측 활성화
FlaskInstrumentor().instrument_app(app)
RequestsInstrumentor().instrument()
SQLAlchemyInstrumentor().instrument(engine=db.engine)

@app.route('/notifications/<user_id>')
def get_notifications(user_id):
    with tracer.start_as_current_span("get-notifications") as span:
        start_time = time.time()
        
        try:
            # 스팬 속성 설정
            span.set_attribute("user.id", user_id)
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.url", request.url)
            
            # 비즈니스 로직
            notifications = fetch_user_notifications(user_id)
            
            # 외부 서비스 호출
            user_preferences = get_user_preferences(user_id)
            
            # 필터링
            filtered_notifications = filter_notifications(notifications, user_preferences)
            
            span.set_attribute("notifications.count", len(filtered_notifications))
            span.set_status(trace.Status(trace.StatusCode.OK))
            
            # 메트릭 기록
            duration = time.time() - start_time
            request_counter.add(1, {"status": "success", "endpoint": "get_notifications"})
            request_duration.record(duration, {"endpoint": "get_notifications"})
            
            return jsonify(filtered_notifications)
            
        except Exception as e:
            span.record_exception(e)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
            
            request_counter.add(1, {"status": "error", "endpoint": "get_notifications"})
            raise

def fetch_user_notifications(user_id):
    with tracer.start_as_current_span("fetch-user-notifications") as span:
        span.set_attribute("operation", "database_query")
        span.set_attribute("user.id", user_id)
        
        # 데이터베이스 쿼리 시뮬레이션
        time.sleep(0.05)  # 50ms 지연
        
        notifications = [
            {"id": 1, "message": "Welcome!", "type": "welcome"},
            {"id": 2, "message": "New feature available", "type": "feature"}
        ]
        
        span.set_attribute("notifications.fetched", len(notifications))
        return notifications

def get_user_preferences(user_id):
    with tracer.start_as_current_span("get-user-preferences") as span:
        span.set_attribute("operation", "external_api_call")
        span.set_attribute("user.id", user_id)
        
        try:
            # 외부 API 호출
            response = requests.get(
                f"http://user-service:8080/api/users/{user_id}/preferences",
                timeout=5
            )
            response.raise_for_status()
            
            preferences = response.json()
            span.set_attribute("http.status_code", response.status_code)
            return preferences
            
        except requests.exceptions.RequestException as e:
            span.record_exception(e)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
            # 기본값 반환
            return {"notifications_enabled": True, "types": ["welcome", "feature"]}

def filter_notifications(notifications, preferences):
    with tracer.start_as_current_span("filter-notifications") as span:
        span.set_attribute("operation", "filter")
        span.set_attribute("input.count", len(notifications))
        
        if not preferences.get("notifications_enabled", True):
            return []
        
        allowed_types = preferences.get("types", [])
        filtered = [n for n in notifications if n["type"] in allowed_types]
        
        span.set_attribute("output.count", len(filtered))
        return filtered
```

### 1.2 Jaeger/Zipkin 통합

**Jaeger 배포 구성**
```yaml
# jaeger-deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jaeger
  template:
    metadata:
      labels:
        app: jaeger
    spec:
      containers:
      - name: jaeger
        image: jaegertracing/all-in-one:latest
        ports:
        - containerPort: 16686  # UI
        - containerPort: 14268  # HTTP collector
        - containerPort: 14250  # gRPC collector
        - containerPort: 9411   # Zipkin compatible
        env:
        - name: COLLECTOR_OTLP_ENABLED
          value: "true"
        - name: SPAN_STORAGE_TYPE
          value: "elasticsearch"
        - name: ES_SERVER_URLS
          value: "http://elasticsearch:9200"
        - name: ES_USERNAME
          value: "elastic"
        - name: ES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: elasticsearch-secret
              key: password
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: jaeger
  namespace: monitoring
spec:
  selector:
    app: jaeger
  ports:
  - name: ui
    port: 16686
    targetPort: 16686
  - name: collector-http
    port: 14268
    targetPort: 14268
  - name: collector-grpc
    port: 14250
    targetPort: 14250
  - name: zipkin
    port: 9411
    targetPort: 9411
```

**Grafana 트레이스 통합**
```json
{
  "datasources": [
    {
      "name": "Jaeger",
      "type": "jaeger",
      "url": "http://jaeger:16686",
      "access": "proxy",
      "basicAuth": false,
      "isDefault": false,
      "jsonData": {
        "tracesToLogs": {
          "datasourceUid": "loki-uid",
          "tags": ["job", "instance", "pod", "namespace"],
          "mappedTags": [
            {"key": "service.name", "value": "service"}
          ],
          "mapTagNamesEnabled": true,
          "spanStartTimeShift": "-1h",
          "spanEndTimeShift": "1h",
          "filterByTraceID": true,
          "filterBySpanID": false
        },
        "tracesToMetrics": {
          "datasourceUid": "prometheus-uid",
          "tags": [
            {"key": "service.name", "value": "service"},
            {"key": "operation", "value": "operation"}
          ],
          "queries": [
            {
              "name": "Sample query",
              "query": "sum(rate(traces_spanmetrics_latency_bucket{$$__tags}[5m]))"
            }
          ]
        },
        "nodeGraph": {
          "enabled": true
        }
      }
    }
  ]
}
```

### 1.3 메트릭 및 로그와의 트레이스 상관관계

**통합 관측성 대시보드**
```json
{
  "dashboard": {
    "title": "Service Observability",
    "panels": [
      {
        "title": "Request Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{service_name=\"user-service\"}[5m]))",
            "legendFormat": "RPS"
          }
        ]
      },
      {
        "title": "Response Time Distribution", 
        "type": "heatmap",
        "targets": [
          {
            "expr": "sum(rate(http_request_duration_seconds_bucket{service_name=\"user-service\"}[5m])) by (le)",
            "format": "heatmap",
            "legendFormat": "{{le}}"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "stat", 
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{service_name=\"user-service\",status=~\"5..\"}[5m])) / sum(rate(http_requests_total{service_name=\"user-service\"}[5m]))",
            "legendFormat": "Error %"
          }
        ]
      },
      {
        "title": "Recent Traces",
        "type": "traces",
        "datasource": "Jaeger",
        "targets": [
          {
            "query": "{service.name=\"user-service\"}",
            "queryType": "",
            "refId": "A"
          }
        ]
      },
      {
        "title": "Service Map",
        "type": "nodeGraph",
        "datasource": "Jaeger",
        "targets": [
          {
            "query": "{service.name=\"user-service\"}",
            "queryType": "",
            "refId": "A"
          }
        ]
      }
    ]
  }
}
```

**로그-트레이스 상관관계**
```python
# trace_log_correlation.py
import logging
from opentelemetry import trace
from opentelemetry.instrumentation.logging import LoggingInstrumentor

# 로깅 계측 활성화
LoggingInstrumentor().instrument(set_logging_format=True)

class TraceContextFilter(logging.Filter):
    """로그에 트레이스 컨텍스트 추가"""
    
    def filter(self, record):
        span = trace.get_current_span()
        if span and span.get_span_context().is_valid:
            span_context = span.get_span_context()
            record.trace_id = format(span_context.trace_id, '032x')
            record.span_id = format(span_context.span_id, '016x')
            record.trace_flags = span_context.trace_flags
        else:
            record.trace_id = ""
            record.span_id = ""
            record.trace_flags = ""
        return True

# 로거 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [trace_id=%(trace_id)s span_id=%(span_id)s] - %(message)s'
)

logger = logging.getLogger(__name__)
logger.addFilter(TraceContextFilter())

# 사용 예제
def process_order(order_id):
    with tracer.start_as_current_span("process-order") as span:
        span.set_attribute("order.id", order_id)
        
        logger.info(f"Processing order {order_id}")
        
        try:
            # 주문 처리 로직
            validate_order(order_id)
            calculate_total(order_id)
            process_payment(order_id)
            
            logger.info(f"Order {order_id} processed successfully")
            
        except Exception as e:
            logger.error(f"Failed to process order {order_id}: {str(e)}")
            span.record_exception(e)
            raise

def validate_order(order_id):
    with tracer.start_as_current_span("validate-order") as span:
        span.set_attribute("order.id", order_id)
        logger.debug(f"Validating order {order_id}")
        
        # 검증 로직
        if not order_exists(order_id):
            logger.warning(f"Order {order_id} not found")
            raise ValueError(f"Order {order_id} not found")
            
        logger.debug(f"Order {order_id} validation completed")
```

## 2. 애플리케이션 메트릭

### 2.1 비즈니스 메트릭 및 KPI 모니터링

**비즈니스 메트릭 수집기**
```python
# business_metrics_collector.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
from typing import Dict, Any

class BusinessMetricsCollector:
    def __init__(self):
        # 주문 관련 메트릭
        self.orders_total = Counter(
            'orders_total', 
            'Total number of orders',
            ['status', 'product_category', 'customer_tier']
        )
        
        self.order_value = Histogram(
            'order_value_dollars',
            'Order value in dollars',
            ['product_category', 'customer_tier'],
            buckets=[10, 50, 100, 250, 500, 1000, 2500, 5000, float('inf')]
        )
        
        self.order_processing_time = Histogram(
            'order_processing_duration_seconds',
            'Time taken to process an order',
            ['processing_stage'],
            buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60, float('inf')]
        )
        
        # 고객 관련 메트릭
        self.customer_registrations = Counter(
            'customer_registrations_total',
            'Total customer registrations',
            ['source', 'tier']
        )
        
        self.active_users = Gauge(
            'active_users',
            'Number of active users',
            ['time_window']
        )
        
        self.customer_lifetime_value = Histogram(
            'customer_lifetime_value_dollars',
            'Customer lifetime value',
            ['customer_tier', 'acquisition_channel'],
            buckets=[100, 500, 1000, 2500, 5000, 10000, float('inf')]
        )
        
        # 재고 관련 메트릭
        self.inventory_levels = Gauge(
            'inventory_level',
            'Current inventory level',
            ['product_id', 'warehouse']
        )
        
        self.stockout_events = Counter(
            'stockout_events_total',
            'Total stockout events',
            ['product_category', 'warehouse']
        )
        
        # 매출 관련 메트릭
        self.revenue_daily = Gauge(
            'revenue_daily_dollars',
            'Daily revenue in dollars',
            ['date', 'product_category']
        )
        
        self.conversion_rate = Gauge(
            'conversion_rate_percent',
            'Conversion rate percentage',
            ['funnel_stage', 'customer_segment']
        )
    
    def record_order(self, order_data: Dict[str, Any]):
        """주문 메트릭 기록"""
        status = order_data.get('status', 'unknown')
        category = order_data.get('product_category', 'unknown')
        tier = order_data.get('customer_tier', 'standard')
        value = order_data.get('value', 0)
        
        self.orders_total.labels(
            status=status,
            product_category=category,
            customer_tier=tier
        ).inc()
        
        self.order_value.labels(
            product_category=category,
            customer_tier=tier
        ).observe(value)
    
    def record_order_processing_time(self, stage: str, duration: float):
        """주문 처리 시간 기록"""
        self.order_processing_time.labels(processing_stage=stage).observe(duration)
    
    def record_customer_registration(self, source: str, tier: str):
        """고객 등록 기록"""
        self.customer_registrations.labels(source=source, tier=tier).inc()
    
    def update_active_users(self, count: int, time_window: str):
        """활성 사용자 수 업데이트"""
        self.active_users.labels(time_window=time_window).set(count)
    
    def update_inventory(self, product_id: str, warehouse: str, level: int):
        """재고 수준 업데이트"""
        self.inventory_levels.labels(
            product_id=product_id,
            warehouse=warehouse
        ).set(level)
        
        # 재고 부족 감지
        if level == 0:
            category = self.get_product_category(product_id)
            self.stockout_events.labels(
                product_category=category,
                warehouse=warehouse
            ).inc()
    
    def update_daily_revenue(self, date: str, category: str, revenue: float):
        """일일 매출 업데이트"""
        self.revenue_daily.labels(
            date=date,
            product_category=category
        ).set(revenue)
    
    def update_conversion_rate(self, stage: str, segment: str, rate: float):
        """전환율 업데이트"""
        self.conversion_rate.labels(
            funnel_stage=stage,
            customer_segment=segment
        ).set(rate)

# 비즈니스 메트릭 대시보드
business_dashboard = {
    "dashboard": {
        "title": "Business KPI Dashboard",
        "panels": [
            {
                "title": "Order Volume",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(increase(orders_total[1h]))",
                        "legendFormat": "Orders/Hour"
                    }
                ]
            },
            {
                "title": "Revenue by Category",
                "type": "piechart",
                "targets": [
                    {
                        "expr": "sum by (product_category) (revenue_daily_dollars)",
                        "legendFormat": "{{product_category}}"
                    }
                ]
            },
            {
                "title": "Average Order Value",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(increase(order_value_dollars_sum[24h])) / sum(increase(order_value_dollars_count[24h]))",
                        "legendFormat": "AOV"
                    }
                ]
            },
            {
                "title": "Conversion Funnel",
                "type": "bargauge",
                "targets": [
                    {
                        "expr": "conversion_rate_percent",
                        "legendFormat": "{{funnel_stage}}"
                    }
                ]
            },
            {
                "title": "Customer Acquisition",
                "type": "timeseries",
                "targets": [
                    {
                        "expr": "sum by (source) (increase(customer_registrations_total[1h]))",
                        "legendFormat": "{{source}}"
                    }
                ]
            }
        ]
    }
}
```

### 2.2 커스텀 애플리케이션 계측

**커스텀 메트릭 데코레이터**
```python
# custom_instrumentation.py
import functools
import time
from prometheus_client import Counter, Histogram, Gauge
from typing import Callable, Any

class ApplicationInstrumentor:
    def __init__(self):
        self.function_calls = Counter(
            'function_calls_total',
            'Total function calls',
            ['function_name', 'status']
        )
        
        self.function_duration = Histogram(
            'function_duration_seconds', 
            'Function execution time',
            ['function_name'],
            buckets=[0.001, 0.01, 0.1, 0.5, 1, 2, 5, 10, float('inf')]
        )
        
        self.cache_operations = Counter(
            'cache_operations_total',
            'Cache operations',
            ['operation', 'cache_name', 'result']
        )
        
        self.database_queries = Counter(
            'database_queries_total',
            'Database queries',
            ['query_type', 'table', 'status']
        )
        
        self.database_query_duration = Histogram(
            'database_query_duration_seconds',
            'Database query execution time',
            ['query_type', 'table'],
            buckets=[0.001, 0.01, 0.1, 0.5, 1, 2, 5, float('inf')]
        )
    
    def instrument_function(self, func: Callable) -> Callable:
        """함수 실행 시간 및 호출 횟수 계측"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            function_name = f"{func.__module__}.{func.__name__}"
            
            try:
                result = func(*args, **kwargs)
                self.function_calls.labels(
                    function_name=function_name,
                    status='success'
                ).inc()
                return result
                
            except Exception as e:
                self.function_calls.labels(
                    function_name=function_name,
                    status='error'
                ).inc()
                raise
                
            finally:
                duration = time.time() - start_time
                self.function_duration.labels(
                    function_name=function_name
                ).observe(duration)
                
        return wrapper
    
    def instrument_cache(self, cache_name: str):
        """캐시 작업 계측 데코레이터"""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                operation = func.__name__
                
                try:
                    result = func(*args, **kwargs)
                    
                    # 캐시 히트/미스 판정
                    if operation == 'get' and result is not None:
                        cache_result = 'hit'
                    elif operation == 'get' and result is None:
                        cache_result = 'miss'
                    else:
                        cache_result = 'operation'
                    
                    self.cache_operations.labels(
                        operation=operation,
                        cache_name=cache_name,
                        result=cache_result
                    ).inc()
                    
                    return result
                    
                except Exception as e:
                    self.cache_operations.labels(
                        operation=operation,
                        cache_name=cache_name,
                        result='error'
                    ).inc()
                    raise
                    
            return wrapper
        return decorator
    
    def instrument_database(self, query_type: str, table: str):
        """데이터베이스 쿼리 계측 데코레이터"""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                
                try:
                    result = func(*args, **kwargs)
                    self.database_queries.labels(
                        query_type=query_type,
                        table=table,
                        status='success'
                    ).inc()
                    return result
                    
                except Exception as e:
                    self.database_queries.labels(
                        query_type=query_type,
                        table=table,
                        status='error'
                    ).inc()
                    raise
                    
                finally:
                    duration = time.time() - start_time
                    self.database_query_duration.labels(
                        query_type=query_type,
                        table=table
                    ).observe(duration)
                    
            return wrapper
        return decorator

# 사용 예제
instrumentor = ApplicationInstrumentor()

class UserService:
    def __init__(self, cache, database):
        self.cache = cache
        self.database = database
    
    @instrumentor.instrument_function
    def get_user(self, user_id: str):
        """사용자 정보 조회"""
        # 캐시에서 먼저 확인
        user = self.cache.get(f"user:{user_id}")
        if user:
            return user
        
        # 데이터베이스에서 조회
        user = self.database.query_user(user_id)
        if user:
            self.cache.set(f"user:{user_id}", user, ttl=300)
        
        return user
    
    @instrumentor.instrument_function
    def update_user(self, user_id: str, data: dict):
        """사용자 정보 업데이트"""
        # 데이터베이스 업데이트
        self.database.update_user(user_id, data)
        
        # 캐시 무효화
        self.cache.delete(f"user:{user_id}")

class RedisCache:
    @instrumentor.instrument_cache('user_cache')
    def get(self, key: str):
        # Redis GET 구현
        pass
    
    @instrumentor.instrument_cache('user_cache')
    def set(self, key: str, value: Any, ttl: int):
        # Redis SET 구현
        pass
    
    @instrumentor.instrument_cache('user_cache')
    def delete(self, key: str):
        # Redis DELETE 구현
        pass

class DatabaseService:
    @instrumentor.instrument_database('SELECT', 'users')
    def query_user(self, user_id: str):
        # 데이터베이스 SELECT 구현
        pass
    
    @instrumentor.instrument_database('UPDATE', 'users')
    def update_user(self, user_id: str, data: dict):
        # 데이터베이스 UPDATE 구현
        pass
```

### 2.3 성능 병목 지점 식별 기법

**성능 프로파일링 시스템**
```python
# performance_profiler.py
import cProfile
import pstats
import io
import functools
import time
from typing import Dict, List, Any
import threading
from collections import defaultdict

class PerformanceProfiler:
    def __init__(self):
        self.profiles = {}
        self.bottlenecks = defaultdict(list)
        self.lock = threading.Lock()
        
    def profile_function(self, func):
        """함수 성능 프로파일링"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            profiler = cProfile.Profile()
            profiler.enable()
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                profiler.disable()
                
                # 프로파일 결과 저장
                function_name = f"{func.__module__}.{func.__name__}"
                with self.lock:
                    self.profiles[function_name] = profiler
                    
                # 병목 지점 분석
                self.analyze_bottlenecks(function_name, profiler)
                
        return wrapper
    
    def analyze_bottlenecks(self, function_name: str, profiler: cProfile.Profile):
        """병목 지점 분석"""
        stats_stream = io.StringIO()
        stats = pstats.Stats(profiler, stream=stats_stream)
        stats.sort_stats('cumulative')
        stats.print_stats(10)  # 상위 10개
        
        # 통계 파싱
        stats_output = stats_stream.getvalue()
        lines = stats_output.split('\n')
        
        bottlenecks = []
        for line in lines:
            if 'function calls' in line or 'filename:lineno' in line:
                continue
            
            parts = line.split()
            if len(parts) >= 6:
                ncalls = parts[0]
                tottime = float(parts[1]) if parts[1].replace('.', '').isdigit() else 0
                cumtime = float(parts[3]) if parts[3].replace('.', '').isdigit() else 0
                
                if cumtime > 0.1:  # 100ms 이상
                    bottlenecks.append({
                        'function': ' '.join(parts[5:]),
                        'calls': ncalls,
                        'total_time': tottime,
                        'cumulative_time': cumtime
                    })
        
        with self.lock:
            self.bottlenecks[function_name] = bottlenecks
    
    def get_performance_report(self) -> Dict[str, Any]:
        """성능 분석 보고서 생성"""
        with self.lock:
            report = {
                'timestamp': time.time(),
                'profiled_functions': list(self.profiles.keys()),
                'bottlenecks': dict(self.bottlenecks),
                'recommendations': self.generate_recommendations()
            }
        
        return report
    
    def generate_recommendations(self) -> List[str]:
        """성능 개선 권장사항 생성"""
        recommendations = []
        
        for function_name, bottlenecks in self.bottlenecks.items():
            for bottleneck in bottlenecks:
                cumtime = bottleneck['cumulative_time']
                func_name = bottleneck['function']
                
                if cumtime > 1.0:  # 1초 이상
                    recommendations.append(
                        f"{function_name}: {func_name} 함수 최적화 필요 (실행시간: {cumtime:.2f}s)"
                    )
                elif 'sleep' in func_name.lower():
                    recommendations.append(
                        f"{function_name}: 불필요한 대기 시간 제거 고려"
                    )
                elif 'query' in func_name.lower() or 'select' in func_name.lower():
                    recommendations.append(
                        f"{function_name}: 데이터베이스 쿼리 최적화 검토"
                    )
        
        return recommendations

# 실시간 성능 모니터링
class RealTimePerformanceMonitor:
    def __init__(self, prometheus_client):
        self.prometheus = prometheus_client
        self.alerting_thresholds = {
            'response_time_p95': 2.0,  # 2초
            'response_time_p99': 5.0,  # 5초
            'error_rate': 0.05,        # 5%
            'throughput_drop': 0.3     # 30% 감소
        }
    
    def check_performance_anomalies(self, service_name: str, time_window: str = '5m'):
        """성능 이상 감지"""
        anomalies = []
        
        # 응답 시간 체크
        p95_query = f'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{{service="{service_name}"}}[{time_window}]))'
        p99_query = f'histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{{service="{service_name}"}}[{time_window}]))'
        
        p95_result = self.prometheus.query(p95_query)
        p99_result = self.prometheus.query(p99_query)
        
        if p95_result and float(p95_result[0]['value'][1]) > self.alerting_thresholds['response_time_p95']:
            anomalies.append({
                'type': 'high_response_time_p95',
                'value': float(p95_result[0]['value'][1]),
                'threshold': self.alerting_thresholds['response_time_p95']
            })
        
        if p99_result and float(p99_result[0]['value'][1]) > self.alerting_thresholds['response_time_p99']:
            anomalies.append({
                'type': 'high_response_time_p99',
                'value': float(p99_result[0]['value'][1]),
                'threshold': self.alerting_thresholds['response_time_p99']
            })
        
        # 에러율 체크
        error_rate_query = f'rate(http_requests_total{{service="{service_name}",status=~"5.."}}[{time_window}]) / rate(http_requests_total{{service="{service_name}"}}[{time_window}])'
        error_rate_result = self.prometheus.query(error_rate_query)
        
        if error_rate_result and float(error_rate_result[0]['value'][1]) > self.alerting_thresholds['error_rate']:
            anomalies.append({
                'type': 'high_error_rate',
                'value': float(error_rate_result[0]['value'][1]),
                'threshold': self.alerting_thresholds['error_rate']
            })
        
        # 처리량 감소 체크
        current_throughput_query = f'rate(http_requests_total{{service="{service_name}"}}[{time_window}])'
        baseline_throughput_query = f'rate(http_requests_total{{service="{service_name}"}}[1h] offset 1d)'
        
        current_result = self.prometheus.query(current_throughput_query)
        baseline_result = self.prometheus.query(baseline_throughput_query)
        
        if current_result and baseline_result:
            current_throughput = float(current_result[0]['value'][1])
            baseline_throughput = float(baseline_result[0]['value'][1])
            
            if baseline_throughput > 0:
                throughput_ratio = current_throughput / baseline_throughput
                if throughput_ratio < (1 - self.alerting_thresholds['throughput_drop']):
                    anomalies.append({
                        'type': 'throughput_drop',
                        'current_throughput': current_throughput,
                        'baseline_throughput': baseline_throughput,
                        'drop_percentage': (1 - throughput_ratio) * 100
                    })
        
        return anomalies
    
    def generate_performance_insights(self, service_name: str):
        """성능 인사이트 생성"""
        insights = {
            'service_name': service_name,
            'analysis_time': time.time(),
            'performance_summary': {},
            'bottleneck_analysis': {},
            'optimization_recommendations': []
        }
        
        # 성능 요약
        queries = {
            'avg_response_time': f'avg(rate(http_request_duration_seconds_sum{{service="{service_name}"}}[5m])) / avg(rate(http_request_duration_seconds_count{{service="{service_name}"}}[5m]))',
            'request_rate': f'sum(rate(http_requests_total{{service="{service_name}"}}[5m]))',
            'error_rate': f'sum(rate(http_requests_total{{service="{service_name}",status=~"5.."}}[5m])) / sum(rate(http_requests_total{{service="{service_name}"}}[5m]))',
            'cpu_usage': f'avg(rate(container_cpu_usage_seconds_total{{pod=~"{service_name}.*"}}[5m]))',
            'memory_usage': f'avg(container_memory_usage_bytes{{pod=~"{service_name}.*"}})'
        }
        
        for metric, query in queries.items():
            result = self.prometheus.query(query)
            if result:
                insights['performance_summary'][metric] = float(result[0]['value'][1])
        
        # 최적화 권장사항
        if insights['performance_summary'].get('avg_response_time', 0) > 1.0:
            insights['optimization_recommendations'].append(
                "응답 시간이 높습니다. 데이터베이스 쿼리 최적화나 캐싱 도입을 고려하세요."
            )
        
        if insights['performance_summary'].get('cpu_usage', 0) > 0.8:
            insights['optimization_recommendations'].append(
                "CPU 사용률이 높습니다. 수평 확장이나 알고리즘 최적화를 검토하세요."
            )
        
        return insights
```

## 3. 실습 과제

### 과제 1: OpenTelemetry 분산 추적 구현
1. 마이크로서비스 간 분산 추적 설정
2. 커스텀 스팬 및 메트릭 추가
3. Jaeger와 Grafana 통합

### 과제 2: 비즈니스 메트릭 대시보드
1. 주요 비즈니스 KPI 메트릭 정의
2. 실시간 비즈니스 대시보드 구축
3. 알림 규칙 설정

### 과제 3: 성능 병목 분석 시스템
1. 자동 성능 프로파일링 구현
2. 병목 지점 탐지 및 분석
3. 성능 개선 권장사항 시스템

## 4. 다음 단계
- 로그 관리 및 분석 (Phase 4-2)
- 보안 모니터링 및 컴플라이언스 (Phase 4-3)