# 로그 관리 및 분석 (Phase 4-2)

## 개요
대규모 분산 시스템에서 로그 수집, 저장, 분석, 상관관계 분석을 통한 종합적인 로그 관리 시스템 구축 방법을 학습합니다.

## 1. ELK 스택 통합

### 1.1 Elasticsearch 클러스터 구성

**Elasticsearch 클러스터 배포**
```yaml
# elasticsearch-cluster.yml
apiVersion: elasticsearch.k8s.elastic.co/v1
kind: Elasticsearch
metadata:
  name: monitoring-logs
  namespace: logging
spec:
  version: 8.11.0
  
  nodeSets:
  # 마스터 노드
  - name: master
    count: 3
    config:
      node.roles: ["master"]
      xpack.security.enabled: true
      xpack.security.transport.ssl.enabled: true
      xpack.security.http.ssl.enabled: true
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 2Gi
              cpu: 1000m
            limits:
              memory: 2Gi
              cpu: 1000m
          env:
          - name: ES_JAVA_OPTS
            value: "-Xms1g -Xmx1g"
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 50Gi
        storageClassName: fast-ssd
  
  # 데이터 노드 - 핫 티어
  - name: data-hot
    count: 3
    config:
      node.roles: ["data_hot", "data_content", "ingest"]
      xpack.security.enabled: true
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 8Gi
              cpu: 2000m
            limits:
              memory: 8Gi
              cpu: 2000m
          env:
          - name: ES_JAVA_OPTS
            value: "-Xms4g -Xmx4g"
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 500Gi
        storageClassName: fast-ssd
  
  # 데이터 노드 - 웜 티어
  - name: data-warm
    count: 2
    config:
      node.roles: ["data_warm", "data_content"]
      xpack.security.enabled: true
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 4Gi
              cpu: 1000m
            limits:
              memory: 4Gi
              cpu: 1000m
          env:
          - name: ES_JAVA_OPTS
            value: "-Xms2g -Xmx2g"
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 1000Gi
        storageClassName: standard
  
  # 데이터 노드 - 콜드 티어
  - name: data-cold
    count: 1
    config:
      node.roles: ["data_cold", "data_content"]
      xpack.security.enabled: true
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 2Gi
              cpu: 500m
            limits:
              memory: 2Gi
              cpu: 500m
          env:
          - name: ES_JAVA_OPTS
            value: "-Xms1g -Xmx1g"
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 2000Gi
        storageClassName: cheap-storage

  http:
    tls:
      selfSignedCertificate:
        disabled: false
```

**인덱스 라이프사이클 관리**
```json
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "10gb",
            "max_age": "1d",
            "max_docs": 10000000
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "allocate": {
            "number_of_replicas": 1,
            "require": {
              "data_tier": "data_warm"
            }
          },
          "forcemerge": {
            "max_num_segments": 1
          },
          "set_priority": {
            "priority": 50
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0,
            "require": {
              "data_tier": "data_cold"
            }
          },
          "set_priority": {
            "priority": 0
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

### 1.2 Logstash 파이프라인 구성

**고급 Logstash 구성**
```ruby
# logstash.conf
input {
  # Filebeat에서 로그 수집
  beats {
    port => 5044
    type => "application_logs"
  }
  
  # Fluentd에서 로그 수집
  http {
    port => 8080
    type => "container_logs"
  }
  
  # Kafka에서 로그 수집 (고성능)
  kafka {
    bootstrap_servers => "kafka-cluster:9092"
    topics => ["application-logs", "system-logs", "security-logs"]
    group_id => "logstash-consumers"
    consumer_threads => 3
    codec => json
  }
  
  # syslog 수집
  syslog {
    port => 514
    type => "syslog"
  }
}

filter {
  # 타입별 처리
  if [type] == "application_logs" {
    # JSON 파싱
    if [message] =~ /^\{.*\}$/ {
      json {
        source => "message"
        target => "parsed"
      }
      
      # 파싱된 필드 추출
      if [parsed] {
        mutate {
          add_field => {
            "log_level" => "%{[parsed][level]}"
            "service_name" => "%{[parsed][service]}"
            "trace_id" => "%{[parsed][trace_id]}"
            "span_id" => "%{[parsed][span_id]}"
          }
        }
      }
    } else {
      # 일반 텍스트 로그 파싱
      grok {
        match => {
          "message" => "%{TIMESTAMP_ISO8601:timestamp} \[%{LOGLEVEL:log_level}\] %{DATA:logger_name} - %{GREEDYDATA:log_message}"
        }
      }
    }
  }
  
  if [type] == "container_logs" {
    # 컨테이너 메타데이터 추가
    if [kubernetes] {
      mutate {
        add_field => {
          "k8s_namespace" => "%{[kubernetes][namespace]}"
          "k8s_pod" => "%{[kubernetes][pod]}"
          "k8s_container" => "%{[kubernetes][container]}"
        }
      }
    }
  }
  
  # 공통 필터
  # 타임스탬프 정규화
  date {
    match => [ "timestamp", "ISO8601", "yyyy-MM-dd HH:mm:ss,SSS" ]
    target => "@timestamp"
  }
  
  # IP 주소 지역 정보 추가
  if [client_ip] {
    geoip {
      source => "client_ip"
      target => "geoip"
    }
  }
  
  # 민감한 정보 마스킹
  mutate {
    gsub => [
      "message", "password=[^\\s]+", "password=***REDACTED***",
      "message", "token=[^\\s]+", "token=***REDACTED***",
      "message", "\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b", "****-****-****-****"
    ]
  }
  
  # 로그 레벨별 우선순위 설정
  if [log_level] == "ERROR" {
    mutate {
      add_field => { "priority" => "high" }
      add_tag => [ "error" ]
    }
  } else if [log_level] == "WARN" {
    mutate {
      add_field => { "priority" => "medium" }
      add_tag => [ "warning" ]
    }
  } else {
    mutate {
      add_field => { "priority" => "low" }
    }
  }
  
  # 성능 메트릭 추출
  if [message] =~ /response_time/ {
    grok {
      match => {
        "message" => "response_time=(?<response_time_ms>\\d+)"
      }
    }
    
    if [response_time_ms] {
      mutate {
        convert => { "response_time_ms" => "integer" }
      }
    }
  }
  
  # 에러 스택 트레이스 처리
  if [log_level] == "ERROR" and [message] =~ /Exception|Error/ {
    multiline {
      pattern => "^\\s"
      what => "previous"
      negate => false
    }
  }
}

output {
  # Elasticsearch 출력 (인덱스 분산)
  if [type] == "application_logs" {
    elasticsearch {
      hosts => ["elasticsearch-master:9200"]
      index => "application-logs-%{+YYYY.MM.dd}"
      template_name => "application-logs"
      template => "/usr/share/logstash/templates/application-logs-template.json"
      template_overwrite => true
      
      # 인증 설정
      user => "${ELASTICSEARCH_USERNAME}"
      password => "${ELASTICSEARCH_PASSWORD}"
      ssl => true
      ssl_certificate_verification => false
    }
  }
  
  if [type] == "system_logs" {
    elasticsearch {
      hosts => ["elasticsearch-master:9200"]
      index => "system-logs-%{+YYYY.MM.dd}"
      template_name => "system-logs"
      template => "/usr/share/logstash/templates/system-logs-template.json"
      template_overwrite => true
      
      user => "${ELASTICSEARCH_USERNAME}"
      password => "${ELASTICSEARCH_PASSWORD}"
      ssl => true
      ssl_certificate_verification => false
    }
  }
  
  # 에러 로그는 별도 인덱스로
  if "error" in [tags] {
    elasticsearch {
      hosts => ["elasticsearch-master:9200"]
      index => "error-logs-%{+YYYY.MM.dd}"
      
      user => "${ELASTICSEARCH_USERNAME}"
      password => "${ELASTICSEARCH_PASSWORD}"
      ssl => true
      ssl_certificate_verification => false
    }
  }
  
  # 고우선순위 로그는 실시간 알림
  if [priority] == "high" {
    http {
      url => "http://alertmanager:9093/api/v1/alerts"
      http_method => "post"
      content_type => "application/json"
      format => "json"
      mapping => {
        "alerts" => [
          {
            "labels" => {
              "alertname" => "HighPriorityLogEvent"
              "service" => "%{service_name}"
              "severity" => "critical"
            }
            "annotations" => {
              "summary" => "High priority log event detected"
              "description" => "%{message}"
            }
          }
        ]
      }
    }
  }
  
  # 디버깅용 stdout (개발 환경)
  if [fields][environment] == "development" {
    stdout {
      codec => rubydebug
    }
  }
}
```

### 1.3 Kibana 대시보드 통합

**Kibana 고급 대시보드 설정**
```json
{
  "dashboard": {
    "title": "Application Logs Analysis",
    "panels": [
      {
        "title": "Log Volume by Service",
        "type": "histogram",
        "query": {
          "bool": {
            "filter": [
              {
                "range": {
                  "@timestamp": {
                    "gte": "now-1h"
                  }
                }
              }
            ]
          }
        },
        "aggs": {
          "services": {
            "terms": {
              "field": "service_name.keyword",
              "size": 10
            },
            "aggs": {
              "log_count": {
                "date_histogram": {
                  "field": "@timestamp",
                  "interval": "5m"
                }
              }
            }
          }
        }
      },
      {
        "title": "Error Rate by Service",
        "type": "line",
        "query": {
          "bool": {
            "filter": [
              {
                "range": {
                  "@timestamp": {
                    "gte": "now-24h"
                  }
                }
              }
            ]
          }
        },
        "aggs": {
          "time_buckets": {
            "date_histogram": {
              "field": "@timestamp",
              "interval": "1h"
            },
            "aggs": {
              "services": {
                "terms": {
                  "field": "service_name.keyword"
                },
                "aggs": {
                  "error_rate": {
                    "bucket_script": {
                      "buckets_path": {
                        "errors": "errors>_count",
                        "total": "_count"
                      },
                      "script": "params.errors / params.total * 100"
                    }
                  },
                  "errors": {
                    "filter": {
                      "term": {
                        "log_level.keyword": "ERROR"
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      {
        "title": "Top Error Messages",
        "type": "data_table",
        "query": {
          "bool": {
            "filter": [
              {
                "term": {
                  "log_level.keyword": "ERROR"
                }
              },
              {
                "range": {
                  "@timestamp": {
                    "gte": "now-1h"
                  }
                }
              }
            ]
          }
        },
        "aggs": {
          "error_messages": {
            "terms": {
              "field": "message.keyword",
              "size": 20,
              "order": {
                "_count": "desc"
              }
            },
            "aggs": {
              "services": {
                "terms": {
                  "field": "service_name.keyword",
                  "size": 5
                }
              }
            }
          }
        }
      },
      {
        "title": "Response Time Distribution",
        "type": "histogram",
        "query": {
          "bool": {
            "filter": [
              {
                "exists": {
                  "field": "response_time_ms"
                }
              }
            ]
          }
        },
        "aggs": {
          "response_time_histogram": {
            "histogram": {
              "field": "response_time_ms",
              "interval": 100,
              "min_doc_count": 1
            }
          }
        }
      }
    ]
  }
}
```

## 2. 고급 로그 분석

### 2.1 메트릭 및 트레이스와의 로그 상관관계

**로그-메트릭-트레이스 상관관계 분석기**
```python
# log_correlation_analyzer.py
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import elasticsearch
import requests

class LogCorrelationAnalyzer:
    def __init__(self, elasticsearch_client, prometheus_client, jaeger_client):
        self.es = elasticsearch_client
        self.prometheus = prometheus_client
        self.jaeger = jaeger_client
        
    def analyze_incident_correlation(self, incident_time: datetime, 
                                   time_window: int = 300) -> Dict[str, Any]:
        """인시던트 시점의 로그-메트릭-트레이스 상관관계 분석"""
        start_time = incident_time - timedelta(seconds=time_window)
        end_time = incident_time + timedelta(seconds=time_window)
        
        analysis_result = {
            'incident_time': incident_time.isoformat(),
            'analysis_window': f"{time_window}s",
            'logs_analysis': self._analyze_logs_around_incident(start_time, end_time),
            'metrics_analysis': self._analyze_metrics_around_incident(start_time, end_time),
            'traces_analysis': self._analyze_traces_around_incident(start_time, end_time),
            'correlations': {},
            'timeline': []
        }
        
        # 상관관계 분석
        analysis_result['correlations'] = self._find_correlations(analysis_result)
        
        # 시간순 이벤트 타임라인 구성
        analysis_result['timeline'] = self._build_incident_timeline(analysis_result)
        
        return analysis_result
    
    def _analyze_logs_around_incident(self, start_time: datetime, 
                                    end_time: datetime) -> Dict[str, Any]:
        """인시던트 주변 로그 분석"""
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "log_levels": {
                    "terms": {
                        "field": "log_level.keyword",
                        "size": 10
                    }
                },
                "services": {
                    "terms": {
                        "field": "service_name.keyword",
                        "size": 20
                    },
                    "aggs": {
                        "error_count": {
                            "filter": {
                                "term": {
                                    "log_level.keyword": "ERROR"
                                }
                            }
                        }
                    }
                },
                "error_messages": {
                    "filter": {
                        "term": {
                            "log_level.keyword": "ERROR"
                        }
                    },
                    "aggs": {
                        "top_errors": {
                            "terms": {
                                "field": "message.keyword",
                                "size": 10
                            }
                        }
                    }
                },
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "interval": "1m"
                    },
                    "aggs": {
                        "error_rate": {
                            "filter": {
                                "term": {
                                    "log_level.keyword": "ERROR"
                                }
                            }
                        }
                    }
                }
            },
            "size": 100,
            "sort": [{"@timestamp": "asc"}]
        }
        
        result = self.es.search(index="application-logs-*", body=query)
        
        return {
            'total_logs': result['hits']['total']['value'],
            'log_levels': result['aggregations']['log_levels']['buckets'],
            'affected_services': result['aggregations']['services']['buckets'],
            'top_errors': result['aggregations']['error_messages']['top_errors']['buckets'],
            'error_timeline': result['aggregations']['timeline']['buckets'],
            'sample_logs': [hit['_source'] for hit in result['hits']['hits']]
        }
    
    def _analyze_metrics_around_incident(self, start_time: datetime, 
                                       end_time: datetime) -> Dict[str, Any]:
        """인시던트 주변 메트릭 분석"""
        start_timestamp = int(start_time.timestamp())
        end_timestamp = int(end_time.timestamp())
        
        metric_queries = {
            'response_time': 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[1m]))',
            'error_rate': 'rate(http_requests_total{status=~"5.."}[1m]) / rate(http_requests_total[1m])',
            'request_rate': 'rate(http_requests_total[1m])',
            'cpu_usage': 'avg(rate(container_cpu_usage_seconds_total[1m])) by (pod)',
            'memory_usage': 'avg(container_memory_usage_bytes) by (pod)',
            'disk_io': 'rate(container_fs_reads_total[1m]) + rate(container_fs_writes_total[1m])',
            'network_errors': 'rate(container_network_receive_errors_total[1m])'
        }
        
        metrics_data = {}
        anomalies = []
        
        for metric_name, query in metric_queries.items():
            try:
                result = self.prometheus.query_range(
                    query=query,
                    start=start_timestamp,
                    end=end_timestamp,
                    step=60
                )
                
                metrics_data[metric_name] = result
                
                # 간단한 이상 감지
                if result['data']['result']:
                    values = [float(v[1]) for series in result['data']['result'] 
                            for v in series['values'] if v[1] != 'NaN']
                    
                    if values:
                        avg_value = sum(values) / len(values)
                        max_value = max(values)
                        
                        # 임계값 기반 이상 감지
                        if metric_name == 'error_rate' and max_value > 0.05:
                            anomalies.append({
                                'metric': metric_name,
                                'value': max_value,
                                'threshold': 0.05,
                                'type': 'threshold_exceeded'
                            })
                        elif metric_name == 'response_time' and max_value > 2.0:
                            anomalies.append({
                                'metric': metric_name,
                                'value': max_value,
                                'threshold': 2.0,
                                'type': 'threshold_exceeded'
                            })
                            
            except Exception as e:
                print(f"메트릭 조회 실패 {metric_name}: {e}")
        
        return {
            'metrics_data': metrics_data,
            'detected_anomalies': anomalies
        }
    
    def _analyze_traces_around_incident(self, start_time: datetime, 
                                      end_time: datetime) -> Dict[str, Any]:
        """인시던트 주변 트레이스 분석"""
        # Jaeger API를 통한 트레이스 조회
        start_micros = int(start_time.timestamp() * 1000000)
        end_micros = int(end_time.timestamp() * 1000000)
        
        try:
            # 에러가 포함된 트레이스 찾기
            traces_response = requests.get(
                f"{self.jaeger.base_url}/api/traces",
                params={
                    'start': start_micros,
                    'end': end_micros,
                    'limit': 100,
                    'tags': 'error:true'
                }
            )
            
            if traces_response.status_code == 200:
                traces_data = traces_response.json()
                
                error_traces = []
                slow_traces = []
                
                for trace in traces_data.get('data', []):
                    trace_duration = trace.get('duration', 0) / 1000  # ms로 변환
                    
                    # 에러 트레이스 분석
                    has_error = any(
                        span.get('tags', {}).get('error') == 'true' 
                        for span in trace.get('spans', [])
                    )
                    
                    if has_error:
                        error_traces.append({
                            'trace_id': trace['traceID'],
                            'duration_ms': trace_duration,
                            'service_count': len(set(
                                span.get('process', {}).get('serviceName') 
                                for span in trace.get('spans', [])
                            )),
                            'error_spans': [
                                span for span in trace.get('spans', [])
                                if span.get('tags', {}).get('error') == 'true'
                            ]
                        })
                    
                    # 느린 트레이스 (2초 이상)
                    if trace_duration > 2000:
                        slow_traces.append({
                            'trace_id': trace['traceID'],
                            'duration_ms': trace_duration,
                            'operation': trace.get('spans', [{}])[0].get('operationName', 'unknown')
                        })
                
                return {
                    'total_traces': len(traces_data.get('data', [])),
                    'error_traces': error_traces,
                    'slow_traces': slow_traces,
                    'trace_duration_stats': self._calculate_trace_stats(traces_data.get('data', []))
                }
                
        except Exception as e:
            print(f"트레이스 분석 실패: {e}")
            
        return {'error': 'Failed to analyze traces'}
    
    def _find_correlations(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """로그-메트릭-트레이스 간 상관관계 찾기"""
        correlations = {
            'log_metric_correlations': [],
            'log_trace_correlations': [],
            'metric_trace_correlations': [],
            'causal_chains': []
        }
        
        logs = analysis_result['logs_analysis']
        metrics = analysis_result['metrics_analysis']
        traces = analysis_result['traces_analysis']
        
        # 로그-메트릭 상관관계
        if logs['total_logs'] > 0 and metrics['detected_anomalies']:
            error_services = [
                bucket['key'] for bucket in logs['affected_services']
                if bucket['error_count']['doc_count'] > 0
            ]
            
            for anomaly in metrics['detected_anomalies']:
                correlations['log_metric_correlations'].append({
                    'log_pattern': f"Errors in services: {error_services}",
                    'metric_anomaly': anomaly,
                    'correlation_strength': 'high' if len(error_services) > 1 else 'medium'
                })
        
        # 로그-트레이스 상관관계
        if isinstance(traces, dict) and 'error_traces' in traces:
            error_trace_services = set()
            for trace in traces['error_traces']:
                for span in trace.get('error_spans', []):
                    service_name = span.get('process', {}).get('serviceName')
                    if service_name:
                        error_trace_services.add(service_name)
            
            log_error_services = set(
                bucket['key'] for bucket in logs['affected_services']
                if bucket['error_count']['doc_count'] > 0
            )
            
            common_services = error_trace_services.intersection(log_error_services)
            if common_services:
                correlations['log_trace_correlations'].append({
                    'common_services': list(common_services),
                    'correlation_type': 'service_overlap',
                    'confidence': len(common_services) / max(len(error_trace_services), len(log_error_services))
                })
        
        return correlations
    
    def _build_incident_timeline(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """인시던트 타임라인 구성"""
        timeline = []
        
        # 로그 이벤트 추가
        for log in analysis_result['logs_analysis']['sample_logs']:
            if log.get('log_level') == 'ERROR':
                timeline.append({
                    'timestamp': log['@timestamp'],
                    'type': 'log_error',
                    'service': log.get('service_name', 'unknown'),
                    'message': log.get('message', '')[:100] + '...',
                    'priority': 'high'
                })
        
        # 메트릭 이상 추가
        for anomaly in analysis_result['metrics_analysis']['detected_anomalies']:
            timeline.append({
                'timestamp': analysis_result['incident_time'],
                'type': 'metric_anomaly',
                'metric': anomaly['metric'],
                'value': anomaly['value'],
                'threshold': anomaly['threshold'],
                'priority': 'high'
            })
        
        # 시간순 정렬
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline

    def generate_correlation_report(self, incident_time: datetime) -> Dict[str, Any]:
        """상관관계 분석 보고서 생성"""
        analysis = self.analyze_incident_correlation(incident_time)
        
        report = {
            'executive_summary': self._generate_executive_summary(analysis),
            'detailed_analysis': analysis,
            'root_cause_candidates': self._identify_root_causes(analysis),
            'recommendations': self._generate_recommendations(analysis),
            'follow_up_actions': self._suggest_follow_up_actions(analysis)
        }
        
        return report
    
    def _generate_executive_summary(self, analysis: Dict[str, Any]) -> str:
        """경영진 요약 생성"""
        logs = analysis['logs_analysis']
        metrics = analysis['metrics_analysis']
        traces = analysis['traces_analysis']
        
        summary_parts = []
        
        if logs['total_logs'] > 1000:
            summary_parts.append(f"High log volume detected ({logs['total_logs']} logs)")
        
        error_count = sum(
            bucket['error_count']['doc_count'] 
            for bucket in logs['affected_services']
        )
        if error_count > 0:
            summary_parts.append(f"{error_count} error events across {len(logs['affected_services'])} services")
        
        if len(metrics['detected_anomalies']) > 0:
            summary_parts.append(f"{len(metrics['detected_anomalies'])} metric anomalies detected")
        
        if isinstance(traces, dict) and traces.get('error_traces'):
            summary_parts.append(f"{len(traces['error_traces'])} failed distributed traces")
        
        return ". ".join(summary_parts) + "."
```

### 2.2 로그 패턴에서의 이상 감지

**로그 이상 감지 시스템**
```python
# log_anomaly_detection.py
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
import pandas as pd
from collections import defaultdict, Counter
import json

class LogAnomalyDetector:
    def __init__(self):
        self.pattern_templates = {}
        self.baseline_patterns = {}
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.clustering_model = DBSCAN(eps=0.3, min_samples=5)
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        
    def learn_normal_patterns(self, logs: List[Dict], window_hours: int = 24):
        """정상 로그 패턴 학습"""
        # 로그 메시지 정규화
        normalized_logs = []
        for log in logs:
            normalized = self._normalize_log_message(log.get('message', ''))
            normalized_logs.append(normalized)
        
        # 패턴 템플릿 생성
        self.pattern_templates = self._extract_log_templates(normalized_logs)
        
        # 기준선 패턴 빈도 계산
        template_counts = Counter(
            self._match_template(log) for log in normalized_logs
        )
        
        total_logs = len(normalized_logs)
        self.baseline_patterns = {
            template: count / total_logs 
            for template, count in template_counts.items()
        }
        
        # TF-IDF 벡터화 학습
        self.vectorizer.fit(normalized_logs)
        
        # 정상 로그의 특성 벡터로 Isolation Forest 훈련
        log_vectors = self.vectorizer.transform(normalized_logs)
        self.isolation_forest.fit(log_vectors.toarray())
        
        print(f"학습 완료: {len(self.pattern_templates)} 패턴 템플릿, {total_logs} 로그")
    
    def detect_anomalies(self, logs: List[Dict]) -> List[Dict]:
        """로그 이상 감지"""
        anomalies = []
        
        for i, log in enumerate(logs):
            message = log.get('message', '')
            normalized = self._normalize_log_message(message)
            
            # 1. 새로운 패턴 감지
            template = self._match_template(normalized)
            if template not in self.baseline_patterns:
                anomalies.append({
                    'type': 'new_pattern',
                    'log_index': i,
                    'log': log,
                    'reason': f'New log pattern: {template}',
                    'severity': 'medium',
                    'confidence': 0.8
                })
            
            # 2. 빈도 이상 감지
            elif self.baseline_patterns[template] < 0.001:  # 매우 드문 패턴
                anomalies.append({
                    'type': 'rare_pattern',
                    'log_index': i,
                    'log': log,
                    'reason': f'Rare pattern frequency: {self.baseline_patterns[template]:.6f}',
                    'severity': 'low',
                    'confidence': 0.6
                })
            
            # 3. 머신러닝 기반 이상 감지
            log_vector = self.vectorizer.transform([normalized])
            anomaly_score = self.isolation_forest.decision_function(log_vector.toarray())[0]
            
            if anomaly_score < -0.5:  # 임계값
                anomalies.append({
                    'type': 'ml_anomaly',
                    'log_index': i,
                    'log': log,
                    'reason': f'ML anomaly score: {anomaly_score:.3f}',
                    'severity': 'high' if anomaly_score < -0.7 else 'medium',
                    'confidence': abs(anomaly_score)
                })
            
            # 4. 특정 패턴 기반 이상 감지
            specific_anomalies = self._detect_specific_anomalies(log)
            anomalies.extend(specific_anomalies)
        
        return anomalies
    
    def _normalize_log_message(self, message: str) -> str:
        """로그 메시지 정규화"""
        # 타임스탬프 제거
        message = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', '<TIMESTAMP>', message)
        message = re.sub(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '<TIMESTAMP>', message)
        
        # IP 주소 정규화
        message = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP>', message)
        
        # 숫자 정규화
        message = re.sub(r'\b\d+\b', '<NUM>', message)
        
        # UUID/해시 정규화
        message = re.sub(r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', '<UUID>', message)
        message = re.sub(r'\b[a-f0-9]{32,}\b', '<HASH>', message)
        
        # 파일 경로 정규화
        message = re.sub(r'/[^\s]+', '<PATH>', message)
        
        # 소문자 변환 및 공백 정리
        message = message.lower().strip()
        message = re.sub(r'\s+', ' ', message)
        
        return message
    
    def _extract_log_templates(self, normalized_logs: List[str]) -> Dict[str, str]:
        """로그 템플릿 추출"""
        # 간단한 클러스터링으로 유사한 로그 그룹화
        if not normalized_logs:
            return {}
            
        vectors = self.vectorizer.fit_transform(normalized_logs)
        clusters = self.clustering_model.fit_predict(vectors)
        
        templates = {}
        for cluster_id in set(clusters):
            if cluster_id == -1:  # 노이즈 클러스터 제외
                continue
                
            cluster_logs = [
                normalized_logs[i] for i, c in enumerate(clusters) if c == cluster_id
            ]
            
            # 클러스터 내 가장 일반적인 패턴을 템플릿으로 사용
            template = self._generate_template_from_cluster(cluster_logs)
            templates[template] = cluster_id
        
        return templates
    
    def _generate_template_from_cluster(self, cluster_logs: List[str]) -> str:
        """클러스터에서 템플릿 생성"""
        if not cluster_logs:
            return ""
        
        # 가장 빈번한 로그를 기본 템플릿으로 사용
        log_counter = Counter(cluster_logs)
        most_common_log = log_counter.most_common(1)[0][0]
        
        return most_common_log
    
    def _match_template(self, normalized_log: str) -> str:
        """로그를 가장 유사한 템플릿과 매칭"""
        if not self.pattern_templates:
            return "unknown_template"
        
        # 간단한 유사도 매칭 (실제로는 더 정교한 알고리즘 필요)
        best_match = "unknown_template"
        best_score = 0
        
        for template in self.pattern_templates.keys():
            # 단어 기반 유사도 계산
            log_words = set(normalized_log.split())
            template_words = set(template.split())
            
            if len(template_words) == 0:
                continue
                
            intersection = len(log_words.intersection(template_words))
            union = len(log_words.union(template_words))
            
            jaccard_similarity = intersection / union if union > 0 else 0
            
            if jaccard_similarity > best_score:
                best_score = jaccard_similarity
                best_match = template
        
        # 최소 유사도 임계값
        if best_score < 0.3:
            return "unknown_template"
        
        return best_match
    
    def _detect_specific_anomalies(self, log: Dict) -> List[Dict]:
        """특정 패턴 기반 이상 감지"""
        anomalies = []
        message = log.get('message', '')
        
        # SQL 인젝션 패턴
        sql_injection_patterns = [
            r"(?i)(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into)",
            r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
            r"(?i)(\bxp_cmdshell\b|\bsp_executesql\b)"
        ]
        
        for pattern in sql_injection_patterns:
            if re.search(pattern, message):
                anomalies.append({
                    'type': 'security_threat',
                    'subtype': 'sql_injection',
                    'log': log,
                    'reason': f'Potential SQL injection pattern detected: {pattern}',
                    'severity': 'critical',
                    'confidence': 0.9
                })
        
        # 비정상적인 응답 시간
        response_time_match = re.search(r'response_time[=:](\d+)', message)
        if response_time_match:
            response_time = int(response_time_match.group(1))
            if response_time > 10000:  # 10초 이상
                anomalies.append({
                    'type': 'performance_anomaly',
                    'subtype': 'high_response_time',
                    'log': log,
                    'reason': f'Extremely high response time: {response_time}ms',
                    'severity': 'high',
                    'confidence': 0.8
                })
        
        # 메모리 부족 패턴
        oom_patterns = [
            r"(?i)(out of memory|outofmemoryerror|memory allocation failed)",
            r"(?i)(heap space|gc overhead limit exceeded)"
        ]
        
        for pattern in oom_patterns:
            if re.search(pattern, message):
                anomalies.append({
                    'type': 'resource_exhaustion',
                    'subtype': 'memory_exhaustion',
                    'log': log,
                    'reason': f'Memory exhaustion pattern detected',
                    'severity': 'high',
                    'confidence': 0.85
                })
        
        # 인증 실패 패턴
        auth_failure_patterns = [
            r"(?i)(authentication failed|login failed|invalid credentials)",
            r"(?i)(unauthorized access|access denied|permission denied)"
        ]
        
        for pattern in auth_failure_patterns:
            if re.search(pattern, message):
                anomalies.append({
                    'type': 'security_event',
                    'subtype': 'authentication_failure',
                    'log': log,
                    'reason': f'Authentication failure detected',
                    'severity': 'medium',
                    'confidence': 0.7
                })
        
        return anomalies
    
    def analyze_log_trends(self, logs: List[Dict], time_window: str = '1h') -> Dict[str, Any]:
        """로그 트렌드 분석"""
        # 시간별 로그 볼륨
        time_buckets = defaultdict(int)
        error_buckets = defaultdict(int)
        service_buckets = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            timestamp = log.get('@timestamp', '')
            log_level = log.get('log_level', 'INFO')
            service = log.get('service_name', 'unknown')
            
            # 시간 버킷 계산 (간단히 시간별로 그룹화)
            if timestamp:
                hour_bucket = timestamp[:13]  # YYYY-MM-DDTHH 형태
                time_buckets[hour_bucket] += 1
                
                if log_level == 'ERROR':
                    error_buckets[hour_bucket] += 1
                
                service_buckets[hour_bucket][service] += 1
        
        # 트렌드 분석
        trend_analysis = {
            'volume_trend': self._calculate_trend(list(time_buckets.values())),
            'error_trend': self._calculate_trend(list(error_buckets.values())),
            'peak_hours': sorted(time_buckets.items(), key=lambda x: x[1], reverse=True)[:5],
            'service_distribution': dict(service_buckets),
            'anomalous_periods': []
        }
        
        # 이상 기간 탐지
        if len(time_buckets) > 1:
            values = list(time_buckets.values())
            mean_volume = np.mean(values)
            std_volume = np.std(values)
            
            for hour, volume in time_buckets.items():
                if volume > mean_volume + 2 * std_volume:
                    trend_analysis['anomalous_periods'].append({
                        'time': hour,
                        'volume': volume,
                        'deviation': (volume - mean_volume) / std_volume,
                        'type': 'volume_spike'
                    })
        
        return trend_analysis
    
    def _calculate_trend(self, values: List[int]) -> str:
        """트렌드 계산"""
        if len(values) < 2:
            return 'insufficient_data'
        
        # 선형 회귀로 트렌드 방향 계산
        x = np.arange(len(values))
        slope = np.polyfit(x, values, 1)[0]
        
        if slope > 0.1:
            return 'increasing'
        elif slope < -0.1:
            return 'decreasing'
        else:
            return 'stable'
```

### 2.3 보안 이벤트 모니터링

**보안 로그 분석 시스템**
```python
# security_log_analyzer.py
import re
import json
import ipaddress
from typing import Dict, List, Set, Any
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import geoip2.database

class SecurityLogAnalyzer:
    def __init__(self, geoip_db_path: str = None):
        self.threat_patterns = self._load_threat_patterns()
        self.ip_reputation_cache = {}
        self.failed_attempts_tracker = defaultdict(list)
        self.geoip_reader = None
        
        if geoip_db_path:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as e:
                print(f"GeoIP database loading failed: {e}")
    
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """보안 위협 패턴 로드"""
        return {
            'sql_injection': [
                r"(?i)(union\s+select|select\s+.*\s+from|drop\s+table)",
                r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
                r"(?i)(\'\s*or\s*\'\s*=\s*\'|\'\s*;\s*drop\s+table)",
                r"(?i)(xp_cmdshell|sp_executesql|exec\s*\()"
            ],
            'xss': [
                r"(?i)(<script[^>]*>|</script>|javascript:|vbscript:)",
                r"(?i)(onload\s*=|onclick\s*=|onerror\s*=)",
                r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()"
            ],
            'path_traversal': [
                r"(\.\.[\\/]){2,}",
                r"(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f)",
                r"(?i)(\.\./\.\./\.\./|\.\.\\\.\.\\\.\.\\)"
            ],
            'command_injection': [
                r"(?i)(;\s*(rm|del|format|shutdown)|`.*`|\$\(.*\))",
                r"(?i)(\|\s*(cat|type|more|less)\s+)",
                r"(?i)(&&\s*(rm|del|format)|;\s*shutdown)"
            ],
            'brute_force': [
                r"(?i)(failed login|authentication failed|invalid password)",
                r"(?i)(login attempt|bad password|access denied)",
                r"(?i)(too many login attempts|account locked)"
            ],
            'privilege_escalation': [
                r"(?i)(sudo|su -|runas|privilege|elevated)",
                r"(?i)(admin|administrator|root|system)",
                r"(?i)(escalation|elevation|bypass)"
            ]
        }
    
    def analyze_security_events(self, logs: List[Dict], 
                              time_window: int = 3600) -> Dict[str, Any]:
        """보안 이벤트 분석"""
        security_events = {
            'threats_detected': [],
            'attack_patterns': defaultdict(int),
            'suspicious_ips': set(),
            'geographic_analysis': {},
            'timeline': [],
            'risk_score': 0
        }
        
        for log in logs:
            message = log.get('message', '')
            timestamp = log.get('@timestamp', '')
            source_ip = log.get('client_ip') or log.get('source_ip') or self._extract_ip_from_message(message)
            
            # 위협 패턴 매칭
            for threat_type, patterns in self.threat_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, message):
                        threat_event = {
                            'type': threat_type,
                            'timestamp': timestamp,
                            'source_ip': source_ip,
                            'log_message': message,
                            'pattern_matched': pattern,
                            'severity': self._calculate_threat_severity(threat_type),
                            'log_source': log
                        }
                        
                        security_events['threats_detected'].append(threat_event)
                        security_events['attack_patterns'][threat_type] += 1
                        
                        if source_ip:
                            security_events['suspicious_ips'].add(source_ip)
                        
                        break  # 첫 번째 매칭에서 중단
            
            # 특별한 보안 이벤트 분석
            self._analyze_authentication_events(log, security_events)
            self._analyze_privilege_events(log, security_events)
            self._analyze_network_events(log, security_events)
        
        # 지리적 분석
        if security_events['suspicious_ips'] and self.geoip_reader:
            security_events['geographic_analysis'] = self._analyze_geographic_patterns(
                security_events['suspicious_ips']
            )
        
        # 브루트포스 공격 감지
        security_events['brute_force_attacks'] = self._detect_brute_force_attacks(logs, time_window)
        
        # 위험 점수 계산
        security_events['risk_score'] = self._calculate_risk_score(security_events)
        
        # 타임라인 생성
        security_events['timeline'] = sorted(
            security_events['threats_detected'],
            key=lambda x: x['timestamp']
        )
        
        return security_events
    
    def _extract_ip_from_message(self, message: str) -> str:
        """로그 메시지에서 IP 주소 추출"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, message)
        
        for match in matches:
            try:
                # 유효한 IP 주소인지 확인
                ipaddress.ip_address(match)
                # 사설 IP가 아닌 경우만 반환
                if not ipaddress.ip_address(match).is_private:
                    return match
            except ValueError:
                continue
        
        return None
    
    def _calculate_threat_severity(self, threat_type: str) -> str:
        """위협 유형별 심각도 계산"""
        severity_map = {
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'xss': 'high',
            'path_traversal': 'high',
            'brute_force': 'medium',
            'privilege_escalation': 'critical'
        }
        return severity_map.get(threat_type, 'low')
    
    def _analyze_authentication_events(self, log: Dict, security_events: Dict):
        """인증 이벤트 분석"""
        message = log.get('message', '').lower()
        source_ip = log.get('client_ip') or log.get('source_ip')
        timestamp = log.get('@timestamp', '')
        
        # 로그인 실패 추적
        if any(phrase in message for phrase in ['failed login', 'authentication failed', 'invalid password']):
            if source_ip:
                self.failed_attempts_tracker[source_ip].append({
                    'timestamp': timestamp,
                    'message': message
                })
        
        # 의심스러운 로그인 패턴
        suspicious_patterns = [
            'login from unusual location',
            'multiple failed attempts',
            'account locked',
            'suspicious user agent'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in message:
                security_events['threats_detected'].append({
                    'type': 'suspicious_authentication',
                    'subtype': pattern.replace(' ', '_'),
                    'timestamp': timestamp,
                    'source_ip': source_ip,
                    'log_message': message,
                    'severity': 'medium',
                    'log_source': log
                })
    
    def _analyze_privilege_events(self, log: Dict, security_events: Dict):
        """권한 상승 이벤트 분석"""
        message = log.get('message', '').lower()
        
        privilege_indicators = [
            'sudo',
            'su -',
            'admin access',
            'privilege escalation',
            'elevated permissions'
        ]
        
        for indicator in privilege_indicators:
            if indicator in message:
                security_events['threats_detected'].append({
                    'type': 'privilege_escalation_attempt',
                    'timestamp': log.get('@timestamp', ''),
                    'source_ip': log.get('client_ip') or log.get('source_ip'),
                    'log_message': message,
                    'indicator': indicator,
                    'severity': 'high',
                    'log_source': log
                })
    
    def _analyze_network_events(self, log: Dict, security_events: Dict):
        """네트워크 보안 이벤트 분석"""
        message = log.get('message', '').lower()
        
        # 포트 스캔 감지
        if 'port scan' in message or 'connection attempt' in message:
            security_events['threats_detected'].append({
                'type': 'network_reconnaissance',
                'subtype': 'port_scan',
                'timestamp': log.get('@timestamp', ''),
                'source_ip': log.get('client_ip') or log.get('source_ip'),
                'log_message': message,
                'severity': 'medium',
                'log_source': log
            })
        
        # DDoS 패턴
        if any(phrase in message for phrase in ['ddos', 'dos attack', 'flood']):
            security_events['threats_detected'].append({
                'type': 'denial_of_service',
                'timestamp': log.get('@timestamp', ''),
                'source_ip': log.get('client_ip') or log.get('source_ip'),
                'log_message': message,
                'severity': 'critical',
                'log_source': log
            })
    
    def _analyze_geographic_patterns(self, suspicious_ips: Set[str]) -> Dict[str, Any]:
        """지리적 패턴 분석"""
        country_counts = Counter()
        city_counts = Counter()
        suspicious_locations = []
        
        for ip in suspicious_ips:
            try:
                response = self.geoip_reader.city(ip)
                country = response.country.name
                city = response.city.name
                
                country_counts[country] += 1
                if city:
                    city_counts[city] += 1
                
                # 의심스러운 지역 (예: 일반적이지 않은 국가)
                high_risk_countries = ['Unknown', 'Tor Exit Node']  # 실제로는 더 포괄적인 리스트
                if country in high_risk_countries:
                    suspicious_locations.append({
                        'ip': ip,
                        'country': country,
                        'city': city,
                        'risk_level': 'high'
                    })
                    
            except Exception as e:
                print(f"GeoIP lookup failed for {ip}: {e}")
        
        return {
            'country_distribution': dict(country_counts),
            'city_distribution': dict(city_counts),
            'suspicious_locations': suspicious_locations,
            'geographic_diversity': len(country_counts)
        }
    
    def _detect_brute_force_attacks(self, logs: List[Dict], 
                                  time_window: int) -> List[Dict]:
        """브루트포스 공격 감지"""
        brute_force_attacks = []
        ip_attempts = defaultdict(list)
        
        # IP별 로그인 실패 시도 수집
        for log in logs:
            message = log.get('message', '').lower()
            if any(phrase in message for phrase in ['failed login', 'authentication failed']):
                source_ip = log.get('client_ip') or log.get('source_ip')
                if source_ip:
                    ip_attempts[source_ip].append({
                        'timestamp': log.get('@timestamp', ''),
                        'user': self._extract_username_from_log(log),
                        'log': log
                    })
        
        # 브루트포스 공격 감지
        for ip, attempts in ip_attempts.items():
            if len(attempts) >= 5:  # 5회 이상 실패
                # 시간 집중도 계산
                timestamps = [
                    datetime.fromisoformat(attempt['timestamp'].replace('Z', '+00:00'))
                    for attempt in attempts
                    if attempt['timestamp']
                ]
                
                if len(timestamps) >= 2:
                    time_span = (max(timestamps) - min(timestamps)).total_seconds()
                    if time_span <= time_window:  # 지정된 시간 내
                        brute_force_attacks.append({
                            'source_ip': ip,
                            'attempt_count': len(attempts),
                            'time_span_seconds': time_span,
                            'users_targeted': list(set(
                                attempt['user'] for attempt in attempts
                                if attempt['user']
                            )),
                            'first_attempt': min(timestamps).isoformat(),
                            'last_attempt': max(timestamps).isoformat(),
                            'severity': 'critical' if len(attempts) > 20 else 'high'
                        })
        
        return brute_force_attacks
    
    def _extract_username_from_log(self, log: Dict) -> str:
        """로그에서 사용자명 추출"""
        message = log.get('message', '')
        
        # 일반적인 사용자명 패턴
        patterns = [
            r'user[:\s]+([a-zA-Z0-9_]+)',
            r'username[:\s]+([a-zA-Z0-9_]+)',
            r'login[:\s]+([a-zA-Z0-9_]+)',
            r'account[:\s]+([a-zA-Z0-9_]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _calculate_risk_score(self, security_events: Dict) -> int:
        """종합 위험 점수 계산"""
        score = 0
        
        # 위협 유형별 점수
        threat_scores = {
            'sql_injection': 20,
            'command_injection': 20,
            'xss': 15,
            'path_traversal': 15,
            'brute_force': 10,
            'privilege_escalation': 25
        }
        
        for threat_type, count in security_events['attack_patterns'].items():
            score += threat_scores.get(threat_type, 5) * count
        
        # 브루트포스 공격 점수
        for attack in security_events.get('brute_force_attacks', []):
            if attack['severity'] == 'critical':
                score += 30
            else:
                score += 15
        
        # 지리적 다양성 점수 (의심스러운 지역에서의 접근)
        geo_analysis = security_events.get('geographic_analysis', {})
        if geo_analysis.get('geographic_diversity', 0) > 10:
            score += 10
        
        suspicious_locations = geo_analysis.get('suspicious_locations', [])
        score += len(suspicious_locations) * 5
        
        return min(score, 100)  # 최대 100점
    
    def generate_security_report(self, logs: List[Dict]) -> Dict[str, Any]:
        """보안 분석 보고서 생성"""
        analysis = self.analyze_security_events(logs)
        
        report = {
            'summary': {
                'total_threats': len(analysis['threats_detected']),
                'unique_attackers': len(analysis['suspicious_ips']),
                'risk_score': analysis['risk_score'],
                'most_common_attack': max(analysis['attack_patterns'].items(), key=lambda x: x[1])[0] if analysis['attack_patterns'] else None
            },
            'threat_breakdown': dict(analysis['attack_patterns']),
            'top_threats': sorted(
                analysis['threats_detected'],
                key=lambda x: x['severity'],
                reverse=True
            )[:10],
            'geographic_analysis': analysis['geographic_analysis'],
            'brute_force_attacks': analysis['brute_force_attacks'],
            'recommendations': self._generate_security_recommendations(analysis),
            'immediate_actions': self._generate_immediate_actions(analysis)
        }
        
        return report
    
    def _generate_security_recommendations(self, analysis: Dict) -> List[str]:
        """보안 권장사항 생성"""
        recommendations = []
        
        if analysis['attack_patterns'].get('brute_force', 0) > 5:
            recommendations.append("계정 잠금 정책 강화 및 다단계 인증 도입")
        
        if analysis['attack_patterns'].get('sql_injection', 0) > 0:
            recommendations.append("웹 애플리케이션 방화벽(WAF) 구축 및 SQL 쿼리 매개변수화")
        
        if len(analysis['suspicious_ips']) > 10:
            recommendations.append("IP 기반 접근 제어 및 지역별 차단 정책 수립")
        
        if analysis['risk_score'] > 50:
            recommendations.append("보안 모니터링 강화 및 실시간 알림 시스템 구축")
        
        return recommendations
    
    def _generate_immediate_actions(self, analysis: Dict) -> List[str]:
        """즉시 조치사항 생성"""
        actions = []
        
        critical_threats = [
            threat for threat in analysis['threats_detected']
            if threat['severity'] == 'critical'
        ]
        
        if critical_threats:
            actions.append(f"{len(critical_threats)}개의 심각한 보안 위협에 대한 즉시 대응 필요")
        
        if analysis['brute_force_attacks']:
            attacking_ips = [attack['source_ip'] for attack in analysis['brute_force_attacks']]
            actions.append(f"브루트포스 공격 IP 차단: {', '.join(attacking_ips)}")
        
        if analysis['risk_score'] > 80:
            actions.append("높은 위험 점수로 인한 보안팀 긴급 대응 필요")
        
        return actions
```

## 3. 실습 과제

### 과제 1: ELK 스택 구축
1. Elasticsearch 클러스터 배포 및 인덱스 라이프사이클 설정
2. Logstash 고급 파이프라인 구성
3. Kibana 대시보드 및 시각화 구축

### 과제 2: 로그 이상 감지 시스템
1. 머신러닝 기반 로그 패턴 학습
2. 실시간 로그 이상 감지 구현
3. 자동화된 이상 알림 시스템

### 과제 3: 보안 로그 분석
1. 보안 위협 패턴 탐지 시스템
2. 브루트포스 공격 자동 감지
3. 지리적 이상 접근 분석

## 4. 성능 최적화

### Elasticsearch 최적화
```json
{
  "index": {
    "number_of_shards": 3,
    "number_of_replicas": 1,
    "refresh_interval": "30s",
    "translog.durability": "async",
    "codec": "best_compression"
  }
}
```

### Logstash 성능 튜닝
```yaml
pipeline.workers: 4
pipeline.batch.size: 1000
pipeline.batch.delay: 50
queue.type: persisted
queue.max_bytes: 1gb
```

## 5. 다음 단계
- 보안 모니터링 및 컴플라이언스 (Phase 4-3)
- 멀티 테넌시 및 거버넌스 (Phase 5-1)