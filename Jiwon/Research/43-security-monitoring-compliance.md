# 보안 모니터링 및 컴플라이언스 (Phase 4-3)

## 개요
보안 이벤트 감지, 침해 지표(IOC) 모니터링, SIEM 통합, 컴플라이언스 자동화를 통한 종합적인 보안 모니터링 시스템 구축 방법을 학습합니다.

## 1. 보안 이벤트 감지

### 1.1 실시간 보안 이벤트 모니터링

**보안 이벤트 탐지 엔진**
```python
# security_event_detector.py
import json
import time
import hashlib
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re
from datetime import datetime, timedelta
import threading
import queue

class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    threat_level: ThreatLevel
    source_ip: Optional[str]
    target_ip: Optional[str]
    user_agent: Optional[str]
    payload: str
    indicators: List[str]
    confidence_score: float
    raw_log: Dict[str, Any]

class SecurityEventDetector:
    def __init__(self, config_path: str = None):
        self.detection_rules = self._load_detection_rules(config_path)
        self.ioc_database = {}
        self.event_queue = queue.Queue(maxsize=10000)
        self.active_sessions = {}
        self.threat_intelligence = {}
        self.running = False
        
    def _load_detection_rules(self, config_path: str) -> Dict[str, Any]:
        """보안 탐지 규칙 로드"""
        default_rules = {
            "web_attacks": {
                "sql_injection": {
                    "patterns": [
                        r"(?i)(union\s+select|select\s+.*\s+from|drop\s+table)",
                        r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
                        r"(?i)(\'\s*or\s*\'\s*=\s*\'|\'\s*;\s*drop\s+table)",
                        r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)"
                    ],
                    "threat_level": "CRITICAL",
                    "confidence_boost": 0.9
                },
                "xss": {
                    "patterns": [
                        r"(?i)(<script[^>]*>.*?</script>|javascript:|vbscript:)",
                        r"(?i)(onload\s*=|onclick\s*=|onerror\s*=|onmouseover\s*=)",
                        r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\(|eval\s*\()"
                    ],
                    "threat_level": "HIGH",
                    "confidence_boost": 0.8
                },
                "lfi_rfi": {
                    "patterns": [
                        r"(\.\.[\\/]){2,}",
                        r"(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)",
                        r"(?i)(php://|file://|data://|expect://)"
                    ],
                    "threat_level": "HIGH",
                    "confidence_boost": 0.8
                },
                "command_injection": {
                    "patterns": [
                        r"(?i)(;\s*(rm|del|format|shutdown)|`.*`|\$\(.*\))",
                        r"(?i)(\|\s*(cat|type|more|less|head|tail)\s+)",
                        r"(?i)(&&\s*(rm|del|format|net\s+user)|;\s*shutdown)"
                    ],
                    "threat_level": "CRITICAL",
                    "confidence_boost": 0.9
                }
            },
            "network_attacks": {
                "port_scan": {
                    "patterns": [
                        r"(?i)(port\s+scan|nmap|masscan|zmap)",
                        r"(?i)(connection\s+refused.*multiple|connection\s+timeout.*multiple)"
                    ],
                    "threat_level": "MEDIUM",
                    "confidence_boost": 0.7
                },
                "brute_force": {
                    "patterns": [
                        r"(?i)(failed\s+login|authentication\s+failed|invalid\s+password)",
                        r"(?i)(multiple\s+login\s+attempts|too\s+many\s+attempts)"
                    ],
                    "threat_level": "HIGH",
                    "confidence_boost": 0.8
                }
            },
            "malware_indicators": {
                "suspicious_processes": {
                    "patterns": [
                        r"(?i)(powershell.*-enc|powershell.*-e\s+[A-Za-z0-9+/=]+)",
                        r"(?i)(cmd\.exe.*echo|cmd\.exe.*copy.*system32)",
                        r"(?i)(certutil.*-decode|bitsadmin.*transfer)"
                    ],
                    "threat_level": "CRITICAL",
                    "confidence_boost": 0.9
                },
                "persistence_mechanisms": {
                    "patterns": [
                        r"(?i)(schtasks.*create|at\s+\d+:|reg\s+add.*run)",
                        r"(?i)(startup\s+folder|autorun|winlogon)"
                    ],
                    "threat_level": "HIGH",
                    "confidence_boost": 0.8
                }
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    custom_rules = json.load(f)
                    # 커스텀 규칙과 기본 규칙 병합
                    return {**default_rules, **custom_rules}
            except Exception as e:
                print(f"Failed to load custom rules: {e}")
        
        return default_rules
    
    def start_monitoring(self):
        """보안 모니터링 시작"""
        self.running = True
        
        # 이벤트 처리 스레드 시작
        processing_thread = threading.Thread(target=self._process_events)
        processing_thread.daemon = True
        processing_thread.start()
        
        print("Security monitoring started")
    
    def stop_monitoring(self):
        """보안 모니터링 중지"""
        self.running = False
        print("Security monitoring stopped")
    
    def analyze_log_entry(self, log_entry: Dict[str, Any]) -> List[SecurityEvent]:
        """로그 엔트리 분석"""
        events = []
        
        message = log_entry.get('message', '')
        timestamp = datetime.fromisoformat(
            log_entry.get('@timestamp', datetime.now().isoformat()).replace('Z', '+00:00')
        )
        source_ip = log_entry.get('client_ip') or log_entry.get('source_ip')
        user_agent = log_entry.get('user_agent', '')
        
        # 각 탐지 규칙 적용
        for category, subcategories in self.detection_rules.items():
            for attack_type, rule_config in subcategories.items():
                patterns = rule_config.get('patterns', [])
                threat_level = ThreatLevel[rule_config.get('threat_level', 'LOW')]
                confidence_boost = rule_config.get('confidence_boost', 0.5)
                
                for pattern in patterns:
                    if re.search(pattern, message):
                        event = SecurityEvent(
                            event_id=self._generate_event_id(log_entry, attack_type),
                            timestamp=timestamp,
                            event_type=f"{category}.{attack_type}",
                            threat_level=threat_level,
                            source_ip=source_ip,
                            target_ip=log_entry.get('server_ip'),
                            user_agent=user_agent,
                            payload=message,
                            indicators=[pattern],
                            confidence_score=confidence_boost,
                            raw_log=log_entry
                        )
                        
                        events.append(event)
                        break  # 첫 번째 매칭에서 중단
        
        # 컨텍스트 기반 분석
        enhanced_events = self._enhance_with_context(events, log_entry)
        
        # 이벤트 큐에 추가
        for event in enhanced_events:
            try:
                self.event_queue.put_nowait(event)
            except queue.Full:
                print("Event queue is full, dropping events")
        
        return enhanced_events
    
    def _generate_event_id(self, log_entry: Dict, attack_type: str) -> str:
        """이벤트 ID 생성"""
        content = f"{log_entry.get('@timestamp', '')}{attack_type}{log_entry.get('message', '')}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def _enhance_with_context(self, events: List[SecurityEvent], 
                            log_entry: Dict[str, Any]) -> List[SecurityEvent]:
        """컨텍스트 정보로 이벤트 강화"""
        enhanced_events = []
        
        for event in events:
            # IP 평판 확인
            if event.source_ip:
                reputation_score = self._check_ip_reputation(event.source_ip)
                if reputation_score < 0.3:  # 낮은 평판
                    event.confidence_score = min(event.confidence_score + 0.2, 1.0)
                    event.indicators.append(f"low_reputation_ip:{reputation_score}")
            
            # 지리적 위치 분석
            geo_risk = self._assess_geographic_risk(event.source_ip)
            if geo_risk == "high":
                event.confidence_score = min(event.confidence_score + 0.1, 1.0)
                event.indicators.append("high_risk_geography")
            
            # 사용자 에이전트 분석
            if event.user_agent:
                ua_risk = self._analyze_user_agent(event.user_agent)
                if ua_risk > 0.7:
                    event.confidence_score = min(event.confidence_score + 0.1, 1.0)
                    event.indicators.append(f"suspicious_user_agent:{ua_risk}")
            
            # 시간 기반 분석
            time_risk = self._analyze_timing_patterns(event)
            if time_risk > 0.7:
                event.confidence_score = min(event.confidence_score + 0.1, 1.0)
                event.indicators.append("suspicious_timing")
            
            enhanced_events.append(event)
        
        return enhanced_events
    
    def _check_ip_reputation(self, ip: str) -> float:
        """IP 평판 확인"""
        # 캐시 확인
        if ip in self.ioc_database:
            return self.ioc_database[ip].get('reputation_score', 0.5)
        
        # 간단한 휴리스틱 (실제로는 외부 위협 인텔리전스 API 사용)
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # 사설 IP는 중간 평판
            if ip_obj.is_private:
                return 0.5
            
            # 알려진 악성 IP 범위 (예시)
            malicious_ranges = [
                ipaddress.ip_network("185.220.100.0/24"),  # 예시 악성 범위
                ipaddress.ip_network("45.95.168.0/24")
            ]
            
            for malicious_range in malicious_ranges:
                if ip_obj in malicious_range:
                    self.ioc_database[ip] = {'reputation_score': 0.1, 'type': 'malicious'}
                    return 0.1
            
            # 기본 평판 점수
            return 0.5
            
        except ValueError:
            return 0.3  # 유효하지 않은 IP
    
    def _assess_geographic_risk(self, ip: str) -> str:
        """지리적 위험도 평가"""
        # 실제로는 GeoIP 데이터베이스와 위협 인텔리전스 사용
        high_risk_countries = [
            "Unknown", "Tor Exit Node", "Anonymous Proxy"
        ]
        
        # 간단한 예시 (실제 구현 필요)
        return "medium"  # 기본값
    
    def _analyze_user_agent(self, user_agent: str) -> float:
        """사용자 에이전트 분석"""
        risk_score = 0.0
        
        # 의심스러운 패턴
        suspicious_patterns = [
            r"(?i)(bot|crawler|spider|scraper)",
            r"(?i)(nmap|sqlmap|nikto|dirb|gobuster)",
            r"(?i)(python|curl|wget|libwww)"
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent):
                risk_score += 0.3
        
        # 매우 짧거나 일반적이지 않은 사용자 에이전트
        if len(user_agent) < 10 or len(user_agent) > 500:
            risk_score += 0.2
        
        # 버전 정보 없음
        if not re.search(r"\d+\.\d+", user_agent):
            risk_score += 0.1
        
        return min(risk_score, 1.0)
    
    def _analyze_timing_patterns(self, event: SecurityEvent) -> float:
        """시간 패턴 분석"""
        risk_score = 0.0
        
        # 업무 시간 외 활동 (예: 밤 시간대)
        hour = event.timestamp.hour
        if hour < 6 or hour > 22:
            risk_score += 0.2
        
        # 주말 활동
        if event.timestamp.weekday() >= 5:  # 토요일, 일요일
            risk_score += 0.1
        
        # 같은 IP에서 빈번한 요청 패턴 확인
        if event.source_ip:
            recent_events = self._get_recent_events_from_ip(event.source_ip, minutes=5)
            if len(recent_events) > 10:
                risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def _get_recent_events_from_ip(self, ip: str, minutes: int = 5) -> List[SecurityEvent]:
        """특정 IP의 최근 이벤트 조회"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        recent_events = []
        
        # 실제로는 데이터베이스나 캐시에서 조회
        # 여기서는 간단한 구현
        return recent_events
    
    def _process_events(self):
        """이벤트 처리 메인 루프"""
        while self.running:
            try:
                # 이벤트 배치 처리
                events_batch = []
                
                # 큐에서 이벤트 수집 (최대 100개 또는 1초 대기)
                deadline = time.time() + 1.0
                while len(events_batch) < 100 and time.time() < deadline:
                    try:
                        event = self.event_queue.get(timeout=0.1)
                        events_batch.append(event)
                    except queue.Empty:
                        break
                
                if events_batch:
                    # 이벤트 상관관계 분석
                    correlated_events = self._correlate_events(events_batch)
                    
                    # 알림 생성
                    for event in correlated_events:
                        if event.threat_level.value >= ThreatLevel.HIGH.value:
                            self._generate_alert(event)
                    
                    # 이벤트 저장
                    self._store_events(correlated_events)
                
            except Exception as e:
                print(f"Error processing events: {e}")
                time.sleep(1)
    
    def _correlate_events(self, events: List[SecurityEvent]) -> List[SecurityEvent]:
        """이벤트 상관관계 분석"""
        # 같은 소스 IP의 이벤트들 그룹화
        ip_groups = {}
        for event in events:
            if event.source_ip:
                if event.source_ip not in ip_groups:
                    ip_groups[event.source_ip] = []
                ip_groups[event.source_ip].append(event)
        
        # 상관관계 기반 위험도 조정
        for ip, ip_events in ip_groups.items():
            if len(ip_events) > 1:
                # 여러 공격 유형이 같은 IP에서 발생
                unique_attack_types = set(event.event_type for event in ip_events)
                if len(unique_attack_types) > 1:
                    for event in ip_events:
                        event.confidence_score = min(event.confidence_score + 0.2, 1.0)
                        event.indicators.append("multiple_attack_types")
        
        return events
    
    def _generate_alert(self, event: SecurityEvent):
        """보안 알림 생성"""
        alert = {
            "alert_id": f"SEC-{event.event_id}",
            "timestamp": event.timestamp.isoformat(),
            "severity": event.threat_level.name,
            "title": f"Security Event: {event.event_type}",
            "description": f"Detected {event.event_type} from {event.source_ip}",
            "source_ip": event.source_ip,
            "confidence": event.confidence_score,
            "indicators": event.indicators,
            "raw_payload": event.payload[:500],  # 처음 500자만
            "recommended_actions": self._get_recommended_actions(event)
        }
        
        # 알림 시스템으로 전송 (예: AlertManager, SIEM 등)
        self._send_alert_to_siem(alert)
        print(f"SECURITY ALERT: {alert['title']} - Severity: {alert['severity']}")
    
    def _get_recommended_actions(self, event: SecurityEvent) -> List[str]:
        """권장 조치사항 생성"""
        actions = []
        
        if event.threat_level == ThreatLevel.CRITICAL:
            actions.append("즉시 해당 IP 차단")
            actions.append("보안팀 긴급 대응")
        
        if "sql_injection" in event.event_type:
            actions.extend([
                "웹 애플리케이션 방화벽 규칙 업데이트",
                "데이터베이스 접근 로그 점검",
                "SQL 인젝션 방어 패치 적용"
            ])
        
        if "brute_force" in event.event_type:
            actions.extend([
                "계정 잠금 정책 확인",
                "다단계 인증 강화",
                "로그인 시도 제한 강화"
            ])
        
        return actions
    
    def _store_events(self, events: List[SecurityEvent]):
        """이벤트 저장"""
        # 실제로는 데이터베이스나 SIEM에 저장
        for event in events:
            event_data = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "threat_level": event.threat_level.name,
                "source_ip": event.source_ip,
                "confidence_score": event.confidence_score,
                "indicators": event.indicators,
                "payload": event.payload
            }
            # 저장 로직 구현
            pass
    
    def _send_alert_to_siem(self, alert: Dict[str, Any]):
        """SIEM으로 알림 전송"""
        # SIEM API 또는 syslog로 전송
        pass
```

### 1.2 침해 지표(IOC) 모니터링

**IOC 관리 시스템**
```python
# ioc_manager.py
import json
import requests
import time
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
import sqlite3
import hashlib

@dataclass
class IOC:
    value: str
    ioc_type: str  # ip, domain, url, hash, email
    threat_type: str  # malware, phishing, c2, etc.
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    description: str
    is_active: bool = True

class IOCManager:
    def __init__(self, db_path: str = "ioc_database.db"):
        self.db_path = db_path
        self.ioc_cache = {}
        self.feed_sources = {}
        self.lock = threading.Lock()
        self._init_database()
        
    def _init_database(self):
        """IOC 데이터베이스 초기화"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT UNIQUE NOT NULL,
                ioc_type TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                tags TEXT,  -- JSON array
                description TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_threat_type ON iocs(threat_type);
        ''')
        
        conn.commit()
        conn.close()
    
    def add_ioc_feed(self, name: str, url: str, format_type: str = "json", 
                     api_key: str = None, update_interval: int = 3600):
        """IOC 피드 추가"""
        self.feed_sources[name] = {
            "url": url,
            "format": format_type,
            "api_key": api_key,
            "update_interval": update_interval,
            "last_update": 0
        }
    
    def start_feed_updates(self):
        """IOC 피드 자동 업데이트 시작"""
        def update_loop():
            while True:
                try:
                    self._update_all_feeds()
                    time.sleep(300)  # 5분마다 체크
                except Exception as e:
                    print(f"Feed update error: {e}")
                    time.sleep(60)
        
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()
    
    def _update_all_feeds(self):
        """모든 IOC 피드 업데이트"""
        current_time = time.time()
        
        for feed_name, feed_config in self.feed_sources.items():
            last_update = feed_config["last_update"]
            interval = feed_config["update_interval"]
            
            if current_time - last_update >= interval:
                try:
                    self._update_feed(feed_name, feed_config)
                    feed_config["last_update"] = current_time
                    print(f"Updated IOC feed: {feed_name}")
                except Exception as e:
                    print(f"Failed to update feed {feed_name}: {e}")
    
    def _update_feed(self, feed_name: str, feed_config: Dict):
        """개별 IOC 피드 업데이트"""
        headers = {}
        if feed_config.get("api_key"):
            headers["Authorization"] = f"Bearer {feed_config['api_key']}"
        
        response = requests.get(feed_config["url"], headers=headers, timeout=30)
        response.raise_for_status()
        
        if feed_config["format"] == "json":
            data = response.json()
            self._process_json_feed(data, feed_name)
        elif feed_config["format"] == "csv":
            self._process_csv_feed(response.text, feed_name)
        elif feed_config["format"] == "txt":
            self._process_txt_feed(response.text, feed_name)
    
    def _process_json_feed(self, data: Dict, source: str):
        """JSON 형식 IOC 피드 처리"""
        # 일반적인 JSON IOC 피드 형식 처리
        if "indicators" in data:
            indicators = data["indicators"]
        elif "iocs" in data:
            indicators = data["iocs"]
        else:
            indicators = data if isinstance(data, list) else []
        
        for indicator in indicators:
            try:
                ioc = IOC(
                    value=indicator.get("value", "").strip(),
                    ioc_type=indicator.get("type", "unknown"),
                    threat_type=indicator.get("threat_type", "unknown"),
                    confidence=float(indicator.get("confidence", 0.5)),
                    source=source,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    tags=indicator.get("tags", []),
                    description=indicator.get("description", ""),
                    is_active=indicator.get("is_active", True)
                )
                
                if ioc.value:  # 빈 값이 아닌 경우만
                    self.add_ioc(ioc)
                    
            except Exception as e:
                print(f"Error processing indicator: {e}")
    
    def _process_csv_feed(self, csv_data: str, source: str):
        """CSV 형식 IOC 피드 처리"""
        lines = csv_data.strip().split('\n')
        
        # 첫 번째 줄이 헤더인 경우 스킵
        if lines and not self._is_valid_ioc_value(lines[0].split(',')[0]):
            lines = lines[1:]
        
        for line in lines:
            parts = line.split(',')
            if len(parts) >= 2:
                try:
                    ioc = IOC(
                        value=parts[0].strip(),
                        ioc_type=parts[1].strip() if len(parts) > 1 else "unknown",
                        threat_type=parts[2].strip() if len(parts) > 2 else "unknown",
                        confidence=float(parts[3]) if len(parts) > 3 else 0.5,
                        source=source,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        tags=[],
                        description=parts[4].strip() if len(parts) > 4 else ""
                    )
                    
                    if self._is_valid_ioc_value(ioc.value):
                        self.add_ioc(ioc)
                        
                except Exception as e:
                    print(f"Error processing CSV line: {e}")
    
    def _process_txt_feed(self, txt_data: str, source: str):
        """텍스트 형식 IOC 피드 처리"""
        lines = txt_data.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):  # 주석 제외
                if self._is_valid_ioc_value(line):
                    ioc_type = self._detect_ioc_type(line)
                    
                    ioc = IOC(
                        value=line,
                        ioc_type=ioc_type,
                        threat_type="unknown",
                        confidence=0.7,
                        source=source,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        tags=[],
                        description=f"IOC from {source}"
                    )
                    
                    self.add_ioc(ioc)
    
    def _is_valid_ioc_value(self, value: str) -> bool:
        """IOC 값의 유효성 검사"""
        if not value or len(value.strip()) < 3:
            return False
        
        # 기본적인 형식 검사
        import re
        
        # IP 주소 패턴
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # 도메인 패턴
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        # 해시 패턴 (MD5, SHA1, SHA256)
        hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
        
        return (re.match(ip_pattern, value) or 
                re.match(domain_pattern, value) or 
                re.match(hash_pattern, value))
    
    def _detect_ioc_type(self, value: str) -> str:
        """IOC 유형 자동 탐지"""
        import re
        
        # IP 주소
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
            return "ip"
        
        # 해시
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return "md5"
        elif re.match(r'^[a-fA-F0-9]{40}$', value):
            return "sha1"
        elif re.match(r'^[a-fA-F0-9]{64}$', value):
            return "sha256"
        
        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return "url"
        
        # 이메일
        if '@' in value and '.' in value:
            return "email"
        
        # 도메인
        if '.' in value and not '/' in value:
            return "domain"
        
        return "unknown"
    
    def add_ioc(self, ioc: IOC) -> bool:
        """IOC 추가"""
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # 기존 IOC 확인
                cursor.execute("SELECT id FROM iocs WHERE value = ?", (ioc.value,))
                existing = cursor.fetchone()
                
                if existing:
                    # 기존 IOC 업데이트
                    cursor.execute('''
                        UPDATE iocs SET 
                            last_seen = ?,
                            confidence = MAX(confidence, ?),
                            is_active = ?
                        WHERE value = ?
                    ''', (ioc.last_seen.isoformat(), ioc.confidence, ioc.is_active, ioc.value))
                else:
                    # 새 IOC 삽입
                    cursor.execute('''
                        INSERT INTO iocs (
                            value, ioc_type, threat_type, confidence, source,
                            first_seen, last_seen, tags, description, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ioc.value, ioc.ioc_type, ioc.threat_type, ioc.confidence,
                        ioc.source, ioc.first_seen.isoformat(), ioc.last_seen.isoformat(),
                        json.dumps(ioc.tags), ioc.description, ioc.is_active
                    ))
                
                conn.commit()
                
                # 캐시 업데이트
                self.ioc_cache[ioc.value] = ioc
                
                conn.close()
                return True
                
            except Exception as e:
                print(f"Error adding IOC: {e}")
                return False
    
    def check_ioc(self, value: str) -> Optional[IOC]:
        """IOC 확인"""
        # 캐시 확인
        if value in self.ioc_cache:
            return self.ioc_cache[value]
        
        # 데이터베이스 조회
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT value, ioc_type, threat_type, confidence, source,
                   first_seen, last_seen, tags, description, is_active
            FROM iocs 
            WHERE value = ? AND is_active = TRUE
        ''', (value,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            ioc = IOC(
                value=result[0],
                ioc_type=result[1],
                threat_type=result[2],
                confidence=result[3],
                source=result[4],
                first_seen=datetime.fromisoformat(result[5]),
                last_seen=datetime.fromisoformat(result[6]),
                tags=json.loads(result[7]) if result[7] else [],
                description=result[8],
                is_active=bool(result[9])
            )
            
            # 캐시에 저장
            self.ioc_cache[value] = ioc
            return ioc
        
        return None
    
    def bulk_check_iocs(self, values: List[str]) -> Dict[str, IOC]:
        """대량 IOC 확인"""
        results = {}
        
        # 캐시에서 확인
        uncached_values = []
        for value in values:
            if value in self.ioc_cache:
                results[value] = self.ioc_cache[value]
            else:
                uncached_values.append(value)
        
        # 데이터베이스에서 일괄 조회
        if uncached_values:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            placeholders = ','.join('?' * len(uncached_values))
            cursor.execute(f'''
                SELECT value, ioc_type, threat_type, confidence, source,
                       first_seen, last_seen, tags, description, is_active
                FROM iocs 
                WHERE value IN ({placeholders}) AND is_active = TRUE
            ''', uncached_values)
            
            db_results = cursor.fetchall()
            conn.close()
            
            for result in db_results:
                ioc = IOC(
                    value=result[0],
                    ioc_type=result[1],
                    threat_type=result[2],
                    confidence=result[3],
                    source=result[4],
                    first_seen=datetime.fromisoformat(result[5]),
                    last_seen=datetime.fromisoformat(result[6]),
                    tags=json.loads(result[7]) if result[7] else [],
                    description=result[8],
                    is_active=bool(result[9])
                )
                
                results[result[0]] = ioc
                self.ioc_cache[result[0]] = ioc
        
        return results
    
    def get_ioc_statistics(self) -> Dict[str, Any]:
        """IOC 통계 정보"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 전체 IOC 수
        cursor.execute("SELECT COUNT(*) FROM iocs WHERE is_active = TRUE")
        total_count = cursor.fetchone()[0]
        
        # 유형별 IOC 수
        cursor.execute('''
            SELECT ioc_type, COUNT(*) 
            FROM iocs 
            WHERE is_active = TRUE 
            GROUP BY ioc_type
        ''')
        type_counts = dict(cursor.fetchall())
        
        # 위협 유형별 IOC 수
        cursor.execute('''
            SELECT threat_type, COUNT(*) 
            FROM iocs 
            WHERE is_active = TRUE 
            GROUP BY threat_type
        ''')
        threat_counts = dict(cursor.fetchall())
        
        # 소스별 IOC 수
        cursor.execute('''
            SELECT source, COUNT(*) 
            FROM iocs 
            WHERE is_active = TRUE 
            GROUP BY source
        ''')
        source_counts = dict(cursor.fetchall())
        
        # 최근 추가된 IOC (24시간 내)
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute('''
            SELECT COUNT(*) 
            FROM iocs 
            WHERE is_active = TRUE AND first_seen > ?
        ''', (yesterday,))
        recent_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_iocs": total_count,
            "by_type": type_counts,
            "by_threat_type": threat_counts,
            "by_source": source_counts,
            "recent_additions": recent_count,
            "cache_size": len(self.ioc_cache)
        }
```

### 1.3 SIEM 통합

**SIEM 통합 어댑터**
```python
# siem_adapter.py
import json
import requests
import socket
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
import threading
import queue
from dataclasses import asdict

class SIEMAdapter:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.event_queue = queue.Queue(maxsize=10000)
        self.batch_size = config.get('batch_size', 100)
        self.flush_interval = config.get('flush_interval', 30)
        self.running = False
        
        # SIEM 유형별 설정
        self.siem_type = config.get('type', 'generic')
        self.endpoint_url = config.get('endpoint_url')
        self.api_key = config.get('api_key')
        self.syslog_host = config.get('syslog_host')
        self.syslog_port = config.get('syslog_port', 514)
        
    def start(self):
        """SIEM 통합 시작"""
        self.running = True
        
        # 이벤트 전송 스레드 시작
        sender_thread = threading.Thread(target=self._event_sender_loop)
        sender_thread.daemon = True
        sender_thread.start()
        
        print(f"SIEM adapter started for {self.siem_type}")
    
    def stop(self):
        """SIEM 통합 중지"""
        self.running = False
        print("SIEM adapter stopped")
    
    def send_security_event(self, event: Dict[str, Any]):
        """보안 이벤트 전송"""
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            print("SIEM event queue is full, dropping event")
    
    def _event_sender_loop(self):
        """이벤트 전송 메인 루프"""
        events_batch = []
        last_flush = time.time()
        
        while self.running:
            try:
                # 이벤트 수집
                try:
                    event = self.event_queue.get(timeout=1.0)
                    events_batch.append(event)
                except queue.Empty:
                    pass
                
                # 배치 전송 조건 확인
                current_time = time.time()
                should_flush = (
                    len(events_batch) >= self.batch_size or
                    (events_batch and current_time - last_flush >= self.flush_interval)
                )
                
                if should_flush:
                    self._send_events_batch(events_batch)
                    events_batch = []
                    last_flush = current_time
                    
            except Exception as e:
                print(f"Error in SIEM sender loop: {e}")
                time.sleep(5)
    
    def _send_events_batch(self, events: List[Dict[str, Any]]):
        """이벤트 배치 전송"""
        if not events:
            return
        
        try:
            if self.siem_type == 'splunk':
                self._send_to_splunk(events)
            elif self.siem_type == 'qradar':
                self._send_to_qradar(events)
            elif self.siem_type == 'arcsight':
                self._send_to_arcsight(events)
            elif self.siem_type == 'sentinel':
                self._send_to_sentinel(events)
            elif self.siem_type == 'syslog':
                self._send_to_syslog(events)
            else:
                self._send_generic(events)
                
            print(f"Sent {len(events)} events to {self.siem_type}")
            
        except Exception as e:
            print(f"Failed to send events to SIEM: {e}")
    
    def _send_to_splunk(self, events: List[Dict[str, Any]]):
        """Splunk으로 이벤트 전송"""
        headers = {
            'Authorization': f'Splunk {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        # Splunk HEC 형식으로 변환
        splunk_events = []
        for event in events:
            splunk_event = {
                "time": event.get('timestamp', time.time()),
                "source": "security_monitoring",
                "sourcetype": "security_event",
                "index": "security",
                "event": event
            }
            splunk_events.append(splunk_event)
        
        # 배치로 전송
        payload = '\n'.join(json.dumps(e) for e in splunk_events)
        
        response = requests.post(
            f"{self.endpoint_url}/services/collector/event",
            headers=headers,
            data=payload,
            timeout=30
        )
        response.raise_for_status()
    
    def _send_to_qradar(self, events: List[Dict[str, Any]]):
        """IBM QRadar로 이벤트 전송"""
        headers = {
            'SEC': self.api_key,
            'Content-Type': 'application/json',
            'Version': '12.0'
        }
        
        # QRadar LEEF 형식으로 변환
        qradar_events = []
        for event in events:
            leef_event = self._convert_to_leef(event)
            qradar_events.append(leef_event)
        
        payload = {"events": qradar_events}
        
        response = requests.post(
            f"{self.endpoint_url}/api/ariel/events",
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
    
    def _send_to_arcsight(self, events: List[Dict[str, Any]]):
        """Micro Focus ArcSight로 이벤트 전송"""
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        # ArcSight CEF 형식으로 변환
        cef_events = []
        for event in events:
            cef_event = self._convert_to_cef(event)
            cef_events.append(cef_event)
        
        payload = {"events": cef_events}
        
        response = requests.post(
            f"{self.endpoint_url}/logger/api/event",
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
    
    def _send_to_sentinel(self, events: List[Dict[str, Any]]):
        """Microsoft Sentinel로 이벤트 전송"""
        # Sentinel은 Log Analytics Workspace를 통해 데이터 수집
        import hashlib
        import hmac
        import base64
        
        workspace_id = self.config.get('workspace_id')
        shared_key = self.config.get('shared_key')
        log_type = 'SecurityEvents'
        
        # 요청 본문 생성
        body = json.dumps(events)
        
        # 서명 생성
        def build_signature(workspace_id, shared_key, date, content_length, method, content_type, resource):
            x_headers = 'x-ms-date:' + date
            string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
            bytes_to_hash = bytes(string_to_hash, 'UTF-8')
            decoded_key = base64.b64decode(shared_key)
            encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
            authorization = f"SharedKey {workspace_id}:{encoded_hash}"
            return authorization
        
        rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = build_signature(workspace_id, shared_key, rfc1123date, content_length, 'POST', 'application/json', '/api/logs')
        
        headers = {
            'content-type': 'application/json',
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }
        
        uri = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        
        response = requests.post(uri, data=body, headers=headers, timeout=30)
        response.raise_for_status()
    
    def _send_to_syslog(self, events: List[Dict[str, Any]]):
        """Syslog로 이벤트 전송"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            for event in events:
                # RFC3164 syslog 형식
                priority = 13  # facility=1 (user), severity=5 (notice)
                timestamp = datetime.now().strftime('%b %d %H:%M:%S')
                hostname = socket.gethostname()
                tag = 'SecurityMonitor'
                
                message = json.dumps(event)
                syslog_message = f"<{priority}>{timestamp} {hostname} {tag}: {message}"
                
                sock.sendto(syslog_message.encode('utf-8'), (self.syslog_host, self.syslog_port))
                
        finally:
            sock.close()
    
    def _send_generic(self, events: List[Dict[str, Any]]):
        """일반적인 HTTP 엔드포인트로 전송"""
        headers = {
            'Content-Type': 'application/json'
        }
        
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        payload = {"events": events}
        
        response = requests.post(
            self.endpoint_url,
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
    
    def _convert_to_leef(self, event: Dict[str, Any]) -> str:
        """QRadar LEEF 형식으로 변환"""
        # LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Fields
        version = "2.0"
        vendor = "SecurityMonitor"
        product = "ThreatDetection"
        product_version = "1.0"
        event_id = event.get('event_type', 'SecurityEvent')
        delimiter = "|"
        
        # 필드 매핑
        fields = [
            f"devTime={event.get('timestamp', '')}",
            f"src={event.get('source_ip', '')}",
            f"dst={event.get('target_ip', '')}",
            f"sev={event.get('threat_level', '')}",
            f"cat={event.get('event_type', '')}",
            f"msg={event.get('description', '')}"
        ]
        
        leef_event = f"LEEF:{version}{delimiter}{vendor}{delimiter}{product}{delimiter}{product_version}{delimiter}{event_id}{delimiter}{delimiter}{'^'.join(fields)}"
        return leef_event
    
    def _convert_to_cef(self, event: Dict[str, Any]) -> str:
        """ArcSight CEF 형식으로 변환"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        version = "0"
        vendor = "SecurityMonitor"
        product = "ThreatDetection"
        device_version = "1.0"
        signature_id = event.get('event_type', 'SecurityEvent')
        name = event.get('title', 'Security Event Detected')
        severity = self._map_severity_to_cef(event.get('threat_level', 'LOW'))
        
        # 확장 필드
        extensions = [
            f"rt={event.get('timestamp', '')}",
            f"src={event.get('source_ip', '')}",
            f"dst={event.get('target_ip', '')}",
            f"msg={event.get('description', '')}",
            f"cs1={event.get('confidence_score', '')}",
            f"cs1Label=ConfidenceScore"
        ]
        
        cef_event = f"CEF:{version}|{vendor}|{product}|{device_version}|{signature_id}|{name}|{severity}|{' '.join(extensions)}"
        return cef_event
    
    def _map_severity_to_cef(self, threat_level: str) -> str:
        """위협 레벨을 CEF 심각도로 매핑"""
        mapping = {
            'LOW': '3',
            'MEDIUM': '6',
            'HIGH': '8',
            'CRITICAL': '10'
        }
        return mapping.get(threat_level.upper(), '3')

# SIEM 통합 관리자
class SIEMIntegrationManager:
    def __init__(self):
        self.adapters = {}
        self.event_processors = []
        
    def add_siem_adapter(self, name: str, config: Dict[str, Any]):
        """SIEM 어댑터 추가"""
        adapter = SIEMAdapter(config)
        self.adapters[name] = adapter
        adapter.start()
        print(f"Added SIEM adapter: {name}")
    
    def send_to_all_siems(self, event: Dict[str, Any]):
        """모든 SIEM에 이벤트 전송"""
        # 이벤트 전처리
        processed_event = self._preprocess_event(event)
        
        # 모든 어댑터에 전송
        for name, adapter in self.adapters.items():
            try:
                adapter.send_security_event(processed_event)
            except Exception as e:
                print(f"Failed to send event to {name}: {e}")
    
    def _preprocess_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """이벤트 전처리"""
        # 표준화된 이벤트 형식
        processed = {
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'event_id': event.get('event_id', ''),
            'event_type': event.get('event_type', 'security_event'),
            'severity': event.get('severity', 'medium'),
            'source_ip': event.get('source_ip', ''),
            'target_ip': event.get('target_ip', ''),
            'description': event.get('description', ''),
            'raw_data': event
        }
        
        # 추가 컨텍스트 정보
        processed['host'] = socket.gethostname()
        processed['product'] = 'SecurityMonitor'
        processed['version'] = '1.0'
        
        return processed
    
    def stop_all_adapters(self):
        """모든 SIEM 어댑터 중지"""
        for adapter in self.adapters.values():
            adapter.stop()
        print("All SIEM adapters stopped")
```

## 2. 실습 과제

### 과제 1: 보안 이벤트 탐지 시스템 구축
1. 실시간 보안 이벤트 탐지 엔진 구현
2. 다양한 공격 패턴 탐지 규칙 작성
3. 컨텍스트 기반 위협 분석 시스템

### 과제 2: IOC 관리 시스템 개발
1. 다중 위협 인텔리전스 피드 통합
2. IOC 자동 업데이트 및 검증 시스템
3. 대량 IOC 조회 최적화

### 과제 3: SIEM 통합 구현
1. 여러 SIEM 플랫폼 지원 어댑터
2. 표준 보안 이벤트 형식 변환
3. 실시간 이벤트 전송 및 배치 처리

## 3. 컴플라이언스 자동화

### 컴플라이언스 체크 프레임워크
```python
# compliance_framework.py
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any

class ComplianceChecker:
    def __init__(self):
        self.frameworks = {
            'SOC2': self._check_soc2_compliance,
            'GDPR': self._check_gdpr_compliance,
            'PCI_DSS': self._check_pci_dss_compliance,
            'HIPAA': self._check_hipaa_compliance
        }
    
    def run_compliance_check(self, framework: str) -> Dict[str, Any]:
        """컴플라이언스 검사 실행"""
        if framework in self.frameworks:
            return self.frameworks[framework]()
        else:
            return {"error": f"Unknown framework: {framework}"}
    
    def _check_soc2_compliance(self) -> Dict[str, Any]:
        """SOC2 컴플라이언스 검사"""
        checks = {
            'security_controls': self._check_security_controls(),
            'availability': self._check_availability_controls(),
            'processing_integrity': self._check_processing_integrity(),
            'confidentiality': self._check_confidentiality_controls(),
            'privacy': self._check_privacy_controls()
        }
        
        total_score = sum(check['score'] for check in checks.values())
        compliance_percentage = (total_score / (len(checks) * 100)) * 100
        
        return {
            'framework': 'SOC2',
            'compliance_percentage': compliance_percentage,
            'checks': checks,
            'overall_status': 'COMPLIANT' if compliance_percentage >= 80 else 'NON_COMPLIANT'
        }
```

## 4. 다음 단계
- 멀티 테넌시 및 거버넌스 (Phase 5-1)
- 성능 최적화 및 비용 관리 (Phase 5-2)