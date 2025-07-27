# 멀티 테넌시 및 거버넌스 (Phase 5-1)

## 개요
대규모 엔터프라이즈 환경에서 다중 테넌트 모니터링 시스템 구축, 리소스 격리, 거버넌스 정책, 셀프 서비스 기능을 학습합니다.

## 1. 멀티 테넌트 아키텍처

### 1.1 테넌트 격리 전략

**Kubernetes 네임스페이스 기반 격리**
```yaml
# tenant-namespace-template.yml
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring-tenant-${TENANT_ID}
  labels:
    tenant: ${TENANT_ID}
    monitoring.company.com/tenant: ${TENANT_ID}
    monitoring.company.com/tier: ${TENANT_TIER}
  annotations:
    monitoring.company.com/contact: ${TENANT_CONTACT}
    monitoring.company.com/billing-code: ${BILLING_CODE}

---
# 네트워크 정책으로 테넌트 간 격리
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-isolation
  namespace: monitoring-tenant-${TENANT_ID}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # 같은 테넌트 내에서만 통신 허용
  - from:
    - namespaceSelector:
        matchLabels:
          tenant: ${TENANT_ID}
  # 모니터링 시스템에서의 접근 허용
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring-system
    ports:
    - protocol: TCP
      port: 9090
    - protocol: TCP
      port: 3000
  
  egress:
  # DNS 해상도를 위한 kube-system 접근
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
  # 같은 테넌트 내 통신
  - to:
    - namespaceSelector:
        matchLabels:
          tenant: ${TENANT_ID}
  # 모니터링 시스템으로의 메트릭 전송
  - to:
    - namespaceSelector:
        matchLabels:
          name: monitoring-system
    ports:
    - protocol: TCP
      port: 9090

---
# 리소스 할당량
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-quota
  namespace: monitoring-tenant-${TENANT_ID}
spec:
  hard:
    requests.cpu: ${CPU_REQUEST_LIMIT}
    requests.memory: ${MEMORY_REQUEST_LIMIT}
    limits.cpu: ${CPU_LIMIT}
    limits.memory: ${MEMORY_LIMIT}
    persistentvolumeclaims: ${PVC_LIMIT}
    requests.storage: ${STORAGE_REQUEST_LIMIT}
    pods: ${POD_LIMIT}
    services: ${SERVICE_LIMIT}
    configmaps: ${CONFIGMAP_LIMIT}
    secrets: ${SECRET_LIMIT}

---
# 기본 제한 범위
apiVersion: v1
kind: LimitRange
metadata:
  name: tenant-limits
  namespace: monitoring-tenant-${TENANT_ID}
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    max:
      cpu: "2000m"
      memory: "4Gi"
    min:
      cpu: "50m"
      memory: "64Mi"
  - type: PersistentVolumeClaim
    max:
      storage: "10Gi"
    min:
      storage: "1Gi"
```

**테넌트 관리 시스템**
```python
# tenant_manager.py
import yaml
import subprocess
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import kubernetes
from kubernetes import client, config
import jinja2

@dataclass
class TenantConfig:
    tenant_id: str
    tenant_name: str
    tier: str  # basic, standard, premium, enterprise
    contact_email: str
    billing_code: str
    resource_limits: Dict[str, str]
    created_at: datetime
    is_active: bool = True
    
@dataclass
class ResourceLimits:
    cpu_request_limit: str
    memory_request_limit: str
    cpu_limit: str
    memory_limit: str
    pvc_limit: str
    storage_request_limit: str
    pod_limit: str
    service_limit: str
    configmap_limit: str
    secret_limit: str

class TenantManager:
    def __init__(self, kubeconfig_path: str = None):
        if kubeconfig_path:
            config.load_kube_config(config_file=kubeconfig_path)
        else:
            config.load_incluster_config()
        
        self.k8s_client = client.ApiClient()
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader('templates')
        )
        
        # 티어별 기본 리소스 한도
        self.tier_defaults = {
            'basic': ResourceLimits(
                cpu_request_limit="2",
                memory_request_limit="4Gi",
                cpu_limit="4",
                memory_limit="8Gi",
                pvc_limit="5",
                storage_request_limit="50Gi",
                pod_limit="20",
                service_limit="10",
                configmap_limit="20",
                secret_limit="20"
            ),
            'standard': ResourceLimits(
                cpu_request_limit="8",
                memory_request_limit="16Gi",
                cpu_limit="16",
                memory_limit="32Gi",
                pvc_limit="10",
                storage_request_limit="200Gi",
                pod_limit="50",
                service_limit="25",
                configmap_limit="50",
                secret_limit="50"
            ),
            'premium': ResourceLimits(
                cpu_request_limit="32",
                memory_request_limit="64Gi",
                cpu_limit="64",
                memory_limit="128Gi",
                pvc_limit="20",
                storage_request_limit="500Gi",
                pod_limit="100",
                service_limit="50",
                configmap_limit="100",
                secret_limit="100"
            ),
            'enterprise': ResourceLimits(
                cpu_request_limit="128",
                memory_request_limit="256Gi",
                cpu_limit="256",
                memory_limit="512Gi",
                pvc_limit="50",
                storage_request_limit="2Ti",
                pod_limit="500",
                service_limit="200",
                configmap_limit="500",
                secret_limit="500"
            )
        }
    
    def create_tenant(self, tenant_config: TenantConfig) -> bool:
        """새 테넌트 생성"""
        try:
            # 1. 네임스페이스 생성
            self._create_tenant_namespace(tenant_config)
            
            # 2. RBAC 설정
            self._setup_tenant_rbac(tenant_config)
            
            # 3. 네트워크 정책 설정
            self._setup_network_policies(tenant_config)
            
            # 4. 리소스 할당량 설정
            self._setup_resource_quotas(tenant_config)
            
            # 5. 모니터링 구성 요소 배포
            self._deploy_tenant_monitoring(tenant_config)
            
            # 6. 대시보드 및 알림 설정
            self._setup_tenant_dashboards(tenant_config)
            
            print(f"Tenant {tenant_config.tenant_id} created successfully")
            return True
            
        except Exception as e:
            print(f"Failed to create tenant {tenant_config.tenant_id}: {e}")
            # 롤백 시도
            self._cleanup_tenant_resources(tenant_config.tenant_id)
            return False
    
    def _create_tenant_namespace(self, tenant_config: TenantConfig):
        """테넌트 네임스페이스 생성"""
        namespace = client.V1Namespace(
            metadata=client.V1ObjectMeta(
                name=f"monitoring-tenant-{tenant_config.tenant_id}",
                labels={
                    "tenant": tenant_config.tenant_id,
                    "monitoring.company.com/tenant": tenant_config.tenant_id,
                    "monitoring.company.com/tier": tenant_config.tier
                },
                annotations={
                    "monitoring.company.com/contact": tenant_config.contact_email,
                    "monitoring.company.com/billing-code": tenant_config.billing_code,
                    "monitoring.company.com/created": tenant_config.created_at.isoformat()
                }
            )
        )
        
        self.core_v1.create_namespace(namespace)
    
    def _setup_tenant_rbac(self, tenant_config: TenantConfig):
        """테넌트 RBAC 설정"""
        namespace = f"monitoring-tenant-{tenant_config.tenant_id}"
        
        # ServiceAccount 생성
        service_account = client.V1ServiceAccount(
            metadata=client.V1ObjectMeta(
                name=f"tenant-{tenant_config.tenant_id}",
                namespace=namespace
            )
        )
        self.core_v1.create_namespaced_service_account(namespace, service_account)
        
        # Role 생성 (네임스페이스 내 권한)
        role = client.V1Role(
            metadata=client.V1ObjectMeta(
                name=f"tenant-{tenant_config.tenant_id}-role",
                namespace=namespace
            ),
            rules=[
                client.V1PolicyRule(
                    api_groups=[""],
                    resources=["pods", "services", "configmaps", "secrets", "persistentvolumeclaims"],
                    verbs=["get", "list", "watch", "create", "update", "patch", "delete"]
                ),
                client.V1PolicyRule(
                    api_groups=["apps"],
                    resources=["deployments", "replicasets", "statefulsets"],
                    verbs=["get", "list", "watch", "create", "update", "patch", "delete"]
                ),
                client.V1PolicyRule(
                    api_groups=["monitoring.coreos.com"],
                    resources=["servicemonitors", "prometheusrules"],
                    verbs=["get", "list", "watch", "create", "update", "patch", "delete"]
                )
            ]
        )
        
        rbac_v1 = client.RbacAuthorizationV1Api()
        rbac_v1.create_namespaced_role(namespace, role)
        
        # RoleBinding 생성
        role_binding = client.V1RoleBinding(
            metadata=client.V1ObjectMeta(
                name=f"tenant-{tenant_config.tenant_id}-binding",
                namespace=namespace
            ),
            subjects=[
                client.V1Subject(
                    kind="ServiceAccount",
                    name=f"tenant-{tenant_config.tenant_id}",
                    namespace=namespace
                )
            ],
            role_ref=client.V1RoleRef(
                kind="Role",
                name=f"tenant-{tenant_config.tenant_id}-role",
                api_group="rbac.authorization.k8s.io"
            )
        )
        rbac_v1.create_namespaced_role_binding(namespace, role_binding)
    
    def _setup_network_policies(self, tenant_config: TenantConfig):
        """네트워크 정책 설정"""
        namespace = f"monitoring-tenant-{tenant_config.tenant_id}"
        
        # 테넌트 격리 네트워크 정책
        network_policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(
                name="tenant-isolation",
                namespace=namespace
            ),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(),
                policy_types=["Ingress", "Egress"],
                ingress=[
                    # 같은 테넌트 내 통신 허용
                    client.V1NetworkPolicyIngressRule(
                        _from=[
                            client.V1NetworkPolicyPeer(
                                namespace_selector=client.V1LabelSelector(
                                    match_labels={"tenant": tenant_config.tenant_id}
                                )
                            )
                        ]
                    ),
                    # 모니터링 시스템 접근 허용
                    client.V1NetworkPolicyIngressRule(
                        _from=[
                            client.V1NetworkPolicyPeer(
                                namespace_selector=client.V1LabelSelector(
                                    match_labels={"name": "monitoring-system"}
                                )
                            )
                        ],
                        ports=[
                            client.V1NetworkPolicyPort(protocol="TCP", port=9090),
                            client.V1NetworkPolicyPort(protocol="TCP", port=3000)
                        ]
                    )
                ],
                egress=[
                    # DNS 해상도
                    client.V1NetworkPolicyEgressRule(
                        to=[
                            client.V1NetworkPolicyPeer(
                                namespace_selector=client.V1LabelSelector(
                                    match_labels={"name": "kube-system"}
                                )
                            )
                        ],
                        ports=[
                            client.V1NetworkPolicyPort(protocol="UDP", port=53)
                        ]
                    ),
                    # 같은 테넌트 내 통신
                    client.V1NetworkPolicyEgressRule(
                        to=[
                            client.V1NetworkPolicyPeer(
                                namespace_selector=client.V1LabelSelector(
                                    match_labels={"tenant": tenant_config.tenant_id}
                                )
                            )
                        ]
                    ),
                    # 모니터링 시스템으로 메트릭 전송
                    client.V1NetworkPolicyEgressRule(
                        to=[
                            client.V1NetworkPolicyPeer(
                                namespace_selector=client.V1LabelSelector(
                                    match_labels={"name": "monitoring-system"}
                                )
                            )
                        ],
                        ports=[
                            client.V1NetworkPolicyPort(protocol="TCP", port=9090)
                        ]
                    )
                ]
            )
        )
        
        self.networking_v1.create_namespaced_network_policy(namespace, network_policy)
    
    def _setup_resource_quotas(self, tenant_config: TenantConfig):
        """리소스 할당량 설정"""
        namespace = f"monitoring-tenant-{tenant_config.tenant_id}"
        
        # 티어에 따른 기본 한도 적용
        limits = self.tier_defaults.get(tenant_config.tier, self.tier_defaults['basic'])
        
        # 커스텀 한도가 있는 경우 오버라이드
        if tenant_config.resource_limits:
            for key, value in tenant_config.resource_limits.items():
                if hasattr(limits, key):
                    setattr(limits, key, value)
        
        # ResourceQuota 생성
        resource_quota = client.V1ResourceQuota(
            metadata=client.V1ObjectMeta(
                name="tenant-quota",
                namespace=namespace
            ),
            spec=client.V1ResourceQuotaSpec(
                hard={
                    "requests.cpu": limits.cpu_request_limit,
                    "requests.memory": limits.memory_request_limit,
                    "limits.cpu": limits.cpu_limit,
                    "limits.memory": limits.memory_limit,
                    "persistentvolumeclaims": limits.pvc_limit,
                    "requests.storage": limits.storage_request_limit,
                    "pods": limits.pod_limit,
                    "services": limits.service_limit,
                    "configmaps": limits.configmap_limit,
                    "secrets": limits.secret_limit
                }
            )
        )
        
        self.core_v1.create_namespaced_resource_quota(namespace, resource_quota)
        
        # LimitRange 생성
        limit_range = client.V1LimitRange(
            metadata=client.V1ObjectMeta(
                name="tenant-limits",
                namespace=namespace
            ),
            spec=client.V1LimitRangeSpec(
                limits=[
                    client.V1LimitRangeItem(
                        type="Container",
                        default={"cpu": "500m", "memory": "512Mi"},
                        default_request={"cpu": "100m", "memory": "128Mi"},
                        max={"cpu": "2000m", "memory": "4Gi"},
                        min={"cpu": "50m", "memory": "64Mi"}
                    ),
                    client.V1LimitRangeItem(
                        type="PersistentVolumeClaim",
                        max={"storage": "10Gi"},
                        min={"storage": "1Gi"}
                    )
                ]
            )
        )
        
        self.core_v1.create_namespaced_limit_range(namespace, limit_range)
    
    def _deploy_tenant_monitoring(self, tenant_config: TenantConfig):
        """테넌트 모니터링 구성 요소 배포"""
        namespace = f"monitoring-tenant-{tenant_config.tenant_id}"
        
        # Prometheus 인스턴스 배포 (테넌트별)
        prometheus_config = self._generate_tenant_prometheus_config(tenant_config)
        self._deploy_prometheus_instance(namespace, prometheus_config)
        
        # Grafana 인스턴스 배포 (선택적)
        if tenant_config.tier in ['premium', 'enterprise']:
            grafana_config = self._generate_tenant_grafana_config(tenant_config)
            self._deploy_grafana_instance(namespace, grafana_config)
    
    def _generate_tenant_prometheus_config(self, tenant_config: TenantConfig) -> Dict[str, Any]:
        """테넌트별 Prometheus 설정 생성"""
        return {
            "global": {
                "scrape_interval": "15s",
                "external_labels": {
                    "tenant": tenant_config.tenant_id,
                    "tier": tenant_config.tier
                }
            },
            "scrape_configs": [
                {
                    "job_name": "kubernetes-pods",
                    "kubernetes_sd_configs": [
                        {
                            "role": "pod",
                            "namespaces": {
                                "names": [f"monitoring-tenant-{tenant_config.tenant_id}"]
                            }
                        }
                    ],
                    "relabel_configs": [
                        {
                            "source_labels": ["__meta_kubernetes_pod_annotation_prometheus_io_scrape"],
                            "action": "keep",
                            "regex": "true"
                        }
                    ]
                }
            ],
            "remote_write": [
                {
                    "url": "http://prometheus-central:9090/api/v1/write",
                    "write_relabel_configs": [
                        {
                            "source_labels": ["__name__"],
                            "target_label": "tenant",
                            "replacement": tenant_config.tenant_id
                        }
                    ]
                }
            ]
        }
    
    def get_tenant_status(self, tenant_id: str) -> Dict[str, Any]:
        """테넌트 상태 조회"""
        namespace = f"monitoring-tenant-{tenant_id}"
        
        try:
            # 네임스페이스 정보
            ns = self.core_v1.read_namespace(namespace)
            
            # 리소스 사용량
            resource_usage = self._get_tenant_resource_usage(namespace)
            
            # Pod 상태
            pods = self.core_v1.list_namespaced_pod(namespace)
            pod_status = {
                "total": len(pods.items),
                "running": len([p for p in pods.items if p.status.phase == "Running"]),
                "pending": len([p for p in pods.items if p.status.phase == "Pending"]),
                "failed": len([p for p in pods.items if p.status.phase == "Failed"])
            }
            
            return {
                "tenant_id": tenant_id,
                "namespace": namespace,
                "created": ns.metadata.creation_timestamp.isoformat(),
                "tier": ns.metadata.labels.get("monitoring.company.com/tier"),
                "contact": ns.metadata.annotations.get("monitoring.company.com/contact"),
                "resource_usage": resource_usage,
                "pod_status": pod_status,
                "status": "active"
            }
            
        except client.exceptions.ApiException as e:
            if e.status == 404:
                return {"tenant_id": tenant_id, "status": "not_found"}
            else:
                raise
    
    def _get_tenant_resource_usage(self, namespace: str) -> Dict[str, Any]:
        """테넌트 리소스 사용량 조회"""
        # 실제로는 Metrics Server API를 사용하여 실시간 메트릭 조회
        # 여기서는 간단한 예시
        try:
            # ResourceQuota 조회
            quota = self.core_v1.read_namespaced_resource_quota("tenant-quota", namespace)
            
            quota_usage = {}
            if quota.status and quota.status.used:
                quota_usage = {k: v for k, v in quota.status.used.items()}
            
            quota_limits = {}
            if quota.spec and quota.spec.hard:
                quota_limits = {k: v for k, v in quota.spec.hard.items()}
            
            return {
                "quota_usage": quota_usage,
                "quota_limits": quota_limits,
                "usage_percentage": self._calculate_usage_percentage(quota_usage, quota_limits)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _calculate_usage_percentage(self, usage: Dict[str, str], limits: Dict[str, str]) -> Dict[str, float]:
        """사용률 백분율 계산"""
        percentages = {}
        
        for resource in ["requests.cpu", "requests.memory", "pods"]:
            if resource in usage and resource in limits:
                try:
                    used_val = self._parse_resource_value(usage[resource])
                    limit_val = self._parse_resource_value(limits[resource])
                    
                    if limit_val > 0:
                        percentages[resource] = (used_val / limit_val) * 100
                        
                except Exception:
                    percentages[resource] = 0.0
        
        return percentages
    
    def _parse_resource_value(self, value: str) -> float:
        """리소스 값 파싱 (예: "500m" -> 0.5, "2Gi" -> 2147483648)"""
        if value.endswith('m'):
            return float(value[:-1]) / 1000
        elif value.endswith('Gi'):
            return float(value[:-2]) * 1024 * 1024 * 1024
        elif value.endswith('Mi'):
            return float(value[:-2]) * 1024 * 1024
        else:
            return float(value)
    
    def update_tenant_resources(self, tenant_id: str, new_limits: Dict[str, str]) -> bool:
        """테넌트 리소스 한도 업데이트"""
        namespace = f"monitoring-tenant-{tenant_id}"
        
        try:
            # ResourceQuota 업데이트
            quota = self.core_v1.read_namespaced_resource_quota("tenant-quota", namespace)
            
            for resource, limit in new_limits.items():
                if quota.spec.hard and resource in quota.spec.hard:
                    quota.spec.hard[resource] = limit
            
            self.core_v1.patch_namespaced_resource_quota(
                name="tenant-quota",
                namespace=namespace,
                body=quota
            )
            
            print(f"Updated resource limits for tenant {tenant_id}")
            return True
            
        except Exception as e:
            print(f"Failed to update tenant resources: {e}")
            return False
    
    def delete_tenant(self, tenant_id: str, force: bool = False) -> bool:
        """테넌트 삭제"""
        namespace = f"monitoring-tenant-{tenant_id}"
        
        try:
            if not force:
                # 안전 확인 - 실행 중인 워크로드 확인
                pods = self.core_v1.list_namespaced_pod(namespace)
                running_pods = [p for p in pods.items if p.status.phase == "Running"]
                
                if running_pods:
                    print(f"Warning: {len(running_pods)} pods are still running in tenant {tenant_id}")
                    return False
            
            # 네임스페이스 삭제 (모든 리소스가 함께 삭제됨)
            self.core_v1.delete_namespace(namespace)
            
            print(f"Tenant {tenant_id} deleted successfully")
            return True
            
        except client.exceptions.ApiException as e:
            if e.status == 404:
                print(f"Tenant {tenant_id} not found")
                return True
            else:
                print(f"Failed to delete tenant {tenant_id}: {e}")
                return False
    
    def _cleanup_tenant_resources(self, tenant_id: str):
        """테넌트 리소스 정리 (롤백용)"""
        try:
            self.delete_tenant(tenant_id, force=True)
        except Exception as e:
            print(f"Cleanup failed for tenant {tenant_id}: {e}")
```

### 1.2 리소스 할당량 및 제한

**동적 리소스 할당 시스템**
```python
# resource_allocator.py
import math
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import asyncio

@dataclass
class ResourceMetrics:
    cpu_usage: float
    memory_usage: float
    storage_usage: float
    network_io: float
    timestamp: datetime

@dataclass
class ResourceRecommendation:
    resource_type: str
    current_allocation: str
    recommended_allocation: str
    reason: str
    confidence: float
    cost_impact: float

class DynamicResourceAllocator:
    def __init__(self, prometheus_client, tenant_manager):
        self.prometheus = prometheus_client
        self.tenant_manager = tenant_manager
        self.allocation_history = {}
        
        # 리소스 할당 정책
        self.allocation_policies = {
            'conservative': {
                'cpu_threshold': 0.6,
                'memory_threshold': 0.7,
                'scale_up_factor': 1.2,
                'scale_down_factor': 0.8,
                'min_observation_period': 3600  # 1시간
            },
            'aggressive': {
                'cpu_threshold': 0.8,
                'memory_threshold': 0.85,
                'scale_up_factor': 1.5,
                'scale_down_factor': 0.7,
                'min_observation_period': 1800  # 30분
            },
            'balanced': {
                'cpu_threshold': 0.7,
                'memory_threshold': 0.75,
                'scale_up_factor': 1.3,
                'scale_down_factor': 0.75,
                'min_observation_period': 2400  # 40분
            }
        }
    
    async def analyze_tenant_resources(self, tenant_id: str, 
                                     analysis_period: int = 7200) -> List[ResourceRecommendation]:
        """테넌트 리소스 분석 및 권장사항 생성"""
        recommendations = []
        
        # 현재 리소스 할당 조회
        current_allocation = await self._get_current_allocation(tenant_id)
        
        # 리소스 사용 패턴 분석
        usage_patterns = await self._analyze_usage_patterns(tenant_id, analysis_period)
        
        # CPU 분석
        cpu_recommendation = self._analyze_cpu_usage(
            current_allocation['cpu'], usage_patterns['cpu']
        )
        if cpu_recommendation:
            recommendations.append(cpu_recommendation)
        
        # 메모리 분석
        memory_recommendation = self._analyze_memory_usage(
            current_allocation['memory'], usage_patterns['memory']
        )
        if memory_recommendation:
            recommendations.append(memory_recommendation)
        
        # 스토리지 분석
        storage_recommendation = self._analyze_storage_usage(
            current_allocation['storage'], usage_patterns['storage']
        )
        if storage_recommendation:
            recommendations.append(storage_recommendation)
        
        return recommendations
    
    async def _get_current_allocation(self, tenant_id: str) -> Dict[str, str]:
        """현재 리소스 할당 조회"""
        namespace = f"monitoring-tenant-{tenant_id}"
        
        # Kubernetes ResourceQuota에서 현재 할당량 조회
        tenant_status = self.tenant_manager.get_tenant_status(tenant_id)
        
        if 'resource_usage' in tenant_status:
            limits = tenant_status['resource_usage'].get('quota_limits', {})
            return {
                'cpu': limits.get('requests.cpu', '1'),
                'memory': limits.get('requests.memory', '1Gi'),
                'storage': limits.get('requests.storage', '10Gi')
            }
        
        return {'cpu': '1', 'memory': '1Gi', 'storage': '10Gi'}
    
    async def _analyze_usage_patterns(self, tenant_id: str, 
                                    period_seconds: int) -> Dict[str, List[float]]:
        """리소스 사용 패턴 분석"""
        end_time = datetime.now().timestamp()
        start_time = end_time - period_seconds
        
        # CPU 사용률 쿼리
        cpu_query = f'''
            avg(rate(container_cpu_usage_seconds_total{{
                namespace="monitoring-tenant-{tenant_id}"
            }}[5m])) by (pod)
        '''
        
        # 메모리 사용률 쿼리
        memory_query = f'''
            avg(container_memory_usage_bytes{{
                namespace="monitoring-tenant-{tenant_id}"
            }}) by (pod)
        '''
        
        # 스토리지 사용률 쿼리
        storage_query = f'''
            sum(kubelet_volume_stats_used_bytes{{
                namespace="monitoring-tenant-{tenant_id}"
            }}) by (persistentvolumeclaim)
        '''
        
        patterns = {}
        
        for resource, query in [('cpu', cpu_query), ('memory', memory_query), ('storage', storage_query)]:
            try:
                result = self.prometheus.query_range(
                    query=query,
                    start=start_time,
                    end=end_time,
                    step=300  # 5분 간격
                )
                
                # 시계열 데이터를 단일 값 리스트로 변환
                values = []
                for series in result['data']['result']:
                    for timestamp, value in series['values']:
                        if value != 'NaN':
                            values.append(float(value))
                
                patterns[resource] = values
                
            except Exception as e:
                print(f"Failed to query {resource} usage: {e}")
                patterns[resource] = []
        
        return patterns
    
    def _analyze_cpu_usage(self, current_allocation: str, 
                          usage_pattern: List[float]) -> Optional[ResourceRecommendation]:
        """CPU 사용률 분석"""
        if not usage_pattern:
            return None
        
        # 현재 할당량을 CPU 코어 수로 변환
        current_cores = self._parse_cpu_value(current_allocation)
        
        # 사용률 통계 계산
        avg_usage = sum(usage_pattern) / len(usage_pattern)
        max_usage = max(usage_pattern)
        p95_usage = sorted(usage_pattern)[int(len(usage_pattern) * 0.95)]
        
        # 권장사항 결정
        policy = self.allocation_policies['balanced']
        threshold = policy['cpu_threshold']
        
        if p95_usage > threshold * current_cores:
            # 스케일 업 권장
            recommended_cores = math.ceil(p95_usage / threshold)
            recommended_allocation = f"{recommended_cores}"
            
            return ResourceRecommendation(
                resource_type="cpu",
                current_allocation=current_allocation,
                recommended_allocation=recommended_allocation,
                reason=f"P95 usage ({p95_usage:.2f}) exceeds {threshold*100}% of allocation",
                confidence=0.8,
                cost_impact=self._calculate_cost_impact('cpu', current_cores, recommended_cores)
            )
        
        elif max_usage < threshold * 0.5 * current_cores and current_cores > 1:
            # 스케일 다운 권장
            recommended_cores = max(1, math.ceil(max_usage / threshold))
            recommended_allocation = f"{recommended_cores}"
            
            return ResourceRecommendation(
                resource_type="cpu",
                current_allocation=current_allocation,
                recommended_allocation=recommended_allocation,
                reason=f"Max usage ({max_usage:.2f}) is well below allocation",
                confidence=0.7,
                cost_impact=self._calculate_cost_impact('cpu', current_cores, recommended_cores)
            )
        
        return None
    
    def _analyze_memory_usage(self, current_allocation: str, 
                            usage_pattern: List[float]) -> Optional[ResourceRecommendation]:
        """메모리 사용률 분석"""
        if not usage_pattern:
            return None
        
        # 현재 할당량을 바이트로 변환
        current_bytes = self._parse_memory_value(current_allocation)
        
        # 사용률 통계 계산
        avg_usage = sum(usage_pattern) / len(usage_pattern)
        max_usage = max(usage_pattern)
        p95_usage = sorted(usage_pattern)[int(len(usage_pattern) * 0.95)]
        
        # 권장사항 결정
        policy = self.allocation_policies['balanced']
        threshold = policy['memory_threshold']
        
        if p95_usage > threshold * current_bytes:
            # 스케일 업 권장
            recommended_bytes = int(p95_usage / threshold * 1.2)  # 20% 버퍼
            recommended_allocation = self._format_memory_value(recommended_bytes)
            
            return ResourceRecommendation(
                resource_type="memory",
                current_allocation=current_allocation,
                recommended_allocation=recommended_allocation,
                reason=f"P95 usage exceeds {threshold*100}% of allocation",
                confidence=0.85,
                cost_impact=self._calculate_cost_impact('memory', current_bytes, recommended_bytes)
            )
        
        elif max_usage < threshold * 0.6 * current_bytes:
            # 스케일 다운 권장
            recommended_bytes = int(max_usage / threshold * 1.3)  # 30% 버퍼
            recommended_allocation = self._format_memory_value(recommended_bytes)
            
            return ResourceRecommendation(
                resource_type="memory",
                current_allocation=current_allocation,
                recommended_allocation=recommended_allocation,
                reason=f"Max usage is well below allocation",
                confidence=0.75,
                cost_impact=self._calculate_cost_impact('memory', current_bytes, recommended_bytes)
            )
        
        return None
    
    def _parse_cpu_value(self, cpu_str: str) -> float:
        """CPU 문자열을 숫자로 변환"""
        if cpu_str.endswith('m'):
            return float(cpu_str[:-1]) / 1000
        else:
            return float(cpu_str)
    
    def _parse_memory_value(self, memory_str: str) -> int:
        """메모리 문자열을 바이트로 변환"""
        if memory_str.endswith('Gi'):
            return int(float(memory_str[:-2]) * 1024 * 1024 * 1024)
        elif memory_str.endswith('Mi'):
            return int(float(memory_str[:-2]) * 1024 * 1024)
        elif memory_str.endswith('G'):
            return int(float(memory_str[:-1]) * 1000 * 1000 * 1000)
        elif memory_str.endswith('M'):
            return int(float(memory_str[:-1]) * 1000 * 1000)
        else:
            return int(memory_str)
    
    def _format_memory_value(self, bytes_value: int) -> str:
        """바이트를 메모리 문자열로 변환"""
        if bytes_value >= 1024 * 1024 * 1024:
            return f"{bytes_value / (1024 * 1024 * 1024):.1f}Gi"
        elif bytes_value >= 1024 * 1024:
            return f"{bytes_value / (1024 * 1024):.1f}Mi"
        else:
            return f"{bytes_value}"
    
    def _calculate_cost_impact(self, resource_type: str, current: float, recommended: float) -> float:
        """비용 영향 계산"""
        # 간단한 비용 모델 (실제로는 클라우드 프로바이더별 가격 적용)
        cost_per_unit = {
            'cpu': 0.05,  # $0.05 per vCPU hour
            'memory': 0.01  # $0.01 per GB hour
        }
        
        if resource_type in cost_per_unit:
            if resource_type == 'memory':
                current = current / (1024 * 1024 * 1024)  # 바이트를 GB로 변환
                recommended = recommended / (1024 * 1024 * 1024)
            
            hourly_cost_change = (recommended - current) * cost_per_unit[resource_type]
            monthly_cost_change = hourly_cost_change * 24 * 30
            
            return monthly_cost_change
        
        return 0.0
    
    async def apply_recommendations(self, tenant_id: str, 
                                  recommendations: List[ResourceRecommendation],
                                  auto_apply: bool = False) -> Dict[str, Any]:
        """권장사항 적용"""
        results = {
            'tenant_id': tenant_id,
            'applied_changes': [],
            'failed_changes': [],
            'total_cost_impact': 0.0
        }
        
        for recommendation in recommendations:
            if auto_apply or recommendation.confidence > 0.8:
                try:
                    # 리소스 할당 업데이트
                    resource_map = {
                        'cpu': 'requests.cpu',
                        'memory': 'requests.memory',
                        'storage': 'requests.storage'
                    }
                    
                    resource_key = resource_map.get(recommendation.resource_type)
                    if resource_key:
                        success = self.tenant_manager.update_tenant_resources(
                            tenant_id,
                            {resource_key: recommendation.recommended_allocation}
                        )
                        
                        if success:
                            results['applied_changes'].append(recommendation)
                            results['total_cost_impact'] += recommendation.cost_impact
                        else:
                            results['failed_changes'].append(recommendation)
                            
                except Exception as e:
                    print(f"Failed to apply recommendation: {e}")
                    results['failed_changes'].append(recommendation)
            else:
                # 신뢰도가 낮은 경우 수동 검토 대기
                results['failed_changes'].append(recommendation)
        
        return results
```

## 2. 거버넌스 및 표준

### 2.1 모니터링 표준 및 모범 사례

**모니터링 거버넌스 프레임워크**
```python
# monitoring_governance.py
import yaml
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import re

@dataclass
class MonitoringStandard:
    standard_id: str
    category: str
    title: str
    description: str
    requirements: List[str]
    validation_rules: List[Dict[str, Any]]
    compliance_level: str  # mandatory, recommended, optional
    created_by: str
    created_at: datetime
    last_updated: datetime

@dataclass
class ComplianceCheckResult:
    standard_id: str
    tenant_id: str
    check_type: str
    status: str  # compliant, non_compliant, warning
    details: str
    remediation_steps: List[str]
    checked_at: datetime

class MonitoringGovernanceFramework:
    def __init__(self):
        self.standards = {}
        self.compliance_history = {}
        self.exemptions = {}
        
        # 기본 모니터링 표준 로드
        self._load_default_standards()
    
    def _load_default_standards(self):
        """기본 모니터링 표준 로드"""
        
        # 메트릭 명명 규칙
        metric_naming_standard = MonitoringStandard(
            standard_id="METRIC_NAMING_001",
            category="metrics",
            title="메트릭 명명 규칙",
            description="일관된 메트릭 명명 규칙을 통한 표준화",
            requirements=[
                "메트릭 이름은 소문자와 언더스코어만 사용",
                "메트릭 이름은 관련 도메인으로 시작 (예: http_, database_, cache_)",
                "카운터 메트릭은 _total 접미사 사용",
                "히스토그램 메트릭은 적절한 버킷 범위 정의"
            ],
            validation_rules=[
                {
                    "rule_type": "regex",
                    "pattern": "^[a-z][a-z0-9_]*[a-z0-9]$",
                    "field": "metric_name",
                    "error_message": "메트릭 이름은 소문자와 언더스코어만 사용해야 합니다"
                },
                {
                    "rule_type": "suffix_check",
                    "metric_type": "counter",
                    "required_suffix": "_total",
                    "error_message": "카운터 메트릭은 _total 접미사가 필요합니다"
                }
            ],
            compliance_level="mandatory",
            created_by="governance-team",
            created_at=datetime.now(),
            last_updated=datetime.now()
        )
        
        # 라벨 사용 규칙
        label_usage_standard = MonitoringStandard(
            standard_id="LABEL_USAGE_001",
            category="labels",
            title="라벨 사용 규칙",
            description="효율적이고 일관된 라벨 사용을 위한 규칙",
            requirements=[
                "라벨 키는 소문자와 언더스코어만 사용",
                "높은 카디널리티 라벨 사용 금지 (예: 사용자 ID, 세션 ID)",
                "필수 라벨: service, environment, version",
                "라벨 값은 공백이나 특수문자 사용 금지"
            ],
            validation_rules=[
                {
                    "rule_type": "required_labels",
                    "required": ["service", "environment", "version"],
                    "error_message": "필수 라벨이 누락되었습니다"
                },
                {
                    "rule_type": "cardinality_check",
                    "max_cardinality": 1000,
                    "error_message": "라벨 카디널리티가 너무 높습니다"
                }
            ],
            compliance_level="mandatory",
            created_by="governance-team",
            created_at=datetime.now(),
            last_updated=datetime.now()
        )
        
        # 알림 규칙 표준
        alerting_standard = MonitoringStandard(
            standard_id="ALERTING_001",
            category="alerting",
            title="알림 규칙 표준",
            description="효과적인 알림을 위한 규칙 작성 표준",
            requirements=[
                "모든 알림에는 severity 라벨 필수",
                "알림 설명(annotation)에는 문제 해결 방법 포함",
                "중복 알림 방지를 위한 적절한 그룹화",
                "알림 임계값은 과거 데이터 기반으로 설정"
            ],
            validation_rules=[
                {
                    "rule_type": "required_annotation",
                    "required": ["summary", "description", "runbook_url"],
                    "error_message": "필수 annotation이 누락되었습니다"
                },
                {
                    "rule_type": "severity_check",
                    "valid_severities": ["critical", "warning", "info"],
                    "error_message": "유효하지 않은 severity 레벨입니다"
                }
            ],
            compliance_level="mandatory",
            created_by="governance-team",
            created_at=datetime.now(),
            last_updated=datetime.now()
        )
        
        # 대시보드 표준
        dashboard_standard = MonitoringStandard(
            standard_id="DASHBOARD_001",
            category="dashboards",
            title="대시보드 작성 표준",
            description="일관되고 효과적인 대시보드 작성을 위한 표준",
            requirements=[
                "대시보드 제목과 설명 필수",
                "패널별 명확한 제목과 단위 표시",
                "색상 사용 일관성 (빨강: 에러, 노랑: 경고, 녹색: 정상)",
                "시간 범위 변수 제공"
            ],
            validation_rules=[
                {
                    "rule_type": "title_check",
                    "min_length": 10,
                    "error_message": "대시보드 제목이 너무 짧습니다"
                },
                {
                    "rule_type": "panel_validation",
                    "required_fields": ["title", "unit"],
                    "error_message": "패널에 필수 필드가 누락되었습니다"
                }
            ],
            compliance_level="recommended",
            created_by="governance-team",
            created_at=datetime.now(),
            last_updated=datetime.now()
        )
        
        # 표준 등록
        for standard in [metric_naming_standard, label_usage_standard, 
                        alerting_standard, dashboard_standard]:
            self.standards[standard.standard_id] = standard
    
    def add_custom_standard(self, standard: MonitoringStandard) -> bool:
        """커스텀 모니터링 표준 추가"""
        try:
            # 표준 ID 중복 확인
            if standard.standard_id in self.standards:
                print(f"Standard {standard.standard_id} already exists")
                return False
            
            # 검증 규칙 유효성 확인
            if not self._validate_standard_rules(standard):
                print(f"Invalid validation rules in standard {standard.standard_id}")
                return False
            
            self.standards[standard.standard_id] = standard
            print(f"Added custom standard: {standard.standard_id}")
            return True
            
        except Exception as e:
            print(f"Failed to add standard: {e}")
            return False
    
    def _validate_standard_rules(self, standard: MonitoringStandard) -> bool:
        """표준의 검증 규칙 유효성 확인"""
        required_fields = ["rule_type", "error_message"]
        
        for rule in standard.validation_rules:
            for field in required_fields:
                if field not in rule:
                    return False
        
        return True
    
    def check_tenant_compliance(self, tenant_id: str, 
                              check_categories: List[str] = None) -> List[ComplianceCheckResult]:
        """테넌트 컴플라이언스 검사"""
        results = []
        
        # 검사할 카테고리 필터링
        standards_to_check = self.standards.values()
        if check_categories:
            standards_to_check = [
                s for s in standards_to_check 
                if s.category in check_categories
            ]
        
        for standard in standards_to_check:
            # 필수 표준만 강제 검사
            if standard.compliance_level == "optional":
                continue
                
            result = self._check_standard_compliance(tenant_id, standard)
            results.append(result)
        
        # 컴플라이언스 히스토리 업데이트
        self.compliance_history[tenant_id] = {
            'last_check': datetime.now(),
            'results': results
        }
        
        return results
    
    def _check_standard_compliance(self, tenant_id: str, 
                                 standard: MonitoringStandard) -> ComplianceCheckResult:
        """개별 표준 컴플라이언스 검사"""
        
        if standard.category == "metrics":
            return self._check_metric_compliance(tenant_id, standard)
        elif standard.category == "labels":
            return self._check_label_compliance(tenant_id, standard)
        elif standard.category == "alerting":
            return self._check_alerting_compliance(tenant_id, standard)
        elif standard.category == "dashboards":
            return self._check_dashboard_compliance(tenant_id, standard)
        else:
            return ComplianceCheckResult(
                standard_id=standard.standard_id,
                tenant_id=tenant_id,
                check_type="unknown",
                status="warning",
                details=f"Unknown standard category: {standard.category}",
                remediation_steps=["Define check implementation for this category"],
                checked_at=datetime.now()
            )
    
    def _check_metric_compliance(self, tenant_id: str, 
                               standard: MonitoringStandard) -> ComplianceCheckResult:
        """메트릭 표준 컴플라이언스 검사"""
        # 실제로는 Prometheus API를 통해 테넌트의 메트릭 조회
        # 여기서는 간단한 예시
        
        violations = []
        
        # 예시: 테넌트의 메트릭 목록 조회 (실제 구현 필요)
        tenant_metrics = self._get_tenant_metrics(tenant_id)
        
        for metric_name in tenant_metrics:
            # 메트릭 명명 규칙 검사
            for rule in standard.validation_rules:
                if rule["rule_type"] == "regex":
                    pattern = rule["pattern"]
                    if not re.match(pattern, metric_name):
                        violations.append(f"Metric '{metric_name}': {rule['error_message']}")
                
                elif rule["rule_type"] == "suffix_check":
                    # 카운터 메트릭 접미사 검사 (실제로는 메트릭 타입 확인 필요)
                    if "_total" in metric_name and not metric_name.endswith("_total"):
                        violations.append(f"Metric '{metric_name}': {rule['error_message']}")
        
        if violations:
            return ComplianceCheckResult(
                standard_id=standard.standard_id,
                tenant_id=tenant_id,
                check_type="metrics",
                status="non_compliant",
                details=f"Found {len(violations)} violations: " + "; ".join(violations[:3]),
                remediation_steps=[
                    "메트릭 이름을 규칙에 맞게 수정",
                    "카운터 메트릭에 _total 접미사 추가",
                    "메트릭 명명 가이드 문서 참조"
                ],
                checked_at=datetime.now()
            )
        else:
            return ComplianceCheckResult(
                standard_id=standard.standard_id,
                tenant_id=tenant_id,
                check_type="metrics",
                status="compliant",
                details="All metrics comply with naming standards",
                remediation_steps=[],
                checked_at=datetime.now()
            )
    
    def _check_label_compliance(self, tenant_id: str, 
                              standard: MonitoringStandard) -> ComplianceCheckResult:
        """라벨 표준 컴플라이언스 검사"""
        violations = []
        
        # 테넌트의 라벨 사용 현황 분석 (실제 구현 필요)
        label_analysis = self._analyze_tenant_labels(tenant_id)
        
        for rule in standard.validation_rules:
            if rule["rule_type"] == "required_labels":
                required_labels = rule["required"]
                missing_labels = set(required_labels) - set(label_analysis.get("common_labels", []))
                
                if missing_labels:
                    violations.append(f"Missing required labels: {', '.join(missing_labels)}")
            
            elif rule["rule_type"] == "cardinality_check":
                max_cardinality = rule["max_cardinality"]
                high_cardinality_labels = [
                    label for label, cardinality in label_analysis.get("cardinality", {}).items()
                    if cardinality > max_cardinality
                ]
                
                if high_cardinality_labels:
                    violations.append(f"High cardinality labels: {', '.join(high_cardinality_labels)}")
        
        status = "non_compliant" if violations else "compliant"
        details = "; ".join(violations) if violations else "All labels comply with standards"
        
        return ComplianceCheckResult(
            standard_id=standard.standard_id,
            tenant_id=tenant_id,
            check_type="labels",
            status=status,
            details=details,
            remediation_steps=[
                "필수 라벨 추가",
                "높은 카디널리티 라벨 제거 또는 수정",
                "라벨 사용 가이드 문서 참조"
            ] if violations else [],
            checked_at=datetime.now()
        )
    
    def _get_tenant_metrics(self, tenant_id: str) -> List[str]:
        """테넌트의 메트릭 목록 조회 (실제 구현 필요)"""
        # 실제로는 Prometheus API를 통해 조회
        return [
            "http_requests_total",
            "http_request_duration_seconds",
            "database_connections_active",
            "cache_hits_total",
            "error_rate"  # 규칙 위반 예시
        ]
    
    def _analyze_tenant_labels(self, tenant_id: str) -> Dict[str, Any]:
        """테넌트 라벨 분석 (실제 구현 필요)"""
        # 실제로는 Prometheus API를 통해 라벨 분석
        return {
            "common_labels": ["service", "environment"],  # version 라벨 누락
            "cardinality": {
                "service": 5,
                "environment": 3,
                "user_id": 15000  # 높은 카디널리티
            }
        }
    
    def generate_compliance_report(self, tenant_id: str = None) -> Dict[str, Any]:
        """컴플라이언스 보고서 생성"""
        if tenant_id:
            # 특정 테넌트 보고서
            return self._generate_tenant_compliance_report(tenant_id)
        else:
            # 전체 테넌트 보고서
            return self._generate_global_compliance_report()
    
    def _generate_tenant_compliance_report(self, tenant_id: str) -> Dict[str, Any]:
        """테넌트별 컴플라이언스 보고서"""
        if tenant_id not in self.compliance_history:
            return {"error": f"No compliance data for tenant {tenant_id}"}
        
        history = self.compliance_history[tenant_id]
        results = history["results"]
        
        compliance_summary = {
            "compliant": len([r for r in results if r.status == "compliant"]),
            "non_compliant": len([r for r in results if r.status == "non_compliant"]),
            "warnings": len([r for r in results if r.status == "warning"])
        }
        
        total_checks = len(results)
        compliance_percentage = (compliance_summary["compliant"] / total_checks * 100) if total_checks > 0 else 0
        
        return {
            "tenant_id": tenant_id,
            "last_check": history["last_check"].isoformat(),
            "compliance_percentage": compliance_percentage,
            "summary": compliance_summary,
            "details": [asdict(result) for result in results],
            "recommendations": self._generate_tenant_recommendations(results)
        }
    
    def _generate_tenant_recommendations(self, results: List[ComplianceCheckResult]) -> List[str]:
        """테넌트별 권장사항 생성"""
        recommendations = []
        
        non_compliant_results = [r for r in results if r.status == "non_compliant"]
        
        if non_compliant_results:
            # 우선순위별 권장사항
            for result in non_compliant_results:
                standard = self.standards.get(result.standard_id)
                if standard and standard.compliance_level == "mandatory":
                    recommendations.extend(result.remediation_steps)
        
        # 중복 제거
        return list(set(recommendations))
    
    def create_exemption(self, tenant_id: str, standard_id: str, 
                        reason: str, expires_at: datetime) -> bool:
        """컴플라이언스 예외 생성"""
        try:
            exemption_key = f"{tenant_id}:{standard_id}"
            
            self.exemptions[exemption_key] = {
                "tenant_id": tenant_id,
                "standard_id": standard_id,
                "reason": reason,
                "created_at": datetime.now(),
                "expires_at": expires_at,
                "created_by": "governance-admin"  # 실제로는 현재 사용자
            }
            
            print(f"Created exemption for tenant {tenant_id}, standard {standard_id}")
            return True
            
        except Exception as e:
            print(f"Failed to create exemption: {e}")
            return False
    
    def is_exempted(self, tenant_id: str, standard_id: str) -> bool:
        """예외 여부 확인"""
        exemption_key = f"{tenant_id}:{standard_id}"
        
        if exemption_key in self.exemptions:
            exemption = self.exemptions[exemption_key]
            
            # 만료 시간 확인
            if datetime.now() < exemption["expires_at"]:
                return True
            else:
                # 만료된 예외 제거
                del self.exemptions[exemption_key]
        
        return False
```

## 3. 실습 과제

### 과제 1: 멀티 테넌트 시스템 구축
1. Kubernetes 기반 테넌트 격리 구현
2. 티어별 리소스 할당 시스템
3. 동적 리소스 스케일링 구현

### 과제 2: 거버넌스 프레임워크 구축
1. 모니터링 표준 정의 및 검증 시스템
2. 자동화된 컴플라이언스 검사
3. 셀프 서비스 대시보드 템플릿

### 과제 3: 비용 관리 시스템
1. 테넌트별 비용 추적 및 할당
2. 리소스 사용량 기반 최적화 권장
3. 예산 알림 및 제한 시스템

## 4. 다음 단계
- 성능 최적화 및 비용 관리 (Phase 5-2)
- 통합 생태계 (Phase 5-3)