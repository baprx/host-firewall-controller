# host-firewall-controller

Kubernetes operator that manages UFW rules on every node from HostFirewallRule custom resources, without ever touching unmanaged rules or the global UFW state.

![Version: 0.6.0](https://img.shields.io/badge/Version-0.6.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.5.0](https://img.shields.io/badge/AppVersion-0.5.0-informational?style=flat-square)

## Requirements

Kubernetes: `>=1.31.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| commonLabels | object | `{}` | Labels added to every resource. |
| defaultRefreshInterval | string | `"5m"` | Hostname refresh interval for rules that do not set spec.resolve.refreshInterval. |
| dryRun | bool | `false` | Log the ufw commands instead of running them. Nothing is written to a host while this is true. |
| extraArgs | list | `[]` | Extra raw flags appended to the manager. |
| extraObjects | list | `[]` | Arbitrary Kubernetes manifests appended to the release. Each item is a manifest map rendered with tpl, so it can reference release values and chart helpers with {{ ... }}. |
| fullnameOverride | string | `""` | Override the full release name used in resource names. |
| healthProbe | object | `{"bindAddress":":8081","port":8081}` | Health probe server settings. |
| healthProbe.bindAddress | string | `":8081"` | Address the health probe server binds to. |
| healthProbe.port | int | `8081` | Container port used by the probes. |
| hostRoot | string | `"/host"` | Path where the host root filesystem is mounted inside the pod. |
| image | object | `{"pullPolicy":"IfNotPresent","repository":"ghcr.io/baprx/host-firewall-controller","tag":""}` | Container image settings. |
| image.pullPolicy | string | `"IfNotPresent"` | Container image pull policy. |
| image.repository | string | `"ghcr.io/baprx/host-firewall-controller"` | Container image repository. |
| image.tag | string | `""` | Container image tag. Defaults to .Chart.AppVersion when empty. |
| imagePullSecrets | list | `[]` | Secrets used to pull the image from a private registry. |
| knock | object | `{"bindAddress":":8082","enabled":false,"httpRoute":{"annotations":{},"enabled":false,"hostnames":[],"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"parentRefs":[]},"ingress":{"annotations":{},"className":"","enabled":false,"hosts":[{"host":"knock.example.com","paths":[{"path":"/","pathType":"Prefix"}]}],"tls":[]},"listenerSet":{"annotations":{},"enabled":false,"listeners":[],"parentRef":{}},"port":8082,"service":{"annotations":{},"enabled":false,"externalTrafficPolicy":"Local","type":"ClusterIP"},"trustedProxies":[]}` | HTTP endpoint that lets a rule update its dynamic endpoint from the caller's source IP. |
| knock.bindAddress | string | `":8082"` | Address the knock server binds to. |
| knock.enabled | bool | `false` | Expose the knock endpoint on every node. |
| knock.httpRoute | object | `{"annotations":{},"enabled":false,"hostnames":[],"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"parentRefs":[]}` | Gateway API HTTPRoute exposing the knock endpoint. Mutually exclusive with knock.ingress. |
| knock.httpRoute.annotations | object | `{}` | Annotations added to the HTTPRoute. |
| knock.httpRoute.enabled | bool | `false` | Create an HTTPRoute for the knock Service. |
| knock.httpRoute.hostnames | list | `[]` | Hostnames the HTTPRoute matches. |
| knock.httpRoute.matches | list | `[{"path":{"type":"PathPrefix","value":"/"}}]` | Matches for the HTTPRoute. The whole list forms one rule, so multiple entries are ANDed by the Gateway API. |
| knock.httpRoute.parentRefs | list | `[]` | Gateway parent references. Defaults to the ListenerSet when knock.listenerSet.enabled is true and this list is empty. |
| knock.ingress | object | `{"annotations":{},"className":"","enabled":false,"hosts":[{"host":"knock.example.com","paths":[{"path":"/","pathType":"Prefix"}]}],"tls":[]}` | Ingress exposing the knock endpoint. Mutually exclusive with knock.httpRoute. |
| knock.ingress.annotations | object | `{}` | Annotations added to the Ingress. |
| knock.ingress.className | string | `""` | Ingress class name. Defaults to the cluster default class when empty. |
| knock.ingress.enabled | bool | `false` | Create an Ingress for the knock Service. |
| knock.ingress.hosts | list | `[{"host":"knock.example.com","paths":[{"path":"/","pathType":"Prefix"}]}]` | Ingress hosts and their paths. |
| knock.ingress.tls | list | `[]` | TLS settings for the Ingress. |
| knock.listenerSet | object | `{"annotations":{},"enabled":false,"listeners":[],"parentRef":{}}` | Gateway API ListenerSet that carries the knock listener. Enable it to attach the HTTPRoute to a listener instead of attaching it to the Gateway directly. |
| knock.listenerSet.annotations | object | `{}` | Annotations added to the ListenerSet, for example cert-manager and external-dns annotations. |
| knock.listenerSet.enabled | bool | `false` | Create a ListenerSet for the knock Service. |
| knock.listenerSet.listeners | list | `[]` | Listeners of the ListenerSet, as Gateway API listener objects. When the HTTPRoute has no parentRefs, the chart attaches it to this ListenerSet. |
| knock.listenerSet.parentRef | object | `{}` | Parent Gateway reference of the ListenerSet, for example {name: my-gateway, namespace: gateway-system}. The Gateway API defaults group and kind when they are empty. |
| knock.port | int | `8082` | Host and container port for the knock endpoint. The chart does not add a ufw rule for this port; allow it in the host firewall when the firewall is default-deny. |
| knock.service | object | `{"annotations":{},"enabled":false,"externalTrafficPolicy":"Local","type":"ClusterIP"}` | Service exposing the knock endpoint. |
| knock.service.annotations | object | `{}` | Annotations added to the knock Service. |
| knock.service.enabled | bool | `false` | Create a Service for the knock endpoint. |
| knock.service.externalTrafficPolicy | string | `"Local"` | Route traffic to node-local pods only. Local preserves the client source IP, which is the address a knock allows. Only rendered for NodePort and LoadBalancer Services. |
| knock.service.type | string | `"ClusterIP"` | Service type. |
| knock.trustedProxies | list | `[]` | CIDRs allowed to set X-Forwarded-For. |
| lockPath | string | `""` | Host-wide ufw lock file. Defaults to <hostRoot>/run/host-firewall-controller.lock. |
| maxAddresses | int | `16` | Maximum number of addresses used per hostname by default. |
| maxRulesPerCR | int | `64` | Maximum number of concrete rules one HostFirewallRule may expand to. |
| maxRulesPerNode | int | `256` | Stop converging on a node that would exceed this many managed rules. |
| metrics | object | `{"bindAddress":":8080","enabled":true,"port":8080,"service":{"enabled":true,"type":"ClusterIP"},"serviceMonitor":{"enabled":false,"interval":"30s","labels":{},"scrapeTimeout":"10s"}}` | Prometheus metrics settings. |
| metrics.bindAddress | string | `":8080"` | Address the metrics server binds to. |
| metrics.enabled | bool | `true` | Expose Prometheus metrics. |
| metrics.port | int | `8080` | Container and Service port for metrics. |
| metrics.service.enabled | bool | `true` | Create a Service for the metrics endpoint. |
| metrics.service.type | string | `"ClusterIP"` | Service type. |
| metrics.serviceMonitor.enabled | bool | `false` | Create a ServiceMonitor for the metrics Service. |
| metrics.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| metrics.serviceMonitor.labels | object | `{}` | Extra labels for the ServiceMonitor. |
| metrics.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout. |
| minRefreshInterval | string | `"30s"` | Floor applied to per-rule refresh intervals. |
| nameOverride | string | `""` | Override the chart name used in resource names. |
| nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Nodes that receive the DaemonSet pods. Linux is required. |
| podAnnotations | object | `{}` | Annotations added to the DaemonSet pods. |
| podLabels | object | `{}` | Labels added to the DaemonSet pods. |
| priorityClassName | string | `"system-node-critical"` | Priority class of the DaemonSet pods. |
| rbac | object | `{"create":true}` | RBAC settings. |
| rbac.create | bool | `true` | Create the ClusterRole and ClusterRoleBinding. |
| resources | object | `{}` | Resource requests and limits for the manager container. |
| rules | object | `{}` | HostFirewallRule resources keyed by their name. Each value is the rule spec, passed through to the CRD verbatim, so any field the operator supports can be set here. A rule applies to every node unless its spec sets nodeSelector. Nothing is applied to a host while dryRun is true. |
| securityContext | object | `{"allowPrivilegeEscalation":true,"privileged":true,"readOnlyRootFilesystem":false,"runAsGroup":0,"runAsUser":0}` | Security context of the manager container. chroot and ufw require privileges, and ufw must write root-owned files inside the host root. |
| securityContext.allowPrivilegeEscalation | bool | `true` | Allow the container to gain privileges. |
| securityContext.privileged | bool | `true` | Run the container privileged. |
| securityContext.readOnlyRootFilesystem | bool | `false` | Keep the container filesystem writable. |
| securityContext.runAsGroup | int | `0` | Group ID the container runs as. |
| securityContext.runAsUser | int | `0` | User ID the container runs as. |
| serviceAccount | object | `{"annotations":{},"create":true,"name":""}` | ServiceAccount settings. |
| serviceAccount.annotations | object | `{}` | Annotations added to the ServiceAccount. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount for the manager. |
| serviceAccount.name | string | `""` | ServiceAccount name. Defaults to the full release name when empty. |
| sweepInterval | string | `"5m"` | How often orphaned rules are pruned from a node. |
| terminationGracePeriodSeconds | int | `60` | Time given to an in-flight ufw command before the pod is terminated. |
| tolerations | list | `[{"operator":"Exists"}]` | Tolerations for the DaemonSet pods. The default runs on every node, including control planes. |
| ufwPath | string | `"/usr/sbin/ufw"` | Path of the ufw binary inside the host root. |
| updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | DaemonSet rollout strategy. |
| updateStrategy.rollingUpdate | object | `{"maxUnavailable":1}` | Rolling update settings. |
| updateStrategy.rollingUpdate.maxUnavailable | int | `1` | Maximum number of pods unavailable during a rollout. |
| updateStrategy.type | string | `"RollingUpdate"` | Update strategy type. |
