# host-firewall-controller

Kubernetes operator that manages UFW rules on every node from HostFirewallRule custom resources, without ever touching unmanaged rules or the global UFW state.

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

## Requirements

Kubernetes: `>=1.29.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| allowMissingUFW | bool | `false` |  |
| commonLabels | object | `{}` |  |
| defaultRefreshInterval | string | `"5m"` |  |
| dryRun | bool | `false` |  |
| extraArgs | list | `[]` |  |
| fullnameOverride | string | `""` |  |
| healthProbe.bindAddress | string | `":8081"` |  |
| healthProbe.port | int | `8081` |  |
| hostRoot | string | `"/host"` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/baprx/host-firewall-controller"` |  |
| image.tag | string | `""` |  |
| imagePullSecrets | list | `[]` |  |
| lockPath | string | `""` |  |
| maxAddresses | int | `16` |  |
| maxRulesPerCR | int | `64` |  |
| maxRulesPerNode | int | `256` |  |
| metrics.bindAddress | string | `":8080"` |  |
| metrics.enabled | bool | `true` |  |
| metrics.port | int | `8080` |  |
| metrics.service.enabled | bool | `true` |  |
| metrics.service.type | string | `"ClusterIP"` |  |
| metrics.serviceMonitor.enabled | bool | `false` |  |
| metrics.serviceMonitor.interval | string | `"30s"` |  |
| metrics.serviceMonitor.labels | object | `{}` |  |
| metrics.serviceMonitor.scrapeTimeout | string | `"10s"` |  |
| minRefreshInterval | string | `"30s"` |  |
| nameOverride | string | `""` |  |
| nodeSelector."kubernetes.io/os" | string | `"linux"` |  |
| podAnnotations | object | `{}` |  |
| podLabels | object | `{}` |  |
| priorityClassName | string | `"system-node-critical"` |  |
| rbac.create | bool | `true` |  |
| resources | object | `{}` |  |
| securityContext.allowPrivilegeEscalation | bool | `true` |  |
| securityContext.privileged | bool | `true` |  |
| securityContext.readOnlyRootFilesystem | bool | `false` |  |
| securityContext.runAsGroup | int | `0` |  |
| securityContext.runAsUser | int | `0` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| sweepInterval | string | `"5m"` |  |
| terminationGracePeriodSeconds | int | `60` |  |
| tolerations[0].operator | string | `"Exists"` |  |
| ufwPath | string | `"/usr/sbin/ufw"` |  |
| updateStrategy.rollingUpdate.maxUnavailable | int | `1` |  |
| updateStrategy.type | string | `"RollingUpdate"` |  |
