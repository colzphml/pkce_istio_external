{{- define "oidc-auth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oidc-auth.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "oidc-auth.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.labels" -}}
app.kubernetes.io/name: {{ include "oidc-auth.name" . }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "oidc-auth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "oidc-auth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "oidc-auth.serviceAccountName" -}}
{{- if .Values.authService.serviceAccount.create -}}
{{- default (include "oidc-auth.fullname" .) .Values.authService.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.authService.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.oidcSecretName" -}}
{{- if .Values.authService.config.oidc.existingSecret -}}
{{- .Values.authService.config.oidc.existingSecret -}}
{{- else -}}
{{- printf "%s-oidc" (include "oidc-auth.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisFullname" -}}
{{- if .Values.redis.fullnameOverride -}}
{{- .Values.redis.fullnameOverride -}}
{{- else -}}
{{- printf "%s-redis" .Release.Name -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisMode" -}}
{{- if .Values.authService.config.redis.mode -}}
{{- .Values.authService.config.redis.mode -}}
{{- else if and .Values.redis.enabled .Values.redis.sentinel.enabled -}}
sentinel
{{- else -}}
standalone
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisAddresses" -}}
{{- if .Values.authService.config.redis.addresses -}}
{{- join "," .Values.authService.config.redis.addresses -}}
{{- else if and .Values.redis.enabled .Values.redis.sentinel.enabled -}}
{{- printf "%s.%s.svc.cluster.local:%v" (include "oidc-auth.redisFullname" .) .Release.Namespace (.Values.redis.sentinel.service.ports.sentinel | default 26379) -}}
{{- else if .Values.redis.enabled -}}
{{- printf "%s-master.%s.svc.cluster.local:%v" (include "oidc-auth.redisFullname" .) .Release.Namespace (.Values.redis.master.service.ports.redis | default 6379) -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisPasswordSecretName" -}}
{{- if .Values.authService.config.redis.existingPasswordSecret -}}
{{- .Values.authService.config.redis.existingPasswordSecret -}}
{{- else if and .Values.redis.enabled .Values.redis.auth.acl.enabled -}}
{{- if .Values.redis.auth.acl.userSecret -}}
{{- .Values.redis.auth.acl.userSecret -}}
{{- else -}}
{{- printf "%s-redis-acl" (include "oidc-auth.fullname" .) -}}
{{- end -}}
{{- else if and .Values.redis.enabled .Values.redis.auth.existingSecret -}}
{{- .Values.redis.auth.existingSecret -}}
{{- else if .Values.redis.enabled -}}
{{- include "oidc-auth.redisFullname" . -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisPasswordSecretKey" -}}
{{- if .Values.authService.config.redis.existingPasswordSecret -}}
{{- .Values.authService.config.redis.existingPasswordSecretKey -}}
{{- else if and .Values.redis.enabled .Values.redis.auth.acl.enabled -}}
{{- .Values.authService.config.redis.username -}}
{{- else if and .Values.redis.enabled .Values.redis.auth.existingSecret -}}
{{- default "redis-password" .Values.redis.auth.existingSecretPasswordKey -}}
{{- else if .Values.redis.enabled -}}
redis-password
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisSentinelPasswordSecretName" -}}
{{- if .Values.authService.config.redis.existingSentinelPasswordSecret -}}
{{- .Values.authService.config.redis.existingSentinelPasswordSecret -}}
{{- else -}}
{{- include "oidc-auth.redisPasswordSecretName" . -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisSentinelPasswordSecretKey" -}}
{{- if .Values.authService.config.redis.existingSentinelPasswordSecret -}}
{{- .Values.authService.config.redis.existingSentinelPasswordSecretKey -}}
{{- else -}}
{{- include "oidc-auth.redisPasswordSecretKey" . -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisTLSSecretName" -}}
{{- if .Values.authService.config.redis.tls.existingSecret -}}
{{- .Values.authService.config.redis.tls.existingSecret -}}
{{- else if and .Values.redis.enabled .Values.redis.tls.enabled -}}
{{- if .Values.redis.tls.existingSecret -}}
{{- .Values.redis.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-crt" (include "oidc-auth.redisFullname" .) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oidc-auth.redisTLSServerName" -}}
{{- if .Values.authService.config.redis.tls.serverName -}}
{{- .Values.authService.config.redis.tls.serverName -}}
{{- else if .Values.redis.enabled -}}
{{- printf "%s.%s.svc.cluster.local" (include "oidc-auth.redisFullname" .) .Release.Namespace -}}
{{- end -}}
{{- end -}}
