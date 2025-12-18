{{/*
Expand the name of the chart.
*/}}
{{- define "backend-java.name" -}}
{{- printf "backend-java" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "backend-java.fullname" -}}
{{- $componentName := include "backend-java.name" .  }}
{{- if index .Values "backend-java" "fullnameOverride" }}
{{- index .Values "backend-java" "fullnameOverride" | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $componentName | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "backend-java.labels" -}}
{{ include "backend-java.selectorLabels" . }}
{{- if .Values.global.tag }}
app.kubernetes.io/image-version: {{ .Values.global.tag | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/short-name: {{ include "backend-java.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "backend-java.selectorLabels" -}}
app.kubernetes.io/name: {{ include "backend-java.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


