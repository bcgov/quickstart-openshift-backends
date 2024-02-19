{{/*
Expand the name of the chart.
*/}}
{{- define "backendGo.name" -}}
{{- printf "backendGo" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "backendGo.fullname" -}}
{{- $componentName := include "backendGo.name" .  }}
{{- if .Values.backendGo.fullnameOverride }}
{{- .Values.backendGo.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $componentName | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "backendGo.labels" -}}
{{ include "backendGo.selectorLabels" . }}
{{- if .Values.global.tag }}
app.kubernetes.io/image-version: {{ .Values.global.tag | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/short-name: {{ include "backendGo.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "backendGo.selectorLabels" -}}
app.kubernetes.io/name: {{ include "backendGo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


