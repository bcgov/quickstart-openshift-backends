{{/*
Expand the name of the chart.
*/}}
{{- define "backendPy.name" -}}
{{- printf "backendPy" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "backendPy.fullname" -}}
{{- $componentName := include "backendPy.name" .  }}
{{- if .Values.backendPy.fullnameOverride }}
{{- .Values.backendPy.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $componentName | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "backendPy.labels" -}}
{{ include "backendPy.selectorLabels" . }}
{{- if .Values.global.tag }}
app.kubernetes.io/image-version: {{ .Values.global.tag | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/short-name: {{ include "backendPy.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "backendPy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "backendPy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


