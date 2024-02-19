{{/*
Expand the name of the chart.
*/}}
{{- define "backendJava.name" -}}
{{- printf "backendJava" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "backendJava.fullname" -}}
{{- $componentName := include "backendJava.name" .  }}
{{- if .Values.backendJava.fullnameOverride }}
{{- .Values.backendJava.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $componentName | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "backendJava.labels" -}}
{{ include "backendJava.selectorLabels" . }}
{{- if .Values.global.tag }}
app.kubernetes.io/image-version: {{ .Values.global.tag | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/short-name: {{ include "backendJava.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "backendJava.selectorLabels" -}}
app.kubernetes.io/name: {{ include "backendJava.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


