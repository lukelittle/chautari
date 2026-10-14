{{/*
Expand the name of the chart.
*/}}
{{- define "chautari.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name, truncated to 63 chars (DNS label limit).
*/}}
{{- define "chautari.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "chautari.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "chautari.labels" -}}
helm.sh/chart: {{ include "chautari.chart" . }}
{{ include "chautari.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: chautari
{{- end }}

{{- define "chautari.selectorLabels" -}}
app.kubernetes.io/name: {{ include "chautari.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "chautari.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "chautari.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding credentials: existingSecret, or the one this chart creates.
*/}}
{{- define "chautari.secretName" -}}
{{- default (include "chautari.fullname" .) .Values.existingSecret }}
{{- end }}

{{/*
Image reference. A repository that already carries a tag or digest is used
as-is; otherwise the tag defaults to the given fallback (chart appVersion).
Usage: include "chautari.image" (dict "image" .Values.image "default" .Chart.AppVersion)
*/}}
{{- define "chautari.image" -}}
{{- $repo := .image.repository }}
{{- $last := $repo | splitList "/" | last }}
{{- if or (contains "@" $last) (contains ":" $last) }}
{{- $repo }}
{{- else }}
{{- printf "%s:%s" $repo (default .default .image.tag | toString) }}
{{- end }}
{{- end }}

{{/*
Data plane config file name inside the shared /gateway volume.
*/}}
{{- define "chautari.gatewayConfigFile" -}}
{{- if eq .Values.dataplane "litellm" }}litellm.yaml{{ else }}gateway.yaml{{ end }}
{{- end }}

{{/*
Data plane arguments (the images have no shell; these are passed to the entrypoint).
*/}}
{{- define "chautari.gatewayArgs" -}}
{{- if .Values.gateway.args }}
{{- toJson .Values.gateway.args }}
{{- else if eq .Values.dataplane "litellm" }}
{{- toJson (list "--config" "/gateway/litellm.yaml" "--port" "3000") }}
{{- else }}
{{- toJson (list "-f" "/gateway/gateway.yaml") }}
{{- end }}
{{- end }}
