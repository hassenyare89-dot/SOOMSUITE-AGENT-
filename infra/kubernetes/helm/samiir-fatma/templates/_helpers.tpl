{{- define "sf.labels" -}}
app.kubernetes.io/part-of: samiir-fatma
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "sf.envName" -}}
{{- . | upper | replace "-" "_" -}}
{{- end -}}

{{/* Downstream URL env var names expected by each service's settings. */}}
{{- define "sf.urlVar" -}}
{{- $m := dict "samiir-agent" "SAMIIR_URL" "crm" "CRM_URL" "scheduling" "SCHEDULING_URL" "knowledge" "KNOWLEDGE_URL" "notifications" "NOTIFICATIONS_URL" "whatsapp" "WHATSAPP_URL" "fatma-soc" "FATMA_URL" "scanner-controller" "SCANNER_CONTROLLER_URL" "security-ingest" "SECURITY_INGEST_URL" "approvals" "APPROVALS_URL" "audit" "AUDIT_READ_URL" -}}
{{- get $m . -}}
{{- end -}}

{{/* Spread replicas across nodes (soft, so small clusters still schedule). Arg: app name. */}}
{{- define "sf.antiAffinity" -}}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        topologyKey: kubernetes.io/hostname
        labelSelector: { matchLabels: { app: {{ . }} } }
{{- end }}
