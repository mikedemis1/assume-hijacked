{{/*
Shared building blocks. Every pod in the chart is built from these, so the rules that apply
to all of them (restricted security context, no automounted service account token, resources,
placement) are written once.
*/}}

{{/* The non-root user of the app image (Dockerfile: useradd --uid 10001, USER 10001). */}}
{{- define "ah.appUid" -}}10001{{- end }}

{{/* Labels on every object. Call with (dict "root" $ "name" "<component>"). */}}
{{- define "ah.labels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/part-of: assume-hijacked
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version }}
{{- end }}

{{/* In-cluster DNS name of a Service. Call with (list "<service>" "<namespace>"). */}}
{{- define "ah.host" -}}
{{ index . 0 }}.{{ index . 1 }}.svc.cluster.local
{{- end }}

{{/*
Pod Security "restricted" plus a fixed user. Call with the UID (the app UID for everything
except the Postgres server, which runs as the image's postgres user).
*/}}
{{- define "ah.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ . }}
runAsGroup: {{ . }}
fsGroup: {{ . }}
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "ah.containerSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ . }}
runAsGroup: {{ . }}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Node placement (nodeSelector, tolerations) of the pods that are not sandboxed; empty when
neither is set. Call with the root context:
  {{- with include "ah.systemPlacement" $ }}{{ . | nindent 6 }}{{ end }}
*/}}
{{- define "ah.systemPlacement" -}}
{{- $p := dict -}}
{{- with .Values.placement.system.nodeSelector }}{{ $_ := set $p "nodeSelector" . }}{{ end -}}
{{- with .Values.placement.system.tolerations }}{{ $_ := set $p "tolerations" . }}{{ end -}}
{{- if $p }}{{ toYaml $p }}{{ end -}}
{{- end }}

{{/*
Explicit API server token for the few components that call the Kubernetes API (TokenReview,
creating agent Jobs). Same files as the automounted token would give, but only where asked for.
*/}}
{{- define "ah.kubeApiTokenVolume" -}}
name: kube-api-token
projected:
  sources:
    - serviceAccountToken:
        path: token
        expirationSeconds: 3600
    - configMap:
        name: kube-root-ca.crt
        items:
          - {key: ca.crt, path: ca.crt}
    - downwardAPI:
        items:
          - path: namespace
            fieldRef: {fieldPath: metadata.namespace}
{{- end }}

{{/*
Where a component's secrets come from. Same Secret name (<name>-secrets) and keys on both
environments, so the pod spec does not change:
  kind   a Secret rendered from values (secrets.*), required at install time
  azure  a SecretProviderClass that reads the component's own Key Vault with its workload
         identity and syncs the objects into that Secret (the pod mounts the CSI volume)
Call with (dict "root" $ "name" ... "namespace" ... "items" (list (dict "key" "value" "kvObject" "what"))).
*/}}
{{- define "ah.secretSource" -}}
{{- $root := .root -}}
{{- $name := .name -}}
{{- if eq $root.Values.env "kind" }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ $name }}-secrets
  namespace: {{ .namespace }}
  labels:
    {{- include "ah.labels" (dict "root" $root "name" $name) | nindent 4 }}
type: Opaque
stringData:
  {{- range .items }}
  {{ .key }}: {{ required (printf "%s is required with env=kind" .what) .value | quote }}
  {{- end }}
{{- else }}
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: {{ $name }}
  namespace: {{ .namespace }}
  labels:
    {{- include "ah.labels" (dict "root" $root "name" $name) | nindent 4 }}
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    clientID: {{ required (printf "azure.clientIds.%s is required with env=azure" $name) (index $root.Values.azure.clientIds $name) | quote }}
    keyvaultName: {{ required (printf "azure.keyVaults.%s is required with env=azure" $name) (index $root.Values.azure.keyVaults $name) | quote }}
    tenantID: {{ required "azure.tenantId is required with env=azure" $root.Values.azure.tenantId | quote }}
    objects: |
      array:
      {{- range .items }}
        - |
          objectName: {{ .kvObject }}
          objectType: secret
      {{- end }}
  secretObjects:
    - secretName: {{ $name }}-secrets
      type: Opaque
      data:
        {{- range .items }}
        - objectName: {{ .kvObject }}
          key: {{ .key }}
        {{- end }}
{{- end }}
{{- end }}

{{/*
A ServiceAccount that never automounts its token. On Azure, a component that reads Key Vault
or calls Azure gets the workload identity annotation.
Call with (dict "root" $ "name" ... "namespace" ... "workloadIdentity" bool).
*/}}
{{- define "ah.serviceAccount" -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .name }}
  namespace: {{ .namespace }}
  labels:
    {{- include "ah.labels" (dict "root" .root "name" .name) | nindent 4 }}
  {{- if .workloadIdentity }}
  annotations:
    azure.workload.identity/client-id: {{ required (printf "azure.clientIds.%s is required with env=azure" .name) (index .root.Values.azure.clientIds .name) | quote }}
  {{- end }}
automountServiceAccountToken: false
{{- end }}

{{/*
One long-running component: ServiceAccount, its secret source, Deployment and Service.
Call with a dict:
  root       $
  name       component name (also the ServiceAccount, Deployment and Service name)
  namespace  its namespace
  command    list, e.g. (list "python" "-m" "app.gateway.main")
  ports      list of (dict "name" "port"), the service ports besides ops
  ops        true when the component serves /healthz and /metrics on 9000
  env        list of (dict "name" "value"), plain settings
  dbRole     PostgreSQL role it logs in as ("" for none): DB_* settings + DB_PASSWORD_<ROLE>
  files      list of (dict "key" "env" "value" "kvObject" "what"): secret files, mounted under
             /var/run/secrets/ah-files/<key>, path given to the app in env <env>
  configMaps list of (dict "name" "mountPath"), read-only
  apiToken   true when it calls the Kubernetes API
  sandbox    true to run under the sandbox RuntimeClass
  workloadIdentity  true when its process calls Azure itself (not needed to read its Key Vault)
*/}}
{{- define "ah.workload" -}}
{{- $root := .root -}}
{{- $v := $root.Values -}}
{{- $name := .name -}}
{{- $uid := include "ah.appUid" . | int -}}
{{- $secretName := printf "%s-secrets" $name -}}

{{- /* Secret items: the DB password first, then the files. */ -}}
{{- $items := list -}}
{{- if .dbRole -}}
{{- $items = append $items (dict
      "key" (printf "DB_PASSWORD_%s" (upper .dbRole))
      "value" (index $v.secrets.dbPasswords .dbRole)
      "kvObject" (printf "db-password-%s" (replace "_" "-" .dbRole))
      "what" (printf "secrets.dbPasswords.%s" .dbRole)) -}}
{{- end -}}
{{- range .files -}}
{{- $items = append $items . -}}
{{- end -}}
{{- $hasSecrets := gt (len $items) 0 -}}
{{- /*
Azure identity. The Secrets Store CSI driver reads Key Vault with a token it requests for the
pod's ServiceAccount and the clientID in the SecretProviderClass (provider docs, workload
identity mode: the example pod has no webhook label). So a component that only reads its vault
gets the ServiceAccount annotation (it names the identity the federated credential trusts) but
no pod label: its process holds no Azure token. Only a component that calls Azure itself
(workloadIdentity) gets the label, and with it the webhook-injected token.
*/ -}}
{{- $wi := and (eq $v.env "azure") (or $hasSecrets .workloadIdentity) -}}
{{- $podIdentity := and (eq $v.env "azure") .workloadIdentity -}}

{{- /* Environment. */ -}}
{{- $env := list (dict "name" "APP_ENV" "value" $v.env) -}}
{{- if .dbRole -}}
{{- $env = concat $env (list
      (dict "name" "DB_HOST" "value" (required "db.host is required" $v.db.host))
      (dict "name" "DB_PORT" "value" (toString $v.db.port))
      (dict "name" "DB_NAME" "value" $v.db.name)
      (dict "name" (printf "DB_PASSWORD_%s" (upper .dbRole))
            "valueFrom" (dict "secretKeyRef" (dict "name" $secretName "key" (printf "DB_PASSWORD_%s" (upper .dbRole)))))) -}}
{{- end -}}
{{- range .files -}}
{{- $env = append $env (dict "name" .env "value" (printf "/var/run/secrets/ah-files/%s" .key)) -}}
{{- end -}}
{{- $env = concat $env (default (list) .env) -}}

{{- /* Volumes and mounts. */ -}}
{{- $volumes := list -}}
{{- $mounts := list -}}
{{- if .files -}}
{{- $fileItems := list -}}
{{- range .files -}}
{{- $fileItems = append $fileItems (dict "key" .key "path" .key) -}}
{{- end -}}
{{- /* 0440: readable by the pod's group (fsGroup), not by others. */ -}}
{{- $volumes = append $volumes (dict "name" "secret-files" "secret" (dict "secretName" $secretName "items" $fileItems "defaultMode" 288)) -}}
{{- $mounts = append $mounts (dict "name" "secret-files" "mountPath" "/var/run/secrets/ah-files" "readOnly" true) -}}
{{- end -}}
{{- if and (eq $v.env "azure") $hasSecrets -}}
{{- $volumes = append $volumes (dict "name" "secrets-store" "csi" (dict "driver" "secrets-store.csi.k8s.io" "readOnly" true "volumeAttributes" (dict "secretProviderClass" $name))) -}}
{{- $mounts = append $mounts (dict "name" "secrets-store" "mountPath" "/mnt/secrets-store" "readOnly" true) -}}
{{- end -}}
{{- if .apiToken -}}
{{- $volumes = append $volumes (include "ah.kubeApiTokenVolume" . | fromYaml) -}}
{{- $mounts = append $mounts (dict "name" "kube-api-token" "mountPath" "/var/run/secrets/kubernetes.io/serviceaccount" "readOnly" true) -}}
{{- end -}}
{{- range .configMaps -}}
{{- $volumes = append $volumes (dict "name" .name "configMap" (dict "name" .name)) -}}
{{- $mounts = append $mounts (dict "name" .name "mountPath" .mountPath "readOnly" true) -}}
{{- end -}}

{{- /* Ports. */ -}}
{{- $ports := default (list) .ports -}}
{{- if .ops -}}
{{- $ports = append $ports (dict "name" "ops" "port" 9000) -}}
{{- end -}}

{{- include "ah.serviceAccount" (dict "root" $root "name" $name "namespace" .namespace "workloadIdentity" $wi) }}
{{- if $hasSecrets }}
---
{{- include "ah.secretSource" (dict "root" $root "name" $name "namespace" .namespace "items" $items) }}
{{- end }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $name }}
  namespace: {{ .namespace }}
  labels:
    {{- include "ah.labels" (dict "root" $root "name" $name) | nindent 4 }}
spec:
  replicas: 1
  revisionHistoryLimit: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ $name }}
  template:
    metadata:
      labels:
        {{- include "ah.labels" (dict "root" $root "name" $name) | nindent 8 }}
        {{- if $podIdentity }}
        azure.workload.identity/use: "true"
        {{- end }}
    spec:
      serviceAccountName: {{ $name }}
      automountServiceAccountToken: false
      enableServiceLinks: false
      {{- if .sandbox }}
      runtimeClassName: {{ $v.sandbox.runtimeClass }}
      {{- else }}
      {{- with include "ah.systemPlacement" $root }}{{ . | nindent 6 }}{{ end }}
      {{- end }}
      securityContext:
        {{- include "ah.podSecurityContext" $uid | nindent 8 }}
      containers:
        - name: {{ $name }}
          image: {{ $v.images.app }}
          imagePullPolicy: IfNotPresent
          command: {{ toJson .command }}
          {{- with $ports }}
          ports:
            {{- range . }}
            - name: {{ .name }}
              containerPort: {{ .port }}
              protocol: TCP
            {{- end }}
          {{- end }}
          env:
            {{- toYaml $env | nindent 12 }}
          {{- with $mounts }}
          volumeMounts:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          securityContext:
            {{- include "ah.containerSecurityContext" $uid | nindent 12 }}
          resources:
            {{- toYaml $v.resources.app | nindent 12 }}
          {{- if .ops }}
          livenessProbe:
            httpGet: {path: /healthz, port: ops}
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            httpGet: {path: /healthz, port: ops}
            periodSeconds: 5
          {{- end }}
      {{- with $volumes }}
      volumes:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- if $ports }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ $name }}
  namespace: {{ .namespace }}
  labels:
    {{- include "ah.labels" (dict "root" $root "name" $name) | nindent 4 }}
spec:
  selector:
    app.kubernetes.io/name: {{ $name }}
  ports:
    {{- range $ports }}
    - name: {{ .name }}
      port: {{ .port }}
      targetPort: {{ .name }}
      protocol: TCP
    {{- end }}
{{- end }}
{{- end }}

{{/* The five tools: MCP tool name -> component name tool-<name with hyphens>. */}}
{{- define "ah.tools" -}}
["read_ticket", "lookup_account", "request_disconnection", "issue_bill_credit", "set_temp_protection"]
{{- end }}

{{/* Every DB login role that has a password (db/sql/02-roles.sql plus the roles lane A adds). */}}
{{- define "ah.dbRoles" -}}
["tool_read_ticket", "tool_lookup_account", "tool_request_disconnection", "tool_issue_bill_credit", "tool_set_temp_protection", "executor", "approver", "gateway", "risk_engine", "dispatcher", "register_sync"]
{{- end }}

{{/*
db/init/init.sh and db/sql/*.sql as ConfigMaps for the job that sets up the database
(kind: postgres-init in ah-data; azure: db-migrate in ah-core). The contents come from
dbFiles.* (--set-file at deploy time), so db/ stays the only copy, and new SQL files are picked
up by the deploy script's loop over db/sql.
Call with (dict "root" $ "namespace" ... "name" <labels name>).
*/}}
{{- define "ah.dbFiles" -}}
{{- $f := .root.Values.dbFiles -}}
{{- if not $f.sql -}}
{{- fail "dbFiles.sql is empty (--set-file dbFiles.sql.<name>=db/sql/<name>.sql for each file)" -}}
{{- end -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: db-init
  namespace: {{ .namespace }}
  labels:
    {{- include "ah.labels" (dict "root" .root "name" .name) | nindent 4 }}
data:
  init.sh: {{ required "dbFiles.initSh is required (--set-file dbFiles.initSh=db/init/init.sh)" $f.initSh | quote }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: db-sql
  namespace: {{ .namespace }}
  labels:
    {{- include "ah.labels" (dict "root" .root "name" .name) | nindent 4 }}
data:
  {{- range $file, $text := $f.sql }}
  {{ printf "%s.sql" (trimSuffix ".sql" $file) }}: {{ $text | quote }}
  {{- end }}
{{- end }}

{{/*
Env of a database setup job: the passwords init.sh passes to 02-roles.sql as psql variables,
one per login role, from the Secret named <secret>. Call with (dict "root" $ "secret" "<name>").
*/}}
{{- define "ah.dbRolePasswordEnv" -}}
{{- $secret := .secret -}}
{{- range $role := include "ah.dbRoles" .root | fromJsonArray }}
- name: DB_PASSWORD_{{ upper $role }}
  valueFrom:
    secretKeyRef: {name: {{ $secret }}, key: DB_PASSWORD_{{ upper $role }}}
{{- end }}
{{- end }}

{{/* Volumes both database setup jobs mount: the two ConfigMaps from ah.dbFiles, and /tmp. */}}
{{- define "ah.dbFilesVolumes" -}}
- name: db-init
  configMap: {name: db-init}
- name: db-sql
  configMap: {name: db-sql}
- name: tmp
  emptyDir: {}
{{- end }}

{{- define "ah.dbFilesMounts" -}}
- {name: db-init, mountPath: /db/init, readOnly: true}
- {name: db-sql, mountPath: /db/sql, readOnly: true}
- {name: tmp, mountPath: /tmp}
{{- end }}
