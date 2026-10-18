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
Projected tokens a component shows to the peers it calls (the same layout as the agent's
tokens in agent.yaml): one per audience, 10 minutes, at <audience>/token. The peer checks it
with a TokenReview. Call with the list of audiences.
*/}}
{{- define "ah.audienceTokenVolume" -}}
name: ah-tokens
projected:
  sources:
    {{- range . }}
    - serviceAccountToken:
        audience: {{ . }}
        expirationSeconds: 600
        path: {{ . }}/token
    {{- end }}
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
  audiences  list of audiences it gets a projected token for, to call a peer that checks it
             with a TokenReview: /var/run/secrets/ah/<audience>/token, 10 minutes, read-only
  sandbox    true to run under the sandbox RuntimeClass
  workloadIdentity  true when its process calls Azure itself (not needed to read its Key Vault)
  strategy   Deployment strategy type; empty for the default rolling update

Every pod gets a small writable /tmp (emptyDir): the root filesystem is read-only, and Python
and its libraries fall back to /tmp for temporary files.

A component listed in `stubs` (kind only, until its code is in this tree) runs the ops stand-in
files/ops-stub.py instead of its entry point; everything else about the pod stays the same.
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
{{- with .audiences -}}
{{- $volumes = append $volumes (include "ah.audienceTokenVolume" . | fromYaml) -}}
{{- $mounts = append $mounts (dict "name" "ah-tokens" "mountPath" "/var/run/secrets/ah" "readOnly" true) -}}
{{- end -}}
{{- range .configMaps -}}
{{- $volumes = append $volumes (dict "name" .name "configMap" (dict "name" .name)) -}}
{{- $mounts = append $mounts (dict "name" .name "mountPath" .mountPath "readOnly" true) -}}
{{- end -}}
{{- $volumes = append $volumes (dict "name" "tmp" "emptyDir" (dict "sizeLimit" "64Mi")) -}}
{{- $mounts = append $mounts (dict "name" "tmp" "mountPath" "/tmp") -}}

{{- /* Ports. */ -}}
{{- $ports := default (list) .ports -}}
{{- if .ops -}}
{{- $ports = append $ports (dict "name" "ops" "port" 9000) -}}
{{- end -}}

{{- /* The entry point, or the ops stand-in while the component's code is not in this tree. */ -}}
{{- $command := .command -}}
{{- if has $name (default (list) $v.stubs) -}}
{{- if ne $v.env "kind" -}}
{{- fail (printf "stubs is for kind only (%s would not run its code)" $name) -}}
{{- end -}}
{{- if not .ops -}}
{{- fail (printf "stubs: %s has no ops port for the stand-in to serve" $name) -}}
{{- end -}}
{{- $command = list "python" "-c" ($root.Files.Get "files/ops-stub.py") $name -}}
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
    {{- with .dbRole }}
    {{- /* The database role it logs in as: scripts/azure-rotate-db-passwords.sh restarts these. */}}
    ah/db-role: {{ . }}
    {{- end }}
spec:
  replicas: 1
  revisionHistoryLimit: 3
  {{- with .strategy }}
  strategy:
    type: {{ . }}
  {{- end }}
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
          command: {{ toJson $command }}
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

{{/* Every DB login role that has a password (db/sql/02-roles.sql plus the gateway, risk engine, dispatcher and register sync roles). */}}
{{- define "ah.dbRoles" -}}
["tool_read_ticket", "tool_lookup_account", "tool_request_disconnection", "tool_issue_bill_credit", "tool_set_temp_protection", "executor", "approver", "gateway", "risk_engine", "dispatcher", "register_sync"]
{{- end }}

{{/*
The component that logs in as each database role, as a JSON object {role: component}. The
role's password lives in that component's Secret (kind) or Key Vault (Azure).
*/}}
{{- define "ah.dbRoleComponents" -}}
{{- $out := dict
  "executor" "executor" "approver" "console" "gateway" "tool-gateway" "risk_engine" "risk-engine"
  "dispatcher" "dispatcher" "register_sync" "register-sync" -}}
{{- range include "ah.tools" . | fromJsonArray }}{{ $_ := set $out (printf "tool_%s" .) (printf "tool-%s" (replace "_" "-" .)) }}{{ end -}}
{{- toJson $out -}}
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

{{/*
The namespaces of the chart, as a JSON list (one per trust zone; ah-data only on kind, where the
chart runs PostgreSQL itself). ah-monitoring belongs to the monitoring stack (deploy/monitoring), not here.
*/}}
{{- define "ah.namespaces" -}}
{{- $ns := list "ah-intake" "ah-agent" "ah-gateway" "ah-tools" "ah-core" "ah-staff" "ah-fakes" -}}
{{- if eq .Values.env "kind" }}{{ $ns = append $ns "ah-data" }}{{ end -}}
{{- toJson $ns -}}
{{- end }}

{{/* Component names of the five tools (tool-read-ticket, ...), as a JSON list. */}}
{{- define "ah.toolComponents" -}}
{{- $names := list -}}
{{- range include "ah.tools" . | fromJsonArray }}{{ $names = append $names (printf "tool-%s" (replace "_" "-" .)) }}{{ end -}}
{{- toJson $names -}}
{{- end }}

{{/*
The allowed network edges inside the cluster, as a JSON list. Each one is a row of the
communication matrix (final architecture, section 4) and becomes two NetworkPolicies:
the egress half in the caller's namespace and the ingress half in the callee's namespace.
Everything else is denied by the default-deny policy of every namespace.
  from  {ns, pods}            pods: app.kubernetes.io/name values; external: no egress half
                              (the caller's namespace is not part of this chart)
  to    {ns, pods, ports}     or {cidr, ports} for the database outside the cluster (Azure)
The Kubernetes API, DNS and the few names outside the cluster are Cilium policies
(templates/policies/cilium.yaml): plain NetworkPolicy cannot express them.
*/}}
{{- define "ah.edges" -}}
{{- $v := .Values -}}
{{- $tools := include "ah.toolComponents" . | fromJsonArray -}}
{{- $pg := list 5432 -}}
{{- $db := dict "ns" "ah-data" "pods" (list "postgres") "ports" $pg -}}
{{- if eq $v.env "azure" -}}
{{- $cidr := required "network.databaseCidr is required with env=azure" $v.network.databaseCidr -}}
{{- /* Also in values.schema.json; here too because --skip-schema-validation skips the schema. A
private (RFC 1918) range of /24 or longer: a wider range would open 5432 to far more than the
database for every caller. */ -}}
{{- if not (regexMatch (include "ah.privateCidrPattern" .) $cidr) -}}
{{- fail (printf "network.databaseCidr must be a private (RFC 1918) range of /24 or longer, got %s" $cidr) -}}
{{- end -}}
{{- $db = dict "cidr" $cidr "ports" $pg -}}
{{- end -}}
{{- $edges := list
  (dict "id" "edge-04-dispatcher-to-db"         "from" (dict "ns" "ah-intake"  "pods" (list "dispatcher"))    "to" $db)
  (dict "id" "edge-05-agent-to-tool-gateway"    "from" (dict "ns" "ah-agent"   "pods" (list "agent"))         "to" (dict "ns" "ah-gateway" "pods" (list "tool-gateway") "ports" (list 8080)))
  (dict "id" "edge-06-agent-to-llm-gateway"     "from" (dict "ns" "ah-agent"   "pods" (list "agent"))         "to" (dict "ns" "ah-agent"   "pods" (list "llm-gateway")  "ports" (list 8083)))
  (dict "id" "edge-07-agent-to-dispatcher"      "from" (dict "ns" "ah-agent"   "pods" (list "agent"))         "to" (dict "ns" "ah-intake"  "pods" (list "dispatcher")   "ports" (list 8081)))
  (dict "id" "edge-08-tool-gateway-to-risk-engine" "from" (dict "ns" "ah-gateway" "pods" (list "tool-gateway")) "to" (dict "ns" "ah-core" "pods" (list "risk-engine") "ports" (list 8082)))
  (dict "id" "edge-09-tool-gateway-to-tools"    "from" (dict "ns" "ah-gateway" "pods" (list "tool-gateway"))  "to" (dict "ns" "ah-tools"   "pods" $tools                "ports" (list 8000)))
  (dict "id" "edge-11-tool-gateway-to-db"       "from" (dict "ns" "ah-gateway" "pods" (list "tool-gateway"))  "to" $db)
  (dict "id" "edge-12-tools-to-db"              "from" (dict "ns" "ah-tools"   "pods" $tools)                 "to" $db)
  (dict "id" "edge-13-risk-engine-to-db"        "from" (dict "ns" "ah-core"    "pods" (list "risk-engine"))   "to" $db)
  (dict "id" "edge-14-executor-to-db"           "from" (dict "ns" "ah-core"    "pods" (list "executor"))      "to" $db)
  (dict "id" "edge-15-executor-to-fake-dso"     "from" (dict "ns" "ah-core"    "pods" (list "executor"))      "to" (dict "ns" "ah-fakes"   "pods" (list "fake-dso")     "ports" (list 8091)))
  (dict "id" "edge-15-executor-to-fake-sms"     "from" (dict "ns" "ah-core"    "pods" (list "executor"))      "to" (dict "ns" "ah-fakes"   "pods" (list "fake-sms")     "ports" (list 8092)))
  (dict "id" "edge-16-register-sync-to-fake-register" "from" (dict "ns" "ah-core" "pods" (list "register-sync")) "to" (dict "ns" "ah-fakes" "pods" (list "fake-register") "ports" (list 8090)))
  (dict "id" "edge-16-register-sync-to-db"      "from" (dict "ns" "ah-core"    "pods" (list "register-sync")) "to" $db)
  (dict "id" "edge-18-console-to-db"            "from" (dict "ns" "ah-staff"   "pods" (list "console"))       "to" $db)
-}}
{{- /* The database setup job: postgres-init on kind, db-migrate on Azure. */ -}}
{{- if eq $v.env "kind" -}}
{{- $edges = append $edges (dict "id" "edge-db-setup-to-db" "from" (dict "ns" "ah-data" "pods" (list "postgres-init")) "to" $db) -}}
{{- else -}}
{{- $edges = append $edges (dict "id" "edge-db-setup-to-db" "from" (dict "ns" "ah-core" "pods" (list "db-migrate")) "to" $db) -}}
{{- end -}}
{{- /* Row 21: Prometheus (namespace ah-monitoring, deploy/monitoring) scrapes the ops port, and only that. */ -}}
{{- range $ns := list "ah-intake" "ah-agent" "ah-gateway" "ah-tools" "ah-core" "ah-staff" "ah-fakes" -}}
{{- $edges = append $edges (dict "id" "edge-21-monitoring-to-metrics" "from" (dict "ns" "ah-monitoring" "pods" (list) "external" true) "to" (dict "ns" $ns "pods" (list) "ports" (list 9000))) -}}
{{- end -}}
{{- toJson $edges -}}
{{- end }}

{{/*
Names outside the cluster that a component may resolve and reach on 443 (matrix rows 19, 20),
as a JSON list of {name, ns, hosts}. Nothing else in the chart resolves a name outside
cluster.local.
  llm-gateway  anthropic: the API host; foundry: the endpoint host + Entra (workload identity)
  console      Entra sign-in keys, when authMode=entra
  db-migrate   Entra (Azure only: it trades its workload identity token for a database token)
*/}}
{{- define "ah.externalNames" -}}
{{- $v := .Values -}}
{{- $entra := "login.microsoftonline.com" -}}
{{- $out := list -}}
{{- if eq $v.llm.backend "anthropic" -}}
{{- $out = append $out (dict "name" "llm-gateway" "ns" "ah-agent" "hosts" (list "api.anthropic.com")) -}}
{{- else if eq $v.llm.backend "foundry" -}}
{{- /* hostname, not host: host keeps a :port, and DNS rules match names. */ -}}
{{- $host := (urlParse (required "llm.foundryEndpoint is required with llm.backend=foundry" $v.llm.foundryEndpoint)).hostname -}}
{{- if not $host -}}
{{- fail (printf "llm.foundryEndpoint must be a URL with a host (https://<name>/...), got %s" $v.llm.foundryEndpoint) -}}
{{- end -}}
{{- $out = append $out (dict "name" "llm-gateway" "ns" "ah-agent" "hosts" (list $host $entra)) -}}
{{- end -}}
{{- if eq $v.console.authMode "entra" -}}
{{- $out = append $out (dict "name" "console" "ns" "ah-staff" "hosts" (list $entra)) -}}
{{- end -}}
{{- if eq $v.env "azure" -}}
{{- /* db-migrate also writes each role's new password into that workload's vault. */ -}}
{{- $vaults := list -}}
{{- range $role, $component := include "ah.dbRoleComponents" . | fromJson -}}
{{- $vault := required (printf "azure.keyVaults.%s is required with env=azure" $component) (index $v.azure.keyVaults $component) -}}
{{- $vaults = append $vaults (printf "%s.vault.azure.net" $vault) -}}
{{- end -}}
{{- $out = append $out (dict "name" "db-migrate" "ns" "ah-core" "hosts" (concat (list $entra) ($vaults | uniq | sortAlpha))) -}}
{{- end -}}
{{- toJson $out -}}
{{- end }}

{{/*
RFC 1918 range of /24 or longer, as a regular expression (values.schema.json has the same).
*/}}
{{- define "ah.privateCidrPattern" -}}
^(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}/(2[4-9]|3[0-2])$
{{- end }}

{{/*
The names a pod's resolver asks for when it looks up <host> from namespace <ns>, as a JSON list:
the search list (<ns>.svc.cluster.local, svc.cluster.local, cluster.local; ndots:5) comes first
for a name with fewer than five dots, and the resolver gives up at the first REFUSED, so a DNS
rule must allow every form (Cilium docs, layer7 page, Kubernetes note). The extra names all end
in cluster.local, which CoreDNS answers itself and never forwards.
Call with (dict "host" ... "ns" ...).
*/}}
{{- define "ah.searchNames" -}}
{{- toJson (list .host (printf "%s.%s.svc.cluster.local" .host .ns) (printf "%s.svc.cluster.local" .host) (printf "%s.cluster.local" .host)) -}}
{{- end }}

{{/*
Azure only: the components that reach PostgreSQL, grouped by namespace, as a JSON object
{namespace: [pod names]}. The connection itself is the ipBlock edge in networkpolicies.yaml;
these pods also need to resolve db.host (the flexible server's name, answered by the private DNS
zone with the private endpoint address). Empty on kind, where the database is a cluster service.
*/}}
{{- define "ah.dbCallers" -}}
{{- $out := dict -}}
{{- range $e := include "ah.edges" . | fromJsonArray -}}
{{- if $e.to.cidr -}}
{{- $_ := set $out $e.from.ns (concat (get $out $e.from.ns | default list) $e.from.pods | uniq | sortAlpha) -}}
{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end }}
