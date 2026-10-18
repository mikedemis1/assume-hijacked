# Staff console

The queue shows request ids, risk tiers and rule codes. It also lists component heartbeats,
protection-removal requests with their closure reason, and ALERT ids with timestamps. It never
renders ticket bodies, customer details, staff removal reasons or event detail. Follow up an alert
using its id in the authorised staff workflow.

`HUMAN_ONLY` and requests awaiting assessment show a protected-customer warning. These cannot be
approved through the console. A rejection records `staff_rejected`. Move-out approvals can be
given after the occupier notice; the database still enforces the waiting period and approval floor.

## Local Compose

Start the stack and open `http://127.0.0.1:8084`. The development sign-in page lists the configured
UUIDs. The Compose demo has one Approver (`aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa`) and two
SeniorApprovers (`bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb` and
`cccccccc-cccc-4ccc-8ccc-cccccccccccc`). Development sign-in trusts the selected local identity.
It provides no identity verification and is refused when `APP_ENV=azure`.

`CONSOLE_DEV_USERS` is a JSON object mapping UUIDs to app-role lists:

```json
{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa":["Approver"]}
```

For local scripts, `GET /` with `X-Dev-User: <configured UUID>` also creates a session in development
mode. Subsequent writes need its cookie and the CSRF token in the returned form. Identity and role
fields in a submitted action never override the session.

Protection removal needs two distinct SeniorApprovers other than the requester. Resuming agents
also requires a SeniorApprover. The database trusts the console's asserted app role; staff do not
log in to PostgreSQL separately.

## Entra sign-in

Register a single-tenant Web application with an exact HTTPS redirect URI ending in
`/auth/callback`. Define `Approver` and `SeniorApprover` app roles and assign the authorised staff.
The console uses the [authorization code flow with PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow).
The Web client authenticates its token exchange using its own client secret in addition to the
PKCE verifier. Do not register the redirect as a SPA or silently enable a public-client flow.

Set these variables on the console only:

| Variable | Value |
|---|---|
| `AUTH_MODE` | `entra` |
| `APP_ENV` | `azure` (or `kind` for the local cluster) |
| `ENTRA_TENANT_ID` | Tenant UUID |
| `ENTRA_CLIENT_ID` | Application UUID |
| `CONSOLE_REDIRECT_URI` | Registered HTTPS callback URL |
| `CONSOLE_CLIENT_SECRET_FILE` | Mounted read-only file containing the Web application's client secret |
| `DB_PASSWORD_APPROVER` | This service's database password, supplied through its existing secret mount |

Keep the client credential in the console's own vault and mount it only in that service. It must
never be placed in chart values, Terraform state, a URL, browser HTML or a log. An explicitly local
process (`APP_ENV=local`) may use an HTTP loopback callback for development.

The code exchange is bound to a five-minute, single-use state, browser correlation cookie, nonce
and S256 PKCE challenge. The console verifies RS256 signatures against the tenant's JWKS, the
tenant-specific issuer, client audience, expiry, tenant id, nonce and app roles. The recorded
approver is the canonical UUID from `oid`; display names and email addresses are never identities.

Application cookies are HttpOnly and SameSite Strict, with Secure outside `APP_ENV=local`. The
temporary correlation cookie is HttpOnly and SameSite Lax so the cross-site GET callback can carry
it. Successful sign-in returns a page with a Continue link. This starts a new same-origin navigation
for the Strict session cookie. All pages use `Cache-Control: no-store` and the console disables
HTTP access logs.

Kind therefore needs HTTPS at the browser, including when using a port-forward. Plain HTTP
port-forwarding does not provide a reliable Secure-cookie session. Use a local TLS terminator;
do not weaken the cookie policy using a forwarded header or a different Host value.

Sessions and pending logins are held in memory, capped at 1,000 each. Run one console process and
one replica. A restart signs staff out. Sessions last at most 30 minutes and never outlive the
verified ID token; role changes take effect on the next sign-in or session expiry. There is no
refresh-token storage or shared-session service.

Port 9000 serves the common `/healthz` and `/metrics` endpoints. The web event loop updates its
heartbeat every ten seconds. No browser session or CSRF token appears in metrics.
