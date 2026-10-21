-- Cluster-level: run once, before the per-database files. Roles are shared by supplier and
-- supplier_test; their privileges inside each database are in 03-grants.sql.
-- CONNECTION LIMIT: one role cannot use up the server's connections. A tool opens one
-- connection per call. The executor keeps one open; 3 leaves room for the test suite, which
-- runs next to the stack's executor on the same server.
-- Created only when missing, so a database setup that stopped halfway can run again; the
-- password is set every time (\gexec runs the CREATE that the SELECT returns, if any).
SELECT 'CREATE ROLE tool_read_ticket LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tool_read_ticket') \gexec
ALTER ROLE tool_read_ticket PASSWORD :'pw_tool_read_ticket';
SELECT 'CREATE ROLE tool_lookup_account LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tool_lookup_account') \gexec
ALTER ROLE tool_lookup_account PASSWORD :'pw_tool_lookup_account';
SELECT 'CREATE ROLE tool_request_disconnection LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tool_request_disconnection') \gexec
ALTER ROLE tool_request_disconnection PASSWORD :'pw_tool_request_disconnection';
SELECT 'CREATE ROLE tool_issue_bill_credit LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tool_issue_bill_credit') \gexec
ALTER ROLE tool_issue_bill_credit PASSWORD :'pw_tool_issue_bill_credit';
SELECT 'CREATE ROLE tool_set_temp_protection LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tool_set_temp_protection') \gexec
ALTER ROLE tool_set_temp_protection PASSWORD :'pw_tool_set_temp_protection';
SELECT 'CREATE ROLE executor LOGIN CONNECTION LIMIT 3' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'executor') \gexec
ALTER ROLE executor PASSWORD :'pw_executor';
SELECT 'CREATE ROLE approver LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'approver') \gexec
ALTER ROLE approver PASSWORD :'pw_approver';
SELECT 'CREATE ROLE gateway LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gateway') \gexec
ALTER ROLE gateway PASSWORD :'pw_gateway';
SELECT 'CREATE ROLE risk_engine LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'risk_engine') \gexec
ALTER ROLE risk_engine PASSWORD :'pw_risk_engine';
SELECT 'CREATE ROLE dispatcher LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dispatcher') \gexec
ALTER ROLE dispatcher PASSWORD :'pw_dispatcher';
-- The demo UI (app/demo, 09-demo.sql): a customer chat and a read-only view of the audit tables.
-- Optional, but the roles exist everywhere, so the database is the same whether the chart runs it or not.
SELECT 'CREATE ROLE demo_portal LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'demo_portal') \gexec
ALTER ROLE demo_portal PASSWORD :'pw_demo_portal';
SELECT 'CREATE ROLE demo_ops LOGIN CONNECTION LIMIT 5' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'demo_ops') \gexec
ALTER ROLE demo_ops PASSWORD :'pw_demo_ops';
-- Owners of SECURITY DEFINER functions. Nobody logs in as them; a function runs with its owner's
-- privileges, so each owner holds only what its functions read and write.
--   api_owner    the five tool functions (05-lease.sql)
--   lease_owner  open_lease, revoke_lease, lease_scope (05-lease.sql)
--   risk_owner   the risk objects: pause_agents, resume_agents (SECURITY DEFINER), and
--                required_approvals, check_approval_floor (06-risk.sql)
--   staff_owner  the staff allow-list (06-risk.sql) and approve_request, the only way an approval
--                is written. Only the database superuser or the migration changes the list.
--   flags_writer owned set_temp_protection(int) until api_set_temp_protection replaced it; kept
--                because the RLS policy (08-rls.sql) names it. It has no grants.
SELECT 'CREATE ROLE flags_writer NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'flags_writer') \gexec
SELECT 'CREATE ROLE api_owner NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'api_owner') \gexec
SELECT 'CREATE ROLE lease_owner NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lease_owner') \gexec
SELECT 'CREATE ROLE risk_owner NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'risk_owner') \gexec
SELECT 'CREATE ROLE staff_owner NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'staff_owner') \gexec
--   demo_owner   the three demo_portal functions and demo_request_errors (09-demo.sql)
SELECT 'CREATE ROLE demo_owner NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'demo_owner') \gexec

-- Every executor session, whatever the code does: a lock it cannot get within 5 s fails that
-- request (executor_error, the batch goes on) instead of hanging the only component that
-- writes effects. statement_timeout caps anything else that hangs.
ALTER ROLE executor SET lock_timeout = '5s';
ALTER ROLE executor SET statement_timeout = '30s';

-- api_set_temp_protection takes a home's advisory lock until its transaction ends. A tool session
-- left idle inside a transaction would keep the executor off that home, so it is ended after
-- 10 s. This only covers an honest tool that hangs: a role can change this setting in its own
-- session, so a hijacked tool can still hold the lock.
ALTER ROLE tool_read_ticket           SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE tool_lookup_account        SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE tool_request_disconnection SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE tool_issue_bill_credit     SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE tool_set_temp_protection   SET idle_in_transaction_session_timeout = '10s';

REVOKE TEMPORARY ON DATABASE supplier FROM PUBLIC;
REVOKE CREATE ON DATABASE supplier FROM PUBLIC;
REVOKE TEMPORARY ON DATABASE supplier_test FROM PUBLIC;
REVOKE CREATE ON DATABASE supplier_test FROM PUBLIC;
