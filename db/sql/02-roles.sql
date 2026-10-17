-- Cluster-level: run once, before the per-database files. Roles are shared by supplier and
-- supplier_test; their privileges inside each database are in 03-grants.sql.
-- CONNECTION LIMIT (gap I9): one role cannot use up the server's connections. A tool opens one
-- connection per call. The executor keeps one open; 3 leaves room for the test suite, which
-- runs next to the stack's executor on the same server.
CREATE ROLE tool_read_ticket           LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_tool_read_ticket';
CREATE ROLE tool_lookup_account        LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_tool_lookup_account';
CREATE ROLE tool_request_disconnection LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_tool_request_disconnection';
CREATE ROLE tool_issue_bill_credit     LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_tool_issue_bill_credit';
CREATE ROLE tool_set_temp_protection   LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_tool_set_temp_protection';
CREATE ROLE executor                   LOGIN CONNECTION LIMIT 3 PASSWORD :'pw_executor';
CREATE ROLE approver                   LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_approver';
CREATE ROLE gateway                    LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_gateway';
CREATE ROLE risk_engine                LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_risk_engine';
CREATE ROLE dispatcher                 LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_dispatcher';
CREATE ROLE register_sync              LOGIN CONNECTION LIMIT 5 PASSWORD :'pw_register_sync';
-- Owners of SECURITY DEFINER functions. Nobody logs in as them; a function runs with its owner's
-- privileges, so each owner holds only what its functions read and write.
--   api_owner    the five tool functions (05-lease.sql)
--   lease_owner  open_lease, revoke_lease, lease_scope (05-lease.sql)
--   flags_admin  the register sync functions, which only add flags (07-register.sql)
--   flags_remover the flag removal functions (07-register.sql); the only role with DELETE on flags
--   risk_owner   the risk objects: pause_agents, resume_agents (SECURITY DEFINER), and
--                required_approvals, check_approval_floor (06-risk.sql)
--   flags_writer owned set_temp_protection(int) until api_set_temp_protection replaced it; kept
--                because the RLS policy (08-rls.sql) and later tasks name it. It has no grants.
CREATE ROLE flags_writer               NOLOGIN;
CREATE ROLE api_owner                  NOLOGIN;
CREATE ROLE lease_owner                NOLOGIN;
CREATE ROLE flags_admin                NOLOGIN;
CREATE ROLE flags_remover              NOLOGIN;
CREATE ROLE risk_owner                 NOLOGIN;

-- Every executor session, whatever the code does: a lock it cannot get within 5 s fails that
-- request (executor_error, the batch goes on) instead of hanging the only component that
-- writes effects. statement_timeout caps anything else that hangs.
ALTER ROLE executor SET lock_timeout = '5s';
ALTER ROLE executor SET statement_timeout = '30s';

-- api_set_temp_protection takes a home's advisory lock until its transaction ends. A tool session
-- left idle inside a transaction would keep the executor off that home, so it is ended after
-- 10 s. This only covers an honest tool that hangs: a role can change this setting in its own
-- session, so a hijacked tool can still hold the lock (docs/attacks.md, Not protected yet).
ALTER ROLE tool_read_ticket           SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE tool_lookup_account        SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE tool_request_disconnection SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE tool_issue_bill_credit     SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE tool_set_temp_protection   SET idle_in_transaction_session_timeout = '10s';

REVOKE TEMPORARY ON DATABASE supplier FROM PUBLIC;
REVOKE CREATE ON DATABASE supplier FROM PUBLIC;
REVOKE TEMPORARY ON DATABASE supplier_test FROM PUBLIC;
REVOKE CREATE ON DATABASE supplier_test FROM PUBLIC;
