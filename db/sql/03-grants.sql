-- Applied to every database (supplier and supplier_test) after 01-schema.sql.
-- Roles and database-level REVOKEs live in 02-roles.sql.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO
    tool_read_ticket, tool_lookup_account, tool_request_disconnection,
    tool_issue_bill_credit, tool_set_temp_protection, executor, approver, flags_writer;

-- Tools: read only the columns their code reads, write requests only. Nobody here can read flags.
-- Only tool_read_ticket reads the ticket text; the others see who owns a ticket, not what it says.
-- Rows are not scoped: each role still sees these columns for every customer (docs/attacks.md, Not protected yet).
GRANT SELECT (id, body) ON tickets TO tool_read_ticket;
GRANT SELECT (id, customer_id) ON tickets
    TO tool_lookup_account, tool_request_disconnection, tool_issue_bill_credit;
-- lookup_account returns name, tariff, status and address. No phone.
GRANT SELECT (id, name) ON customers TO tool_lookup_account;
GRANT SELECT (customer_id, supply_point_id, tariff, status) ON accounts TO tool_lookup_account;
GRANT SELECT (id, address) ON supply_points TO tool_lookup_account;
-- The request tools (and check_action_request, which runs as them) only map a ticket owner to an account id.
GRANT SELECT (id, customer_id) ON accounts TO tool_request_disconnection, tool_issue_bill_credit;
GRANT INSERT (kind, ticket_id, account_id, amount_eur, reason, evidence_ref, move_out_date)
    ON action_requests TO tool_request_disconnection, tool_issue_bill_credit;
GRANT USAGE ON SEQUENCE action_requests_id_seq TO tool_request_disconnection, tool_issue_bill_credit;

-- Audit trail: append only. Roles set kind and detail; actor (current_user) and
-- created_at (now()) come from the column defaults, so nobody can forge who or when.
GRANT INSERT (kind, detail) ON events TO
    tool_read_ticket, tool_lookup_account, tool_request_disconnection,
    tool_issue_bill_credit, executor, approver;
-- flags_writer runs set_temp_protection and records the calling role (session_user) as actor.
GRANT INSERT (kind, actor, detail) ON events TO flags_writer;
GRANT USAGE ON SEQUENCE events_id_seq TO
    tool_read_ticket, tool_lookup_account, tool_request_disconnection,
    tool_issue_bill_credit, executor, approver, flags_writer;

-- flags_writer owns the single write path into flags.
GRANT SELECT (id, customer_id) ON tickets TO flags_writer;
GRANT SELECT (customer_id, supply_point_id) ON accounts TO flags_writer;
GRANT SELECT, INSERT ON flags TO flags_writer;  -- SELECT for ON CONFLICT; NOLOGIN role
ALTER FUNCTION set_temp_protection(int) OWNER TO flags_writer;
REVOKE ALL ON FUNCTION set_temp_protection(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION set_temp_protection(int) TO tool_set_temp_protection;

-- Executor: reads evidence and flags, decides, writes effects.
GRANT SELECT ON accounts, supply_points, charges, flags, register_sync, approvals,
    credits, occupier_notices, disconnection_orders, events, action_requests TO executor;
GRANT UPDATE (status, decision_reason, decided_at) ON action_requests TO executor;
-- No sent_at / created_at: the database sets them, so the executor cannot back-date a notice
-- or date a credit outside the daily and monthly windows.
GRANT INSERT (request_id, account_id, amount_eur, evidence_ref) ON credits TO executor;
GRANT INSERT (request_id, supply_point_id) ON occupier_notices, disconnection_orders TO executor;
GRANT USAGE ON SEQUENCE credits_id_seq, occupier_notices_id_seq, disconnection_orders_id_seq TO executor;

-- Staff approval page.
GRANT SELECT ON action_requests TO approver;
-- No created_at: the database sets it, so an approval cannot be back-dated or post-dated.
GRANT INSERT (request_id, approver) ON approvals TO approver;

-- Advisory locks (gap I9). By default PUBLIC may call these, so any tool role could hold a
-- home's lock and freeze the executor. Only the executor (its own lock and the order trigger)
-- and flags_writer (set_temp_protection) take them. Function privileges live in each database,
-- which is why this is here and not in 02-roles.sql. Unlock functions stay public: a session
-- can only release locks it holds.
DO $$
DECLARE
    f regprocedure;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
        WHERE p.pronamespace = 'pg_catalog'::regnamespace
          AND p.proname IN ('pg_advisory_lock', 'pg_advisory_lock_shared',
                            'pg_try_advisory_lock', 'pg_try_advisory_lock_shared',
                            'pg_advisory_xact_lock', 'pg_advisory_xact_lock_shared',
                            'pg_try_advisory_xact_lock', 'pg_try_advisory_xact_lock_shared')
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO executor, flags_writer', f);
    END LOOP;
END $$;
