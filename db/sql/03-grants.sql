-- Applied to every database (supplier and supplier_test) after 01-schema.sql.
-- Roles and database-level REVOKEs live in 02-roles.sql. The lease, the five tool functions and
-- their owners' grants are in 05-lease.sql; the risk tables and theirs in 06-risk.sql; row-level
-- security in 08-rls.sql.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
-- USAGE only lets a role find names in the schema; what it may do there is granted per object.
GRANT USAGE ON SCHEMA public TO
    tool_read_ticket, tool_lookup_account, tool_request_disconnection,
    tool_issue_bill_credit, tool_set_temp_protection, executor, approver,
    gateway, risk_engine, dispatcher, api_owner, lease_owner, risk_owner, staff_owner;

-- Tools: no table, column or sequence grant at all. Each tool role may only EXECUTE its one
-- api_* function, which answers for the ticket of a live lease (05-lease.sql).

-- Audit trail: append only. Roles set kind and detail; actor (current_user) and
-- created_at (now()) come from the column defaults, so nobody can forge who or when.
GRANT INSERT (kind, detail) ON events TO executor, approver;
GRANT USAGE ON SEQUENCE events_id_seq TO executor, approver;

-- Executor: reads evidence and flags, decides, writes effects.
GRANT SELECT ON accounts, supply_points, charges, flags, approvals,
    credits, disconnection_orders, events, action_requests TO executor;
GRANT UPDATE (status, decision_reason, decided_at) ON action_requests TO executor;
-- No created_at: the database sets it, so the executor cannot date a credit outside the daily
-- and monthly windows.
GRANT INSERT (request_id, account_id, amount_eur, evidence_ref) ON credits TO executor;
GRANT INSERT (request_id, supply_point_id) ON disconnection_orders TO executor;
GRANT USAGE ON SEQUENCE credits_id_seq, disconnection_orders_id_seq TO executor;

-- Staff approval page.
GRANT SELECT ON action_requests TO approver;
-- Approvals are not inserted by the console role: it calls approve_request (06-risk.sql), which
-- checks the approver against the staff list and writes the row with the listed role and the
-- database clock.

-- Advisory locks (gap I9). By default PUBLIC may call these, so any tool role could hold a
-- home's lock and freeze the executor. Only the executor (its own lock and the order trigger)
-- and api_owner (api_set_temp_protection) take them. Function privileges live in each database,
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
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO executor, api_owner', f);
    END LOOP;
END $$;
