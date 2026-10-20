-- The demo UI (app/demo): a customer chat in front of the agent, and a read-only panel of what the
-- walls decided. Applied to every database after 08-rls.sql. The roles are in 02-roles.sql.
--
--   demo_portal  the chat. Three functions and no table grant: list the fictional customers
--                (the dev sign-in), open a ticket for a customer, read the reply to that
--                customer's own ticket.
--   demo_ops     the panel. Read-only on the audit tables, by column. Never ticket text, names,
--                phones, addresses, flags, or the argument values of a tool call.
--
-- The demo is a new door into the system, so both roles get as little as the chat and the panel
-- need. Which customer a request is for is decided by the demo's session, never by the message.

-- Seed tickets use small ids (1-4 here, 101-111 for the attack suite); chat tickets start above them.
CREATE SEQUENCE demo_ticket_id_seq START 1000;
ALTER SEQUENCE demo_ticket_id_seq OWNER TO demo_owner;

-- What the demo may touch is marked, not guessed from ids:
--   demo_customers  the customers the demo signs in as (seeded in 04-seed.sql, the fictional three)
--   demo_tickets    the tickets opened through portal_open_ticket, and only those
-- portal_reply answers for a ticket in demo_tickets and no other, so a seeded ticket, one filed by
-- scripts/new-ticket.sh or one of the attack suite gets no answer here whoever asks.
CREATE TABLE demo_customers (
    customer_id int PRIMARY KEY REFERENCES customers ON DELETE CASCADE
);
CREATE TABLE demo_tickets (
    ticket_id   int PRIMARY KEY REFERENCES tickets ON DELETE CASCADE,
    customer_id int NOT NULL REFERENCES demo_customers ON DELETE CASCADE
);
ALTER TABLE demo_customers OWNER TO demo_owner;
ALTER TABLE demo_tickets OWNER TO demo_owner;

GRANT USAGE ON SCHEMA public TO demo_owner;
GRANT INSERT (id, customer_id, body) ON tickets TO demo_owner;
GRANT SELECT (ticket_id, text) ON replies TO demo_owner;
GRANT SELECT (id, name) ON customers TO demo_owner;
-- The tables have forced row-level security (08-rls.sql); the owner of the functions needs a policy.
CREATE POLICY demo_owner_tickets ON tickets FOR INSERT TO demo_owner WITH CHECK (true);
CREATE POLICY demo_owner_replies ON replies FOR SELECT TO demo_owner USING (true);
CREATE POLICY demo_owner_customers ON customers FOR SELECT TO demo_owner USING (true);

-- The customer comes from the demo's session. The body is the customer's message, 1 to 2000 characters.
CREATE FUNCTION portal_open_ticket(p_customer int, p_body text) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_id int;
BEGIN
    IF p_body IS NULL OR p_body !~ '[^[:space:]]' OR length(p_body) > 2000 THEN
        RAISE EXCEPTION 'message must be 1 to 2000 characters';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.demo_customers WHERE customer_id = p_customer) THEN
        RAISE EXCEPTION 'unknown customer';
    END IF;
    v_id := nextval('public.demo_ticket_id_seq');
    INSERT INTO public.tickets (id, customer_id, body) VALUES (v_id, p_customer, p_body);
    INSERT INTO public.demo_tickets (ticket_id, customer_id) VALUES (v_id, p_customer);
    RETURN v_id;
END $$;

-- The reply to a ticket this customer opened through the demo. No row while the agent is still
-- working, and no row for another customer's ticket or for any ticket the demo did not open (the
-- same answer, so the chat cannot be used to probe tickets).
CREATE FUNCTION portal_reply(p_customer int, p_ticket int) RETURNS TABLE(text text)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT r.text FROM public.replies r JOIN public.demo_tickets d ON d.ticket_id = r.ticket_id
    WHERE d.ticket_id = p_ticket AND d.customer_id = p_customer;
$$;

-- The sign-in page lists the demo's fictional customers: id and name, nothing else.
CREATE FUNCTION portal_customers() RETURNS TABLE(id int, name text)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT c.id, c.name FROM public.customers c JOIN public.demo_customers d ON d.customer_id = c.id ORDER BY c.id;
$$;

ALTER FUNCTION portal_open_ticket(int, text) OWNER TO demo_owner;
ALTER FUNCTION portal_reply(int, int) OWNER TO demo_owner;
ALTER FUNCTION portal_customers() OWNER TO demo_owner;
REVOKE ALL ON FUNCTION portal_open_ticket(int, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION portal_reply(int, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION portal_customers() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION portal_open_ticket(int, text) TO demo_portal;
GRANT EXECUTE ON FUNCTION portal_reply(int, int) TO demo_portal;
GRANT EXECUTE ON FUNCTION portal_customers() TO demo_portal;

-- The panel: what the walls decided, by ticket. The lease_hash columns tie a ticket's run to the
-- gateway's and the risk engine's records of its calls (it is a hash, never the lease).
GRANT SELECT (ticket_id, lease_hash, status, created_at) ON agent_runs TO demo_ops;
GRANT SELECT (id, lease_hash, tool, arg_names, dropped_args, outcome, reason, created_at) ON tool_calls TO demo_ops;
GRANT SELECT (id, lease_hash, tool, decision, created_at) ON call_assessments TO demo_ops;
GRANT SELECT (id, kind, ticket_id, amount_eur, status, decision_reason, created_at) ON action_requests TO demo_ops;
GRANT SELECT (request_id, tier, reasons, created_at) ON risk_assessments TO demo_ops;
-- replies.kind says where the stored text came from (agent, safe, template); agent_events is the
-- agent's own report of what it dropped, names only (05-lease.sql). Neither role reads reply text here.
GRANT SELECT (ticket_id, kind, created_at) ON replies TO demo_ops;
GRANT SELECT (id, ticket_id, kind, tool, arg_names, reported_at) ON agent_events TO demo_ops;
GRANT SELECT (request_id, created_at) ON credits TO demo_ops;
GRANT SELECT (request_id, created_at) ON disconnection_orders TO demo_ops;
GRANT SELECT (request_id, approver_role, created_at) ON approvals TO demo_ops;
-- The security console shows whether the kill switch is on: the one flag, not the reason.
GRANT SELECT (paused) ON agent_control TO demo_ops;
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['agent_runs', 'tool_calls', 'call_assessments', 'action_requests',
                            'risk_assessments', 'replies', 'agent_events', 'agent_control']
    LOOP
        EXECUTE format('CREATE POLICY demo_ops_read ON %I FOR SELECT TO demo_ops USING (true)', t);
    END LOOP;
END $$;

-- The executor's failures for these requests: the request id and the error class only (the event
-- detail is "credit request=<id>: <ErrorClass>", written by app/executor). A database trigger that
-- refuses a credit or an order shows up here as RaiseException. The role gets no grant on events.
CREATE FUNCTION demo_request_errors(p_ids int[])
RETURNS TABLE(request_id int, error text, created_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT m[1]::int, m[2], e.created_at
    FROM public.events e,
         LATERAL regexp_match(e.detail, '^(?:credit|move_out)[a-z_ ]* request=([0-9]+): ([A-Za-z]+)$') AS m
    WHERE e.kind = 'executor_error' AND m IS NOT NULL AND m[1]::int = ANY(p_ids)
    ORDER BY e.id DESC LIMIT 50;
$$;
GRANT SELECT (id, kind, detail, created_at) ON events TO demo_owner;
ALTER FUNCTION demo_request_errors(int[]) OWNER TO demo_owner;
REVOKE ALL ON FUNCTION demo_request_errors(int[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION demo_request_errors(int[]) TO demo_ops;
