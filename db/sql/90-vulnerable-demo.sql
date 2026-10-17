-- DEMO ONLY. Applied by db/init/init.sh to the stack database only when DEMO_VULNERABLE=1, and
-- never to the test database (tests add it for the tests of the VULNERABLE switch, then drop it).
--
-- The hole the demo shows (docs/attacks.md, row 1): lookup_account trusts a customer id from the
-- model instead of the lease's ticket. The lease is still checked, so this leaks only during a
-- live lease that lists lookup_account, and only to tool_lookup_account. With VULNERABLE=true the
-- agent passes customer_id on and lookup_account calls this function instead of
-- api_lookup_account. Without this file, VULNERABLE=true leaks nothing: the call fails.
CREATE OR REPLACE FUNCTION api_lookup_account_any(p_lease text, p_customer int)
RETURNS TABLE(name text, tariff text, status text, address text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_ticket int;
BEGIN
    -- Same check as api_lookup_account (05-lease.sql): session_user, live lease, tool listed.
    SELECT l.ticket_id INTO v_ticket FROM public.leases l
    WHERE session_user = 'tool_lookup_account'
      AND l.token_hash = sha256(convert_to(p_lease, 'UTF8'))
      AND NOT l.revoked AND l.expires_at > clock_timestamp()
      AND 'lookup_account' = ANY (l.allowed_tools);
    IF v_ticket IS NULL THEN
        RAISE EXCEPTION 'lease invalid';
    END IF;
    RETURN QUERY
        SELECT c.name, a.tariff, a.status, s.address
        FROM public.accounts a
        JOIN public.customers c ON c.id = a.customer_id
        JOIN public.supply_points s ON s.id = a.supply_point_id
        WHERE a.customer_id = p_customer;  -- the hole: any customer, not the lease's ticket owner
END $$;

ALTER FUNCTION api_lookup_account_any(text, int) OWNER TO api_owner;
REVOKE ALL ON FUNCTION api_lookup_account_any(text, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api_lookup_account_any(text, int) TO tool_lookup_account;
