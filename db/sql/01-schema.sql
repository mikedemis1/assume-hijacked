-- PostgreSQL grants EXECUTE to PUBLIC on every new function by default. In this database no
-- function is executable by PUBLIC: each one is granted to its callers by name. This changes the
-- default for functions created by the init user and by the function owners (02-roles.sql), so a
-- function added later starts closed even if its file forgets the REVOKE. Default privileges are
-- per database, which is why this is here and not in 02-roles.sql.
-- (tests/test_lease.py: test_no_function_in_public_is_executable_by_public)
ALTER DEFAULT PRIVILEGES FOR ROLE postgres, api_owner, lease_owner, flags_writer,
    risk_owner, staff_owner, demo_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE customers (
    id    int PRIMARY KEY,
    name  text NOT NULL,
    phone text NOT NULL
);

-- Supply point = αριθμός παροχής. Protection belongs to the home, not the account.
CREATE TABLE supply_points (
    id      text PRIMARY KEY,
    address text NOT NULL
);

-- One account per customer in this model: "the ticket owner's account" must be a single row,
-- or the tools and triggers that look it up would have to pick one.
CREATE TABLE accounts (
    id              int PRIMARY KEY,
    customer_id     int NOT NULL UNIQUE REFERENCES customers,
    supply_point_id text NOT NULL REFERENCES supply_points,
    tariff          text NOT NULL,
    status          text NOT NULL DEFAULT 'active'
);

CREATE TABLE tickets (
    id          int PRIMARY KEY,
    customer_id int NOT NULL REFERENCES customers,
    body        text NOT NULL,
    status      text NOT NULL DEFAULT 'open'
);

CREATE TABLE charges (
    id         int PRIMARY KEY,
    account_id int NOT NULL REFERENCES accounts,
    period     text NOT NULL,
    amount_eur numeric(10,2) NOT NULL
);

-- A row means "protected". No row means "not protected". Rows are only ever added: nobody may
-- change or delete one (07-flags.sql).
CREATE TABLE flags (
    supply_point_id text PRIMARY KEY REFERENCES supply_points,
    source          text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE action_requests (
    id              serial PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('credit', 'move_out')),
    ticket_id       int NOT NULL REFERENCES tickets,
    account_id      int NOT NULL REFERENCES accounts,
    amount_eur      numeric(10,2) CHECK (amount_eur IS NULL OR (amount_eur > 0 AND amount_eur <> 'NaN')),
    reason          text,
    evidence_ref    int,
    move_out_date   date,
    status          text NOT NULL DEFAULT 'pending',
    decision_reason text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    decided_at      timestamptz,
    -- sha256 of the lease the request was filed on. Set only inside api_request_credit and
    -- api_request_moveout (05-lease.sql); no role can write it (only api_owner has INSERT on it).
    -- NULL for a request filed any other way (tests, seed data).
    lease_hash      bytea
);

-- One effect request per lease, whichever tool files it. A hijacked tool pod holding a
-- valid lease cannot file a second credit or move-out request on it: the second insert fails.
CREATE UNIQUE INDEX action_requests_one_effect_per_lease ON action_requests (lease_hash)
    WHERE lease_hash IS NOT NULL;

-- Each request tool files only its own kind of request, and always for the account of
-- the customer who opened the ticket: the ticket decides, not the tool or the LLM.
-- A move-out needs a date that is today or later (UTC, the same date the order trigger uses),
-- or it would wait forever (NULL) or skip the customer's real date (past).
-- Tools file requests only through api_request_moveout / api_request_credit (05-lease.sql), which
-- already set the kind and take the account from the lease's ticket; this is the backstop behind
-- them. It checks session_user, the role that logged in: inside those SECURITY DEFINER functions
-- current_user is their owner (api_owner), and a login role cannot change its session_user.
-- Runs as the inserting role (current_user), which can read tickets and accounts: api_owner.
CREATE FUNCTION check_action_request() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    owner_account int;
BEGIN
    IF (session_user = 'tool_issue_bill_credit' AND NEW.kind <> 'credit')
       OR (session_user = 'tool_request_disconnection' AND NEW.kind <> 'move_out') THEN
        RAISE EXCEPTION '% cannot file a % request', session_user, NEW.kind;
    END IF;
    IF NEW.kind = 'move_out'
       AND (NEW.move_out_date IS NULL OR NEW.move_out_date < (now() AT TIME ZONE 'UTC')::date) THEN
        RAISE EXCEPTION 'a move-out needs a date of today or later, got %', NEW.move_out_date;
    END IF;
    IF session_user IN ('tool_issue_bill_credit', 'tool_request_disconnection') THEN
        SELECT a.id INTO owner_account
        FROM public.tickets t JOIN public.accounts a ON a.customer_id = t.customer_id
        WHERE t.id = NEW.ticket_id;
        IF owner_account IS NULL THEN
            RAISE EXCEPTION 'unknown ticket %', NEW.ticket_id;
        END IF;
        NEW.account_id := owner_account;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER action_requests_check BEFORE INSERT ON action_requests
    FOR EACH ROW EXECUTE FUNCTION check_action_request();

-- approver is the Entra object id the console validated, or a dev user id locally.
-- Rows are written only by approve_request (06-risk.sql), which refuses an id that is not on the
-- staff list and takes approver_role from that list. The database enforces that one person
-- counts once, whatever the spelling (check_approval_floor, 06-risk.sql).
CREATE TABLE approvals (
    request_id    int NOT NULL REFERENCES action_requests,
    approver      uuid NOT NULL,
    approver_role text NOT NULL DEFAULT 'Approver' CHECK (approver_role IN ('Approver', 'SeniorApprover')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, approver)
);

-- created_at is the database clock: the daily and monthly caps count by it, so the executor
-- cannot write it (03-grants.sql) and cannot date a credit outside the windows.
CREATE TABLE credits (
    id           serial PRIMARY KEY,
    request_id   int NOT NULL UNIQUE REFERENCES action_requests,
    account_id   int NOT NULL REFERENCES accounts,
    amount_eur   numeric(10,2) NOT NULL CHECK (amount_eur > 0 AND amount_eur <> 'NaN'),
    evidence_ref int NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- A credit pays exactly what its credit request asked for, to that request's account, against
-- that request's evidence. The executor decides whether to pay; this stops a bug from paying
-- another amount or account, or paying one charge twice under an evidence_ref nobody used yet.
-- The charges must also back it, the same evidence rule the executor applies: the
-- evidence is a charge on that account, an earlier charge has the same account, period and
-- amount (so this one is the duplicate), and the credit is no more than the charge.
-- Last, the approval floor (check_approval_floor, 06-risk.sql): the request needs a risk assessment
-- whose tier allows a credit, and as many distinct approvers as that tier asks for.
-- Runs as the inserting role (executor), which can read action_requests, charges,
-- risk_assessments and approvals.
CREATE FUNCTION check_credit() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    req    record;
    charge record;
BEGIN
    -- numeric takes 'NaN', which PostgreSQL sorts above every number, so a plain `> 0` lets it
    -- through. (Infinity cannot reach here: numeric(10,2) cannot hold it.)
    IF NOT (NEW.amount_eur > 0 AND NEW.amount_eur < 'Infinity') THEN
        RAISE EXCEPTION 'credit amount must be a positive finite number';
    END IF;
    SELECT kind, account_id, amount_eur, evidence_ref INTO req
    FROM public.action_requests WHERE id = NEW.request_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'credit for unknown request %', NEW.request_id;
    END IF;
    IF req.kind <> 'credit' THEN
        RAISE EXCEPTION 'request % is not a credit request', NEW.request_id;
    END IF;
    IF NEW.account_id IS DISTINCT FROM req.account_id THEN
        RAISE EXCEPTION 'credit for account % but request % is for account %',
            NEW.account_id, NEW.request_id, req.account_id;
    END IF;
    IF NEW.amount_eur IS DISTINCT FROM req.amount_eur THEN
        RAISE EXCEPTION 'credit of % but request % asked for %', NEW.amount_eur, NEW.request_id, req.amount_eur;
    END IF;
    IF NEW.evidence_ref IS DISTINCT FROM req.evidence_ref THEN
        RAISE EXCEPTION 'credit against evidence % but request % cites %',
            NEW.evidence_ref, NEW.request_id, req.evidence_ref;
    END IF;
    SELECT id, account_id, period, amount_eur INTO charge
    FROM public.charges WHERE id = NEW.evidence_ref;
    IF NOT FOUND OR charge.account_id IS DISTINCT FROM NEW.account_id THEN
        RAISE EXCEPTION 'evidence % is not a charge on account %', NEW.evidence_ref, NEW.account_id;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.charges
        WHERE account_id = charge.account_id AND period = charge.period
          AND amount_eur = charge.amount_eur AND id < charge.id
    ) THEN
        RAISE EXCEPTION 'charge % is not a duplicate of an earlier charge', charge.id;
    END IF;
    IF NEW.amount_eur > charge.amount_eur THEN
        RAISE EXCEPTION 'credit of % is above charge % of %', NEW.amount_eur, charge.id, charge.amount_eur;
    END IF;
    -- A ceiling no setting can raise. The executor's limits (CREDIT_AUTO_MAX_EUR and the others)
    -- are environment variables, so a bad deploy or a bug can set them to anything; this one
    -- takes a schema change. 500.00 is ten times the automatic limit and above any single
    -- residential charge in this model. A bigger refund is for finance, outside this system.
    IF NEW.amount_eur > 500.00 THEN
        RAISE EXCEPTION 'credit of % is above the hard cap of 500.00', NEW.amount_eur;
    END IF;
    PERFORM public.check_approval_floor(NEW.request_id, NULL);
    RETURN NEW;
END $$;

CREATE TRIGGER credits_check BEFORE INSERT ON credits
    FOR EACH ROW EXECUTE FUNCTION check_credit();

CREATE TABLE disconnection_orders (
    id              serial PRIMARY KEY,
    request_id      int NOT NULL UNIQUE REFERENCES action_requests,
    supply_point_id text NOT NULL REFERENCES supply_points,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Enforced on every order row whatever the executor code does. An order needs:
-- a move-out request that is still pending (not sent to a human as manual_only, nor rejected,
-- nor executed), for that request's own home (exact string), a home with no flag row, a
-- move-out date that has come, at least one staff approval given after the risk assessment (no
-- automatic move-out, even at a score that would be T0), and the approval floor: a risk
-- assessment whose tier allows an order, and as many distinct approvers as that tier asks for
-- (check_approval_floor, 06-risk.sql).
-- All times are the database's (now()), never a value the executor passes in. The date is
-- taken in UTC so a session cannot move it with SET TimeZone; Greece is ahead of UTC, so the
-- order can only come later than local midnight, never earlier.
-- Runs as the inserting role (executor), which can read every table used here.
-- The advisory lock is the same one api_set_temp_protection takes, so a flag being added and an
-- order being written for the same home cannot interleave: a flag added after the assessment
-- still blocks the order.
CREATE FUNCTION check_disconnection_order() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    req record;
BEGIN
    SELECT r.kind, r.status, r.move_out_date, a.supply_point_id AS home INTO req
    FROM public.action_requests r JOIN public.accounts a ON a.id = r.account_id
    WHERE r.id = NEW.request_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'order for unknown request %', NEW.request_id;
    END IF;
    IF req.kind <> 'move_out' THEN
        RAISE EXCEPTION 'request % is not a move-out request', NEW.request_id;
    END IF;
    IF req.status IS DISTINCT FROM 'pending' THEN
        RAISE EXCEPTION 'request % is %, not pending', NEW.request_id, req.status;
    END IF;
    -- 'SP-1003 ' or 'sp-1003' is a different string, so it is refused here too.
    IF NEW.supply_point_id IS DISTINCT FROM req.home THEN
        RAISE EXCEPTION 'the order is not for the home of request %', NEW.request_id;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(NEW.supply_point_id));
    IF EXISTS (SELECT 1 FROM public.flags WHERE supply_point_id = NEW.supply_point_id) THEN
        RAISE EXCEPTION 'the home of request % is protected', NEW.request_id;
    END IF;
    IF req.move_out_date IS NULL OR req.move_out_date > (now() AT TIME ZONE 'UTC')::date THEN
        RAISE EXCEPTION 'request % move-out date has not come yet', NEW.request_id;
    END IF;
    -- The floor first: it refuses a request without an assessment and counts the tier's approvals.
    PERFORM public.check_approval_floor(NEW.request_id, NULL);
    -- Then the rule the floor does not give: an order always needs a person, even at a tier
    -- that asks for no approval (T0).
    IF NOT EXISTS (
        SELECT 1 FROM public.approvals a JOIN public.risk_assessments k ON k.request_id = a.request_id
        WHERE a.request_id = NEW.request_id AND a.created_at > k.created_at
    ) THEN
        RAISE EXCEPTION 'request % has no staff approval given after its risk assessment', NEW.request_id;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER disconnection_orders_check BEFORE INSERT ON disconnection_orders
    FOR EACH ROW EXECUTE FUNCTION check_disconnection_order();

CREATE TABLE events (
    id         serial PRIMARY KEY,
    kind       text NOT NULL,
    actor      text NOT NULL DEFAULT current_user,
    detail     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
-- The only way into flags from a tool is api_set_temp_protection (05-lease.sql).
