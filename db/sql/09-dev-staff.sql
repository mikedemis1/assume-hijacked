-- Local development staff: the three identities the console's dev sign-in offers (AUTH_MODE=dev,
-- CONSOLE_DEV_USERS in deploy/helm/assume-hijacked/values-kind.yaml). Applied by db/init/init.sh
-- only when SEED_DEV_STAFF=yes (local, CI and kind callers). On Azure the list is filled by an admin
-- step (docs/azure.md, "Staff").
INSERT INTO staff (oid, display_name, roles) VALUES
    ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Dev Anna (Approver)',        '{Approver}'),
    ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Dev Bob (SeniorApprover)',   '{SeniorApprover}'),
    ('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'Dev Carol (SeniorApprover)', '{SeniorApprover}')
ON CONFLICT (oid) DO NOTHING;
