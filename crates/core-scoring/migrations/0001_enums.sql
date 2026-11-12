CREATE TYPE protocol_enum AS ENUM ('tcp', 'udp', 'icmp');

CREATE TYPE category_enum AS ENUM ('honeypot', 'ids', 'network', 'waf', 'auth');

CREATE TYPE feed_tier_enum AS ENUM ('aggressive', 'standard');

CREATE TYPE signal_type_enum AS ENUM (
    'honeypot_connection',
    'honeypot_login_attempt',
    'honeypot_command_exec',
    'honeypot_malware_upload',
    'honeypot_file_download',
    'suricata_sev1',
    'suricata_sev2',
    'suricata_sev3',
    'port_scan',
    'syn_flood',
    'blocked_connection',
    'waf_sqli_xss',
    'waf_generic_block',
    'ssh_brute_force',
    'catchall_probe',
    'remote_auth_failure'
);

-- Used by the review sub-project (sub-project 4), defined here so the schema is complete.
CREATE TYPE review_state_enum AS ENUM ('pending', 'approved', 'rejected', 'snoozed');
