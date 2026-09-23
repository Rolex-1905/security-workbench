# Security Infrastructure & Integrations

Research and implementation work on security infrastructure — SIEM deployments and external data source integrations.

| Write-up | Summary |
|---|---|
| [Wazuh SIEM: External Intelligence & EDR/Firewall Integrations](./wazuh-siem-integrations) | A consolidated implementation reference covering 8 integrations with Wazuh SIEM — typosquatting detection (Have I Been Squatted), threat intel feeds (Filescan.io, InsecureWeb), attack surface monitoring (Shodan.io), URL reputation (urlscan.io), and EDR/firewall ingestion (Symantec EDR, CrowdStrike Falcon, Sophos Firewall). Each integration is corrected against its original source material, renumbered into a collision-free custom rule ID scheme, and includes copy-paste-ready scripts, decoders, rules, and validation steps. |
