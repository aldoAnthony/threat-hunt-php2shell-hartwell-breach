# KQL Queries

Every query cited in the [report](../REPORT.md), numbered in the order I ran it. All were run in Microsoft Sentinel against workspace LAW-HuntPractice, filtered on `OriginalTime`. Query 6 is not included: it was exploratory, and nothing in the report relies on it.

| Query | Purpose | Screenshot |
|---|---|---|
| [1](query-01-requests-per-source-address-to-identify-the.kql) | Requests per source address, to identify the scanner | [view](../images/query-01-requests-per-source-address-to-identify-the.png) |
| [2](query-02-user-agents-used-by-192-168-1.kql) | User agents used by 192.168.1.100 | [view](../images/query-02-user-agents-used-by-192-168-1.png) |
| [3](query-03-error-log-entries-from-192-168-1.kql) | Error-log entries from 192.168.1.100 | [view](../images/query-03-error-log-entries-from-192-168-1.png) |
| [4](query-04-search-of-all-web-tables-for-upload.kql) | Search of all web tables for upload_progress | [view](../images/query-04-search-of-all-web-tables-for-upload.png) |
| [5](query-05-method-and-content-type-per-source.kql) | Method and content type per source | [view](../images/query-05-method-and-content-type-per-source.png) |
| [7](query-07-first-appearance-of-health-check-php-in.kql) | First appearance of health-check.php in each table | [view](../images/query-07-first-appearance-of-health-check-php-in.png) |
| [8](query-08-processes-started-by-apache-or-php-by.kql) | Processes started by Apache or PHP, by user | [view](../images/query-08-processes-started-by-apache-or-php-by.png) |
| [9](query-09-header-names-on-requests-to-health-check.kql) | Header names on requests to health-check.php | [view](../images/query-09-header-names-on-requests-to-health-check.png) |
| [10](query-10-reversal-of-the-header-encoding-for-every.kql) | Reversal of the header encoding for every value | [view](../images/query-10-reversal-of-the-header-encoding-for-every.png) |
| [11](query-11-network-discovery-commands-run-by-www-data.kql) | Network discovery commands run by www-data | [view](../images/query-11-network-discovery-commands-run-by-www-data.png) |
| [12](query-12-process-service-and-security-tool-enumeration-by.kql) | Process, service and security-tool enumeration by www-data | [view](../images/query-12-process-service-and-security-tool-enumeration-by.png) |
| [13](query-13-configuration-file-access-by-www-data.kql) | Configuration-file access by www-data | [view](../images/query-13-configuration-file-access-by-www-data.png) |
| [14](query-14-mysql-queries-run-by-www-data.kql) | MySQL queries run by www-data | [view](../images/query-14-mysql-queries-run-by-www-data.png) |
| [15](query-15-service-control-commands-run-by-www-data.kql) | Service-control commands run by www-data | [view](../images/query-15-service-control-commands-run-by-www-data.png) |
| [16](query-16-service-stops-and-starts-and-logging-after.kql) | Service stops and starts, and logging after the stop attempts | [view](../images/query-16-service-stops-and-starts-and-logging-after.png) |
| [17](query-17-persistence-commands-run-by-www-data.kql) | Persistence commands run by www-data | [view](../images/query-17-persistence-commands-run-by-www-data.png) |
| [18](query-18-every-reference-to-dev-shm.kql) | Every reference to /dev/shm | [view](../images/query-18-every-reference-to-dev-shm.png) |
| [19](query-19-encoding-commands-matched-to-apache-response-sizes.kql) | Encoding commands matched to Apache response sizes | [view](../images/query-19-encoding-commands-matched-to-apache-response-sizes.png) |
| [20](query-20-lateral-movement-tools-internal-addresses-network-events.kql) | Lateral-movement tools, internal addresses, network events and SSH logins | [view](../images/query-20-lateral-movement-tools-internal-addresses-network-events.png) |
| [21](query-21-first-and-last-event-in-each-table.kql) | First and last event in each table | [view](../images/query-21-first-and-last-event-in-each-table.png) |
| [22](query-22-error-log-clock-offset-from-parse-errors.kql) | Error-log clock offset, from parse errors matched to Apache 500s | [view](../images/query-22-error-log-clock-offset-from-parse-errors.png) |
| [23](query-23-error-log-on-the-corrected-clock-beside.kql) | Error log on the corrected clock, beside non-login POSTs from 192.168.1.100 | [view](../images/query-23-error-log-on-the-corrected-clock-beside.png) |
| [24](query-24-logging-continuity-and-audit-rule-changes-around.kql) | Logging continuity and audit-rule changes around the stop attempts | [view](../images/query-24-logging-continuity-and-audit-rule-changes-around.png) |
| [25](query-25-events-per-table-12-20-13-50.kql) | Events per table, 12:20–13:50 | [view](../images/query-25-events-per-table-12-20-13-50.png) |
| [26](query-26-hashes-and-event-types-for-dev-shm.kql) | Hashes and event types for /dev/shm/.cache-helper and /usr/bin/sleep | [view](../images/query-26-hashes-and-event-types-for-dev-shm.png) |
| [27](query-27-ssh-logins-and-sudo-commands-2026-10.kql) | SSH logins and sudo commands, 2026-10-22 to 2026-10-23 | [view](../images/query-27-ssh-logins-and-sudo-commands-2026-10.png) |
| [28](query-28-requests-per-source-and-user-agent-with.kql) | Requests per source and user agent, with webshell and exploit contact | [view](../images/query-28-requests-per-source-and-user-agent-with.png) |
| [29](query-29-validation-of-detection-d1.kql) | Validation of detection D1 | [view](../images/query-29-validation-of-detection-d1.png) |
| [30](query-30-validation-of-detection-d2.kql) | Validation of detection D2 | [view](../images/query-30-validation-of-detection-d2.png) |
| [31](query-31-validation-of-detection-d3.kql) | Validation of detection D3 | [view](../images/query-31-validation-of-detection-d3.png) |
| [32](query-32-every-command-auditd-recorded-between-04-34.kql) | Every command auditd recorded between 04:34 and 05:25, before Sysmon was running | [view](../images/query-32-every-command-auditd-recorded-between-04-34.png) |
| [33](query-33-web-root-writes-joined-to-the-files.kql) | Web-root writes, joined to the files they touched and the account that made them | [view](../images/query-33-web-root-writes-joined-to-the-files.png) |
| [34](query-34-every-command-the-web-server-ran-across.kql) | Every command the web server ran across the window, outside the first run and the implant's cron runs | [view](../images/query-34-every-command-the-web-server-ran-across.png) |
