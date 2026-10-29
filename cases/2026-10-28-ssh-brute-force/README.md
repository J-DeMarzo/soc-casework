# CASE-2026-001: SSH brute force against linux-victim

| | |
|---|---|
| **Date** | 2026-10-29 |
| **Analyst** | demarzo |
| **Severity** | High: a password was guessed and the attacker logged in |
| **Verdict** | True positive |
| **ATT&CK** | T1110.001: Password Guessing · T1078.003: Valid Accounts: Local Accounts |
| **Detection** | None fired: there was no SSH brute-force detection, so this was found by a manual search. Written as a result: [`credential-access-ssh-brute-force.spl`](https://github.com/J-DeMarzo/enterprise-homelab/blob/08e78c1012cd673ec569635d287070cb8ce5b0c6/detections/credential-access-ssh-brute-force.spl) ([§8](#8-detection-improvements)) |

## 1. Alert
No detection covers SSH authentication on `linux-victim`, so nothing reached the alert queue. The activity was found with a manual search of sshd events on the host over a 1-hour window: a burst of about 140 authentication events in two minutes, 16:28–16:29, almost all from `10.12.40.102` ([`01-auth-events-by-source.png`](evidence/01-auth-events-by-source.png)).

```spl
index=linux host=linux-victim ("Failed password" OR "Accepted password" OR "authentication failure" OR "Invalid user")
| rex "for (?:invalid user )?(?<user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| timechart span=1m count by src_ip
```

That this went unalerted is itself a finding: a successful brute force on a lab host produced no alert.

## 2. Triage
**Is it real?** ✅ Yes. In the previous 24 hours, the only sshd login on `linux-victim` was a key-based admin login for `demarzo` from `ops` (10.12.5.10) ([`00-baseline-sshd-24h.png`](evidence/00-baseline-sshd-24h.png)). 119 failed passwords in 96 seconds from one source is not a person mistyping.

**Did it work?** ✅ Yes. `10.12.40.102` logged in as `brutis` with a password at 16:29:53 ([`03-accepted-passwords.png`](evidence/03-accepted-passwords.png)).

**Likely impact:** an interactive shell as `brutis` on `linux-victim`. The host also accepts password logins, so any other account with a weak password is exposed the same way.

### Local LLM first pass
A summarized search sent to the lab's local model with [`scripts/llm-triage.sh`](../../scripts/llm-triage.sh), before the investigation below. Input: the 3-row output of the scope search in [§3 Q2](#q2-which-sources-and-accounts-and-how-many-attempts). Output: [`evidence/llm-triage.md`](evidence/llm-triage.md). Each claim is checked against the data.

| Model's claim | Checked against | Result |
|---|---|---|
| "Automated login attempts originating from two source IPs" | Q1, Q2 · [`01`](evidence/01-auth-events-by-source.png), [`02`](evidence/02-scope-by-source-user-outcome.png) | ❌ Only `10.12.40.102` is automated. `10.12.5.10` made one login, 44 s before the attack started |
| `10.12.40.102`: 120 events, 119 failures + 1 success | Q2 · [`02`](evidence/02-scope-by-source-user-outcome.png) | ✅ correct |
| `10.12.5.10`: 1 event, 1 success | Q2, Q3 · [`02`](evidence/02-scope-by-source-user-outcome.png), [`03`](evidence/03-accepted-passwords.png) | ✅ correct |
| Only user `brutis` is involved | Q2 · [`02`](evidence/02-scope-by-source-user-outcome.png) | ✅ correct |
| Time range 16:27:35.238574 to 16:29:55.615369 | Q2 · [`02`](evidence/02-scope-by-source-user-outcome.png) | ✅ correct |
| "119 failed attempts immediately preceding a success" | Q2 · [`02`](evidence/02-scope-by-source-user-outcome.png) | ❌ The last failure (16:29:55.6) came 2.4 s **after** the success (16:29:53.2). The failures didn't all come before it |
| Brute force / password guessing | Q1–Q3 | ✅ correct |
| (not mentioned) | Q3 · [`03`](evidence/03-accepted-passwords.png) | ⚠️ Missed that the `10.12.5.10` login is the first event in the window and needs explaining |

**Takeaway:** in 35 seconds the model got the counts, the account, the time range and the classification right, so it saved typing up the table. It got two things wrong that matter for scoping: it merged a separate login into the attack, and it implied the attacker stopped at the success. The data it was given has no host names or network context, so identifying the source (Q4) and what happened after the login (Q5) were always going to be the analyst's job.

## 3. Investigation

### Q1. Is anything unusual in SSH authentication on linux-victim?
Yes. See the search in [§1](#1-alert). There are 141 events in the hour: a spike at 16:28 and 16:29 from `10.12.40.102`, one event from `10.12.5.10` at 16:27, and about 20 with no `src_ip` ([`01`](evidence/01-auth-events-by-source.png)). The no-`src_ip` events are PAM `authentication failure` lines, which name the source as `rhost=` rather than `from`, so the regex doesn't extract it. They appear in the same minutes as the `Failed password` lines, so they are the same attempts logged a second time. The searches below leave them out.

### Q2. Which sources and accounts, and how many attempts?
```spl
index=linux host=linux-victim ("Failed password" OR "Accepted password" OR "Invalid user")
| rex "(?<action>Failed|Accepted) password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval outcome=if(action="Accepted","success","failure")
| stats count min(_time) as first max(_time) as last by src_ip user outcome
| convert ctime(first) ctime(last)
| sort - count
```

| src_ip | user | outcome | count | first | last |
|---|---|---|---|---|---|
| 10.12.40.102 | brutis | failure | 119 | 16:28:19.327 | 16:29:55.615 |
| 10.12.40.102 | brutis | success | 1 | 16:29:53.180 | 16:29:53.180 |
| 10.12.5.10 | brutis | success | 1 | 16:27:35.239 | 16:27:35.239 |

Evidence: [`02-scope-by-source-user-outcome.png`](evidence/02-scope-by-source-user-outcome.png).

- One source, one account. No `Invalid user` events, so the attacker already knew `brutis` existed. It wasn't a username spray.
- About 1.2 attempts per second, for 96 seconds.
- 3 failures were logged after the success, one from each of the other three connections. auditd shows those three passwords were rejected at 16:29:53.126–.189, alongside the success at .162. sshd then wrote `Failed password` about 2.4 s later, at 16:29:55.552–.615, after PAM's failure delay. So the guessing stopped at the success; the failures were only logged late. Evidence: `USER_AUTH` and `USER_LOGIN res=failed` records for sshd PIDs 11891, 11895 and 11897 in [`05-brutis-after-login.csv`](evidence/05-brutis-after-login.csv).

### Q3. Did any login succeed?
```spl
index=linux host=linux-victim "Accepted password"
| rex "for (?<user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| table _time user src_ip
```
Two did, both as `brutis` ([`03-accepted-passwords.png`](evidence/03-accepted-passwords.png)):
- 16:29:53.180 from `10.12.40.102`: the brute force succeeded. ❌ The account is compromised.
- 16:27:35.238 from `10.12.5.10`, which is `ops`, the admin workstation ([DNS records](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/docs/architecture/dns.md)). This isn't part of the attack: it is a different source, on the Management VLAN, 44 s before the first failure, with no failures before it. It's still unusual, because admin logins in this lab are key-based as `demarzo` ([compute](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/docs/architecture/compute.md)), and the baseline confirms that ([`00`](evidence/00-baseline-sshd-24h.png)). The account owner confirmed it: a manual login from `ops` to check the host was reachable. ✅ Benign.

### Q4. What is 10.12.40.102, and did the firewall see it?
```spl
index=netfw src_ip=10.12.40.102
```
The firewall didn't see any of it. The only event is the Omada controller's DHCP lease at 16:25:56: `10.12.40.102` was given to MAC `BC:24:11:B3:C6:B2` ([`04-netfw-kali-dhcp-only.png`](evidence/04-netfw-kali-dhcp-only.png)). In the Proxmox config that MAC is `net0` of **`kali`** (VM 250), the lab attack box. `linux-victim` is on the same VLAN, 40 ([`proxmox-net0.txt`](evidence/proxmox-net0.txt), [inventory](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/docs/inventory.md)).

So the source is the lab's own attack box, and the brute force stayed inside VLAN 40. Traffic within a VLAN is switched without passing through the gateway, so the Omada ACL logs never see it. ❌ **Blind spot:** for attacks host to host within a VLAN, the host's own logs are the only record.

### Q5. What did brutis do after logging in?
```spl
index=linux host=linux-victim earliest="10/29/2026:16:29:53" latest="10/29/2026:17:30:00"
    (brutis OR auid=1002 OR uid=1002) NOT "Failed password"
| table _time sourcetype _raw
```
This found 119 events (104 auditd, 15 journald), all between 16:29:53.002 and 16:30:03.745. Nothing involving `brutis` was logged in the 86 minutes after that. Full export: [`05-brutis-after-login.csv`](evidence/05-brutis-after-login.csv); first page: [`05-brutis-after-login.png`](evidence/05-brutis-after-login.png).

**The SSH session lasted 458 ms.** sshd opened session 153 at 16:29:53.181 and closed it at 16:29:53.638, with no shell or commands from the client. The client logged in and disconnected straight away.

**Root commands under `AUID="brutis"` look alarming but are normal.** 63 auditd `execve` records in session 153 have `UID="root"` and `AUID="brutis"`. Read without context, that looks like privilege escalation. It isn't: this is Ubuntu building the login message (MOTD). At session start, PAM runs `run-parts` on `/etc/update-motd.d/` as root. The login UID is already set by then, so auditd tags every command with the user who logged in. Every command fits:
- the MOTD scripts themselves: `00-header`, `10-help-text`, `50-landscape-sysinfo`, `50-motd-news`, `85-fwupd`, `90-updates-available`, `91-release-upgrade`, `92-unattended-upgrades`, `95-hwe-eol`, `97-overlayroot`, `98-fsck-at-reboot`, `98-reboot-required`;
- the helpers they call: `landscape-sysinfo`, `date`, `cut`, `grep`, `egrep`, `cat`, `env`, `find`, `uname`, `stat`, `id`, `bc`, `awk`, `sort`, `expr`, `tr`, `head`, `chmod`, `who`.

All of them ran between 16:29:53.339 and the session close.

**Session 154 is systemd, not the attacker.** This was `brutis`'s first login, so `pam_systemd` started a per-user systemd manager (session 154, parent PID 1), running as `brutis`. It ran its generators and `systemctl` at start (16:29:53.2–.3). Its last `systemctl` calls, at 16:30:03.7, came 10 s after the session closed. That matches logind's default `UserStopDelaySec=10s`, after which the user manager shuts down.

**The parallel connections ran out of attempts.** At 16:29:57.45–.50, sshd dropped the three other connections from 10.12.40.102 (ports 34192, 34206, 34216) with `maximum authentication attempts exceeded`. Each had hit sshd's per-connection limit.

✅ No commands at the attacker's direction. The attacker confirmed the password, disconnected within half a second, and did nothing with it.

## 4. Timeline
| Time (UTC) | Host | Event | Source |
|---|---|---|---|
| 2026-10-28 20:40:42 | linux-victim | Baseline: `Accepted publickey for demarzo from 10.12.5.10` | [`00`](evidence/00-baseline-sshd-24h.png) |
| 2026-10-29 16:25:56 | Omada controller | DHCP gives `10.12.40.102` to `BC:24:11:B3:C6:B2` (`kali`) | [`04`](evidence/04-netfw-kali-dhcp-only.png) |
| 16:27:35.238 | linux-victim | `Accepted password for brutis from 10.12.5.10` (`ops`). Benign availability check | [`03`](evidence/03-accepted-passwords.png) |
| 16:28:19.327 | linux-victim | First `Failed password for brutis from 10.12.40.102` | [`02`](evidence/02-scope-by-source-user-outcome.png) |
| 16:29:53.180 | linux-victim | `Accepted password for brutis from 10.12.40.102`. **Compromise** | [`02`](evidence/02-scope-by-source-user-outcome.png), [`03`](evidence/03-accepted-passwords.png) |
| 16:29:53.339 | linux-victim | MOTD scripts run as root in session 153 (system behavior) | [`05`](evidence/05-brutis-after-login.csv) |
| 16:29:53.638 | linux-victim | `session closed for user brutis`, 458 ms after login. No commands | [`05`](evidence/05-brutis-after-login.csv) |
| 16:29:55.615 | linux-victim | Last `Failed password` from 10.12.40.102 (119 in total; the last 3 are delayed logs of attempts made before the success) | [`02`](evidence/02-scope-by-source-user-outcome.png) |
| 16:29:57.453–.496 | linux-victim | Three other connections from 10.12.40.102 dropped: `maximum authentication attempts exceeded` | [`05`](evidence/05-brutis-after-login.csv) |
| 16:30:03.745 | linux-victim | Last event involving `brutis`: the per-user systemd manager stopping, 10 s after the session closed. Nothing after this, to 17:30 | [`05`](evidence/05-brutis-after-login.csv) |

## 5. Indicators
| Type | Value | Context |
|---|---|---|
| IP | `10.12.40.102` | Source of the brute force and the successful login. DHCP lease on VLAN 40 |
| MAC | `BC:24:11:B3:C6:B2` | `kali` (VM 250), holder of 10.12.40.102 |
| User | `brutis` | Targeted account; password guessed and used to log in at 16:29:53 |
| Host | `linux-victim` | Target; accepts SSH password logins |
| IP | `10.12.5.10` | `ops`. One password login as `brutis` before the attack. Benign: owner's availability check |

## 6. Conclusion
`kali` (10.12.40.102) guessed the password for the local account `brutis` on `linux-victim` over SSH: 119 failures in 96 seconds, then a successful login at 16:29:53 UTC. The attacker already knew the username. The traffic stayed inside VLAN 40, so the gateway firewall recorded nothing, and with no SSH brute-force detection in place, no alert fired. The host's journald logs are the only record.

It went no further than the login. The SSH session lasted 458 ms, the only commands in it were Ubuntu's own login scripts, and nothing involving `brutis` was logged after 16:30:03 (Q5). The impact is a valid credential in the attacker's hands. The host itself wasn't compromised. Nothing was contained during the activity, so the password still works until it's reset.

## 7. Response and recommendations
What an analyst would do in production:

1. **Contain:** lock `brutis` (`usermod -L`, expire the password), kill its sessions, and block `10.12.40.102` on the host. Because the source is on the same VLAN, a gateway rule wouldn't help.
2. **Scope:** Q5 found nothing after the login, so handle it as an account compromise, not a host compromise. Check whether the same password is used anywhere else, and search other hosts for logins from `10.12.40.102` or as `brutis`.
3. **Eradicate:** reset `brutis`'s password. There's nothing else to remove.
4. **Harden:**
   - Turn off SSH password authentication (`PasswordAuthentication no`). Key-only SSH is already the standard on every admin host ([compute](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/docs/architecture/compute.md)).
   - Add fail2ban, as on `sefi`: a ban after 3 failures would have stopped this after 3 attempts.
   - Use `AllowUsers` so only expected accounts can log in over SSH.
5. **Visibility:** for traffic inside a VLAN, consider logging from the Proxmox VM firewall (`firewall=1` is already set on both NICs) or a network sensor on VLAN 40.

## 8. Detection improvements
**New detection:** [`credential-access-ssh-brute-force.spl`](https://github.com/J-DeMarzo/enterprise-homelab/blob/08e78c1012cd673ec569635d287070cb8ce5b0c6/detections/credential-access-ssh-brute-force.spl), committed in `08e78c1`.

It's built from this case's findings:
- **Counts one line per attempt.** It counts `Failed password` lines only. The PAM `authentication failure` lines log the same attempts again (Q1).
- **Fires at 10 failures from one source against one host** in a 15-minute window, on every Linux host. It counts usernames, so a spray across many accounts is caught too. The 24 h baseline has no failed passwords at all, since admin logins are key-based (Q1).
- **Rates it high if the attack worked.** That means a password login from the same source after its first failure (Q3). The `ops` login before the attack doesn't count.
- **Keeps working when the firewall can't see the traffic.** It reads the host's own sshd logs, which are the only record of traffic within a VLAN (Q4).

✅ **Tested against this attack:** run by hand over 16:20–16:35, without `collect`. It returned one **high** hit: *"10.12.40.102 (security) failed 119 SSH passwords on linux-victim for 1 user(s), then logged in as brutis"*. The ops login wasn't flagged ([`06-detection-test.png`](evidence/06-detection-test.png)).

✅ **Tested on schedule after deployment:** two more Hydra runs from 10.12.40.102 were each picked up by the next 15-minute run and written to the Alert queue ([`07-alert-queue.png`](evidence/07-alert-queue.png)):

| Attack (UTC) | Result | Run (UTC) | Alert |
|---|---|---|---|
| 18:02:53–18:09:06 | 224 failures, no login | 18:15 | **medium**, `succeeded=0`, T1110.001 |
| 18:27:04–18:28:22 | 119 failures, login as `brutis` at 18:28:20 | 18:45 | **high**, `succeeded=1`, T1110.001 + T1078.003 |

Both severity paths work. The alerts came 6 and 17 minutes after each attack ended. With the 15-minute schedule and 5-minute indexing delay, the worst case is about 20 minutes.

**Known gap:** if the success comes in the next 15-minute window, after fewer than 10 failures in that window, the alert stays medium.

## Evidence
| File | What it shows |
|---|---|
| [`00-baseline-sshd-24h.png`](evidence/00-baseline-sshd-24h.png) | sshd events on linux-victim over the 24 h before: only key-based admin logins from `ops` |
| [`01-auth-events-by-source.png`](evidence/01-auth-events-by-source.png) | Auth events per minute by source (Q1) |
| [`02-scope-by-source-user-outcome.png`](evidence/02-scope-by-source-user-outcome.png) | Counts and first/last times by source, user and outcome (Q2) |
| [`03-accepted-passwords.png`](evidence/03-accepted-passwords.png) | The two successful password logins (Q3) |
| [`04-netfw-kali-dhcp-only.png`](evidence/04-netfw-kali-dhcp-only.png) | Only a DHCP lease for 10.12.40.102 in `netfw`; no firewall events (Q4) |
| [`proxmox-net0.txt`](evidence/proxmox-net0.txt) | MAC and VLAN of `kali` and `linux-victim` (Q4) |
| [`05-brutis-after-login.csv`](evidence/05-brutis-after-login.csv) | All 119 events involving `brutis` from the login to 17:30: login, MOTD scripts, session close, systemd user manager (Q2, Q5) |
| [`05-brutis-after-login.png`](evidence/05-brutis-after-login.png) | The same search, first page (Q5) |
| [`06-detection-test.png`](evidence/06-detection-test.png) | New SSH brute-force detection run over the attack window: one high hit (§8) |
| [`07-alert-queue.png`](evidence/07-alert-queue.png) | The deployed detection's scheduled alerts for two test reruns: medium (no login) and high (login) (§8) |
| [`llm-triage.md`](evidence/llm-triage.md) | Local LLM first pass on the Q2 output |

## Appendix: emulation details
- **Target setup (2026-10-28):** created the local user `brutis` on `linux-victim` with a password ([`appendix-create-brutis.png`](evidence/appendix-create-brutis.png)). Enabled password authentication with `PasswordAuthentication yes` in `/etc/ssh/sshd_config.d/60-cloudimg-settings.conf`; the target is otherwise key-only ([rebuild runbook](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/docs/runbooks/rebuild-targets.md)). `brutis` is uid 1002 ([`appendix-sshd-password-auth.png`](evidence/appendix-sshd-password-auth.png)). Snapshot `BrutisCreated` taken.
- **Splunk time zone** set to GMT so every time in the case is UTC ([`appendix-splunk-timezone.png`](evidence/appendix-splunk-timezone.png)).
- **Atomic Red Team:** this version has no Linux SSH test for T1110.001. The tests listed are Azure AD (-3) and sudo brute force (-5, -6, -7) ([`appendix-atomic-t1110-001.png`](evidence/appendix-atomic-t1110-001.png)).
- **Attack:** [Hydra](https://github.com/vanhauser-thc/thc-hydra) v9.7 from `kali` (10.12.40.102) against `linux-victim` (10.12.40.103), started 16:28:16 UTC ([`appendix-hydra-command.png`](evidence/appendix-hydra-command.png)):
  ```
  hydra -l brutis -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/best110.txt -t 4 -V -f -o ~/hydra-ssh.txt ssh://10.12.40.103
  ```
  One login (`-l brutis`), the 110-entry SecLists `best110.txt` list, 4 parallel tasks (`-t 4`), and stop at the first valid password (`-f`). The 3 other tasks' attempts were already in flight when the password was found, which explains the 3 failures logged after the success (Q2). sshd then dropped those three connections at its per-connection attempt limit (Q5), and `-f` stopped Hydra from starting new ones. sshd logged 120 attempts for a 110-entry list, so Hydra retried some, probably after dropped connections. No commands were run after the login.
- **16:27:35 login from `ops`:** the operator logged in as `brutis` from `ops` to confirm `linux-victim` was up before starting the run.
- **Detection tests (after the investigation):** after deploying the detection, Hydra was run twice more from `kali`. The first run, from 18:02 UTC, didn't find the password. The password was then changed to one in `best110.txt`, and the second run, 18:27–18:28 UTC, logged in. `kali`'s clock is on US Eastern time, so its output reads 4 hours behind UTC.
