# Roadmap

Each item is one emulated attack → detection → case write-up. An item is checked off only when its case exists, linked from the item. This continues Phase 5 of the [enterprise-homelab roadmap](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/docs/roadmap.md), which moved here ([ADR 0011](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/docs/adr/0011-soc-casework-own-repo.md)).

## Lab cases
Ordered by what needs the least new work.
- [ ] SSH brute force against `linux-victim` (T1110.001). There's no SSH brute-force detection yet, so writing one is part of the case
- [ ] DNS tunneling / exfiltration (T1071.004). The [detection](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/detections/exfiltration-dns-tunneling.spl) exists, so this needs the emulation run and the write-up
- [ ] Web attack against `vuln-web`, e.g. SQL injection (T1190)
- [ ] Network scan and cross-VLAN probe (T1046), detected from the Omada gateway ACL logs ([detection](https://github.com/J-DeMarzo/enterprise-homelab/blob/main/detections/discovery-denied-probes-to-management.spl))

## Dataset investigations
- [ ] [Boss of the SOC](https://github.com/splunk/botsv3) investigations. These need no lab targets, so they can fill gaps between lab cases

## Waiting on lab work
These need infrastructure that's on the enterprise-homelab roadmap first.
- Windows cases: scheduled-task persistence (T1053.005) and LSASS credential dumping (T1003.001). Need the standalone Windows 11 target
- Cases worked in a case-management tool (TheHive or DFIR-IRIS) instead of Markdown only
