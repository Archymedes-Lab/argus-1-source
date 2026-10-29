# Spyware and covert-attack reading list — 2026-10-27

Compiled for ARGUS-1 by web search. Every entry was checked against a source
page (publisher, USENIX/NDSS/IEEE/ACM, arXiv, university repository or Citizen
Lab); reports and industry write-ups are marked as such. Spot-check: the newest
entry (arXiv 2608.01639) was re-fetched and matches.

## Start here

1. **Strider GhostBuster**: the cross-view diff behind hidden-process and hidden-file detection.
2. **Chatterjee 2018 and Freed 2018**: the threat model for spyware abuse that uses legitimate access.
3. **NoDoze and "Sometimes Simpler is Better"**: alert triage, and a reality check on provenance-graph detectors.
4. **Survivalism and EvilEDR**: LOTL coverage gaps, and the monitor itself as attack surface.
5. **Trace of the Times and "Tracing Provenance on Windows EDR Telemetry"**: eBPF and Windows telemetry that fit ARGUS-1's sensors.

## Part 1: foundational, by importance

### Stalkerware and intimate-partner surveillance

1. Freed et al., **"A Stalker's Paradise": How Intimate Partner Abusers Exploit Technology**, CHI 2018. https://unpaywall.org/10.1145/3173574.3174241. Abusers often hold legitimate credentials, so a monitor cannot treat them as benign.
2. Chatterjee et al., **The Spyware Used in Intimate Partner Violence**, IEEE S&P 2018. https://www.cs.cornell.edu/~rahul/papers/IPV_Spyware.pdf. Dual-use monitoring apps were missed by antivirus; detect by capability, not signature.
3. Havron et al., **Clinical Computer Security for Victims of Intimate Partner Violence**, USENIX Security 2019. https://www.usenix.org/conference/usenixsecurity19/presentation/havron. A field triage workflow.
4. Roundy et al., **The Many Kinds of Creepware Used for Interpersonal Attacks**, IEEE S&P 2020. https://pages.cs.wisc.edu/~roundy/papers/ieeesp-creepware.pdf. Co-occurrence scoring (CreepRank).

### Commercial and mercenary spyware

5. Marczak et al., **When Governments Hack Opponents**, USENIX Security 2014. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/marczak. Covers FinSpy and Hacking Team, with C2 fingerprinting.
6. Marczak and Scott-Railton, **The Million Dollar Dissident** (Citizen Lab report, 2016). https://citizenlab.ca/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/
7. Marczak et al., **Hide and Seek: Tracking NSO Group's Pegasus** (Citizen Lab report, 2018). https://citizenlab.ca/2018/09/hide-and-seek-tracking-nso-groups-pegasus-spyware-to-operations-in-45-countries/

### Rootkits, hidden processes and kernel integrity

8. Wang et al., **Detecting Stealth Software with Strider GhostBuster**, MSR TR-2005-25 / DSN 2005. https://www.microsoft.com/en-us/research/publication/detecting-stealth-software-with-strider-ghostbuster/
9. Petroni et al., **Copilot: a Coprocessor-based Kernel Runtime Integrity Monitor**, USENIX Security 2004. https://www.usenix.org/conference/13th-usenix-security-symposium/copilot%E2%80%94-coprocessor-based-kernel-runtime-integrity
10. Yin et al., **Panorama: Capturing System-Wide Information Flow for Malware Detection and Analysis**, ACM CCS 2007. https://www.cs.ucr.edu/~heng/pubs/panorama-ccs07.pdf
11. Ortolani et al., **Bait Your Hook: A Novel Detection Technique for Keyloggers**, RAID 2010. https://download.vusec.net/papers/raid-2010.pdf

### Provenance and causal intrusion detection

12. King and Chen, **Backtracking Intrusions**, SOSP 2003. https://web.eecs.umich.edu/~pmchen/papers/king03_1.pdf
13. Milajerdi et al., **HOLMES: Real-time APT Detection**, IEEE S&P 2019. https://arxiv.org/pdf/1810.01594
14. Hassan et al., **NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage**, NDSS 2019. https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage
15. Hassan, Bates and Marino, **Tactical Provenance Analysis for EDR Systems**, IEEE S&P 2020. https://www.cs.virginia.edu/~hur7wv/papers/hassan-oakland20.pdf
16. Han et al., **UNICORN: Runtime Provenance-Based Detector for APTs**, NDSS 2020. https://www.ndss-symposium.org/ndss-paper/unicorn-runtime-provenance-based-detector-for-advanced-persistent-threats

### Living off the land, C2 and EDR evaluation

17. Barr-Smith et al., **Survivalism: Systematic Analysis of Windows Malware Living-Off-The-Land**, IEEE S&P 2021. https://ora.ox.ac.uk/objects/uuid:6199c7e7-5021-4537-aa36-c23c9317ee77
18. Karantzas and Patsakis, **An Empirical Assessment of Endpoint Security Systems Against APT Attack Vectors**, 2021. https://arxiv.org/pdf/2108.10422
19. Gu et al., **BotHunter**, USENIX Security 2007. https://www.usenix.org/conference/16th-usenix-security-symposium/bothunter-detecting-malware-infection-through-ids-driven
20. Hu et al., **Baywatch: Robust Beaconing Detection**, IEEE/IFIP DSN 2016. https://pure.psu.edu/en/publications/baywatch-robust-beaconing-detection-to-identify-infected-hosts-in/

### Covert channels, tracking and method

21. Lampson, **A Note on the Confinement Problem**, CACM 1973. https://bwlampson.site/11-Confinement/WebPage.html
22. Yarom and Falkner, **FLUSH+RELOAD**, USENIX Security 2014. https://www.usenix.org/node/184416
23. Englehardt and Narayanan, **Online Tracking: A 1-million-site Measurement**, ACM CCS 2016. https://www.cs.princeton.edu/~arvindn/publications/OpenWPM_1_million_site_tracking_measurement.pdf
24. Arp et al., **Dos and Don'ts of Machine Learning in Computer Security**, USENIX Security 2022. https://usenix.org/conference/usenixsecurity22/presentation/arp

## Part 2: latest, newest first

1. Yuan et al., **Mutate to Bypass: Autonomous Endpoint Evasion via Knowledge-Driven Multi-Agent Orchestration**, arXiv, Aug 2026. https://arxiv.org/abs/2608.01639. LLM agents evaded all seven EDRs tested, with about 90% evasion of Defender; DLL side-loading kept working.
2. Liu, Inam et al., **How to Effectively Trace Provenance on Windows EDR Telemetry**, PRISM @ NDSS 2026. https://sts.cs.illinois.edu/papers/paper/HowtoEffectivelyTrac20260223.html
3. Munir et al., **Every Keystroke You Make: Event Listeners for Wiretapping**, arXiv, Aug 2025. https://arxiv.org/abs/2508.19825. Browser keystroke capture and session replay.
4. Raz et al., **Ransomware 3.0: Self-Composing and LLM-Orchestrated**, arXiv, Aug 2025. https://arxiv.org/abs/2508.20444
5. Bilot et al., **Sometimes Simpler is Better: provenance-based IDS analysis**, USENIX Security 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/bilot
6. Jiang et al., **ORTHRUS: Quality of Attribution in Provenance-based IDS**, USENIX Security 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang
7. Alachkar et al., **EvilEDR: Repurposing EDR as an Offensive Tool**, USENIX Security 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/alachkar. The monitor's own control surface can be the attack, which bears on ARGUS-1's local API.
8. **Graphite Caught: Paragon iOS mercenary spyware** (Citizen Lab report), June 2025. https://citizenlab.ca/2025/06/first-forensic-confirmation-of-paragons-ios-mercenary-spyware-finds-journalists-targeted/
9. Landauer et al., **Trace of the Times: Rootkit Detection through Temporal Anomalies in Kernel Activity**, ACM DTRAP 2025. https://arxiv.org/abs/2503.02402. eBPF timing as a rootkit signal.
10. Liu et al., **First Early Evidence of Browser Fingerprinting for Online Tracking**, WWW 2025. https://spies.engr.tamu.edu/2025/01/20/2-papers-accepted-to-www-2025/ (only the lab announcement was verified).
11. Alageel and Maffeis, **EarlyCrow: Detecting APT C2 over HTTP(S)**, arXiv 2025. https://arxiv.org/abs/2502.05367
12. Guri, **RAMBO: covert radio exfiltration from RAM**, arXiv 2024. https://arxiv.org/abs/2409.02292
13. Jia et al., **MAGIC: masked graph learning for APT detection**, USENIX Security 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/jia
14. Cheng et al., **KAIROS: whole-system provenance IDS**, IEEE S&P 2024. https://arxiv.org/abs/2308.05034
15. Rehman, Ahmadi and Hassan, **FLASH: provenance graph representation learning**, IEEE S&P 2024 (title and venue confirmed via citations, paper page not reached).
16. Matsuo et al., **SmmPack: Obfuscation for SMM Modules with TPM Sealed Key**, DIMVA 2024. https://arxiv.org/abs/2405.04355
17. Mangeard et al., **WARNE: a stalkerware evidence collection tool**, FSI: Digital Investigation, DFRWS EU 2024. https://dfrws.org/presentation/warne-a-stalkerware-evidence-collection-tool/
18. Zaidenberg et al., **Detecting eBPF Rootkits Using Virtualization and Memory Forensics**, ICISSP 2024. https://scitepress.org/PublishedPapers/2024/124708
19. Carvalho Junior, **HookChain: Bypassing EDR Solutions**, arXiv 2024. https://arxiv.org/abs/2404.16856
20. Scalabrino, Fasano and Oliveto, **An Empirical Study on the Effectiveness of Privacy Indicators**, IEEE TSE 2023. https://unpaywall.org/10.1109/TSE.2023.3308392
21. Nadim, Lee and Akopian, **Kernel-level Rootkit Detection: a Taxonomy and Survey**, arXiv 2023. https://arxiv.org/abs/2304.00473
22. **ESET Research: BlackLotus UEFI bootkit** (industry analysis), March 2023. https://www.eset.com/us/about/newsroom/research/eset-research-analyzes-blacklotus-a-uefi-bootkit-that-can-bypass-uefi-secure-boot-on-fully-patched-systems

## Gaps in the literature

No peer-reviewed 2023-2026 paper at IEEE S&P or USENIX Security was found on
stalkerware, UEFI bootkits or session-replay measurement. In those areas the
best current sources are industry write-ups and journals.
