# Detection Engineering in Splunk: Scheduled Tasks and Brute Force

Graduation project, Vocational Higher Education in Cybersecurity.

A homelab built to practice detection engineering in Splunk Enterprise. I wrote and iterated on two alerts mapped to MITRE ATT&CK, tested them against simulated attacks and simulated background noise, and documented the reasoning behind each change.

## Contents

1. [Purpose and Scope](#purpose-and-scope)
2. [The Lab](#the-lab)
3. [Methodology](#methodology)
4. [Project Timeline](#project-timeline)
5. [Analysis and Alerts](#analysis-and-alerts)
   - [Alert 1: Scheduled Task Persistence (T1053.005)](#alert-1-scheduled-task-persistence-t1053005)
   - [Alert 2: Brute Force Logon Attempts (T1110.001)](#alert-2-brute-force-logon-attempts-t1110001)
6. [Results and Deliverables](#results-and-deliverables)
7. [Limitations](#limitations)
8. [Reflection](#reflection)
9. [Connection to My Future Role](#connection-to-my-future-role)
10. [Next Steps](#next-steps)
11. [References](#references)

---

## Purpose and Scope

This project was meant to exercise and improve my skills in Splunk Enterprise, with a focus on detection engineering through Splunk alerts. A second goal was practical: setting up VMs, configuring them, getting them to talk to each other, and forwarding logs between hosts.

**Core question:** How well can a detection rule tell real attack activity apart from ordinary system noise?

**Scope.** I limited the project to two techniques:

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |

I had some hands-on Splunk experience going in, though not relating to writing alerts, only querying existing datasets. A small scope meant I could go through a full detection engineering cycle for each technique (baseline rule, testing, iteration, validation) instead of producing several shallow, unvalidated rules. Depth over breadth was subsequently the trade-off.

**How I defined success:**

- False positive rate after tuning
- Whether each alert can be traced to a specific MITRE ATT&CK technique
- Whether the reasoning behind each iteration is documented, and not only the end result

---

## The Lab

The lab consists of three VMs running in VMware.

![Network diagram of the lab](images/network-diagram.png)

| Machine | Role |
|---|---|
| Windows 10 | Domain-joined workstation. Target for attack simulation and noise generation. Runs Sysmon. |
| Windows Server 2022 | Domain controller (Active Directory) |
| Ubuntu Server | Hosts Splunk Enterprise |

The setup instructions come from the [MyDFIR](https://www.youtube.com/@MyDFIR) YouTube playlist, with a few modifications to suit my needs. The biggest one was leaving out the Kali Linux VM, since the project focused on detection rather than offensive tooling and Atomic Red Team gave me enough technique simulation without it.

Two domain user accounts were created so the environment had some realistic user activity. Sysmon events are then forwarded to Splunk.

---

## Methodology

**Planning.** I used a Kanban board to plan and track the work, and kept a running log throughout the project.

**Attack simulation.** [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (ART) was a big part of the project. It generates telemetry for specific MITRE ATT&CK techniques on the target machine through PowerShell, which gives the alerts true positives to find. Without it: no data.

**Interview.** I did a qualitative interview with a former SOC analyst to get a sense of which alerts are common in practice and how a setup like mine compares to a larger enterprise environment. I asked about the most common alert they saw, typical false positive rates, whether they had worked with detection engineering, and for general advice. One suggestion I took seriously was to start from an imported baseline ruleset and refine from there, rather than writing everything from scratch.

### A problem I didn't expect: perfect alerts

Early on I noticed that ART had a blind spot. With no benign activity in the logs, any alert would look 100% accurate. An alert that only searched for `schtasks.exe` would return nothing except the simulated attack, because nothing else on the machine had a reason to use it.

That meant no iteration was needed to reach a perfect true-to-false-positive ratio. Not because the rule was well designed, but because it had never been tested against anything it could be confused with. A rule that hasn't been tested against realistic noise can't really be called validated.

### The noise generator

To fix this I wrote a PowerShell script (with the help of AI) that simulates what an office worker might do during a day: opening applications, creating scheduled tasks through legitimate means, and running standard administrative commands, at randomised intervals. The randomised timing builds on [this Microsoft scripting blog post](https://devblogs.microsoft.com/scripting/use-powershell-to-start-a-process-at-random-times/).

The script will be in [`scripts/`](scripts/) when I have access to my PC again.

### A second problem: noise that wasn't comparable

Building the generator exposed something more specific. My alert is built on Sysmon process-creation events (Event ID 1). Scheduled tasks created with the PowerShell cmdlet `Register-ScheduledTask` talk directly to the Task Scheduler service and don't spawn a new process, so they never produce Event ID 1. The alert ignored them, which looked like good filtering.

It wasn't, really. A real attacker using `schtasks.exe` directly would spawn a process and be caught, while my benign noise slipped past for a completely different reason. The noise wasn't comparable to the technique the alert was meant to detect. I extended the generator to also create tasks through `schtasks.exe`, so the noise would test the rule's actual logic and not just look plausible.

---

## Project Timeline

| Date | What happened |
|---|---|
| Early Sept | Lab setup, first ART runs for T1053.005 |
| Mid Sept | Realised the alert was "perfect" because of missing noise, wrote the noise generator |
| 15 Sept | Ran the noise generator for 45 minutes and narrowed the project down to two alerts |
| 16 Sept | Interview with a former SOC analyst |
| 22 Sept | Compared a naive alert with a refined one. Slow VMs and technical issues slowed progress. |
| 23 Sept | Ran noise alongside the alert: 15 hits, 66% false positive rate for the naive version |
| 28 Sept | Refined the scheduled task alert (see below) |
| 29 to 30 Sept | Built and iterated on the brute force alert |

![Kanban board](images/kanban-board.png) (also when i have access to my PC again)

---

## Analysis and Alerts

Each alert was evaluated on its true positive rate against ART and its false positive rate against the noise generator. I tried to look at *why* a result happened, not only record it. A rule that appeared to work wasn't treated as proof by itself.

### SPL cheat sheet

A short guide to reading the searches below.

| Part | Meaning |
|---|---|
| `index=endpoint` | Search the index where the endpoint logs are stored |
| `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | Only Sysmon events |
| `Event_ID=1` | Sysmon process creation |
| `Image="*\\schtasks.exe"` | The process that was started ends in `schtasks.exe` |
| `CommandLine="*/create*"` | The command line contains `/create` |
| `\| table ...` | Show the chosen fields as a table |

<!-- TODO: add short explanation of the commands used in the brute force searches -->

### Alert 1: Scheduled Task Persistence (T1053.005)

**Why it matters.** Attackers often gain persistence by abusing legitimate system features, which helps them avoid detection by AV and EDR. Scheduled tasks in Windows are one of many ways to do this, and they are also used constantly for legitimate purposes.

**Iteration 1: keyword search.** The first version looked for any mention of `schtasks.exe`. It returned every log generated by ART, but also every benign event from my noise generator. In practice that meant a false positive rate of about 66% (15 hits).

**Iteration 2: filter on creation.** I narrowed the search to `/create` events. This filtered out cleanup activity run by both ART and the noise generator, and returned 8 results. I switched to a table at this point for an easier overview.

<img width="1602" height="1183" alt="image" src="https://github.com/user-attachments/assets/1b769ce3-2aa8-4204-9b65-187bce8c8e67" />


**Current version:**

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" Event_ID=1 Image="*\\schtasks.exe" CommandLine="*/create*" (CommandLine="*/sc onstart*" OR CommandLine="*/sc onlogon*" OR CommandLine="*/ru*system*") | table _time host User ParentImage CommandLine
```

The extra conditions look for tasks that run at startup or logon, or that run as SYSTEM, since those are the patterns most relevant to persistence.

![Refined alert results](images/alert1-refined-results.png)

### Alert 2: Brute Force Logon Attempts (T1110.001)

**Why it matters.** Users forget their passwords all the time (a common theme on r/cybersecurity), and that can trigger brute force alerts. The question is how to separate regular user noise from an actual attack.

**Iteration 1: every logon and failure.** The first search tracked every interactive logon (Event ID 4624, logon type 2) and every failure (4625). At this point no ART test had been run, so there were no true positives to compare against. The search would clearly give a very high false positive rate.

<img width="753" height="102" alt="image" src="https://github.com/user-attachments/assets/ab48d384-6314-4ea7-9b73-7524cc296f47" />


**Iteration 2: add a threshold and time window.** Brute forcing follows a pattern: many passwords tried against one account in quick succession. A better search counts failures within a time window. I settled on 5 or more failed logons within 5 minutes. This caught all the brute force attempts generated by ART.

The numbers are somewhat arbitrary, though. Five in five is a starting point and not a result I could validate against real user behaviour.

<img width="1354" height="319" alt="image" src="https://github.com/user-attachments/assets/9a835c96-e62a-4bd5-834e-f8e98595f092" />



**Iteration 3: include success.** This version only tracks failed attempts. In a brute force scenario, the more interesting signal is several failures followed by a successful logon, because that suggests an account may have been compromised. I changed the search to account for that.

<img width="1384" height="384" alt="image" src="https://github.com/user-attachments/assets/689f3ede-b804-4920-a320-523bcfed319d" />



**A change in how I measured it.** Counting true and false positives became less meaningful here. To count them, I would first have to define what a true positive is. Only successful attacks where an account was compromised? Or anyone attempting brute force, even if they haven't succeeded yet? That is a question about what the alert is for, and it doesn't have one answer.

**Iteration 4: severity.** Instead of choosing, I added a final step that rates each alert by severity, depending on whether the attempt succeeded. The alert now has two purposes: it tracks both successful and failed attempts and categorises them accordingly.

<img width="1359" height="465" alt="image" src="https://github.com/user-attachments/assets/3aaf5db5-b624-453a-9b40-f5c14f53849e" />


---

## Results and Deliverables

- A working homelab with three integrated VMs, Splunk Enterprise and Sysmon log forwarding
- Two functioning Splunk detection rules, one for scheduled task creation (T1053.005) and one for brute force logons (T1110.001), each mapped to MITRE ATT&CK
- Each rule iterated on at least once, based on testing against both attack simulation and background noise
- A reusable noise generator script
- A documented account of the iteration process, including cases where an early version looked successful for the wrong reasons

---

## Limitations

I want to be upfront about what this project does not show.

- **A single small environment.** One workstation and two domain users is very far from a real network, so the false positive rates I measured should be read as illustrations of the method, not as benchmarks.
- **Simple noise.** The noise generator is a script of my own design. It covers a limited set of behaviours and was run for short periods (for example 45 minutes at a time).
- **Arbitrary thresholds.** The 5-in-5 limit for the brute force alert was not tuned against real data.
- **Simulation only.** All attack activity came from Atomic Red Team. Real attackers vary more.
- **Performance.** Slow VMs limited how much testing I could do.

---

## Reflection

The most important lesson was not about Splunk syntax. It was about what it means to validate a detection rule. Early on, a rule with zero false positives felt like a good outcome. It turned out to be a sign of a rule that hadn't been tested enough. Noticing that gap, and building a way to close it (first the noise generator, then making the noise comparable to the real technique), was more useful to me than any individual SPL query.

On the technical side I learned a lot about configuring VMs and getting them to work together, using the Linux command line through Ubuntu Server, how a SIEM is actually set up in a smaller organisation, and troubleshooting when something in a multi-machine setup doesn't work.

---

## Connection to My Future Role

This project connects to my SOC analyst internship. Understanding why an alert fires, or doesn't, is a core part of SOC work, and the habit of questioning an apparently good result before trusting it is something I expect to carry with me. Working from a baseline detection and refining it also mirrors how detection engineering usually works in practice, since analysts rarely start from a blank page.

I want to keep working in a SOC after the internship, and detection engineering is something I’d like to move toward over time. This project gave me a first look at that side of the work: writing a rule, testing it against both attack and noise, and finding out where it breaks. Questions like “what counts as a true positive?” and “how do I know this alert is actually doing its job?” are ones I’d like to keep working on, ideally with real data and people who have done this for years.

---

## Next Steps

- Import a basic baseline ruleset and compare it with my own rules
- Tune the brute force thresholds against more varied noise
- Make the noise generator more diverse
- Add more techniques now that the method and the lab are in place

---

## References

- [MITRE ATT&CK T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MyDFIR lab setup playlist](https://www.youtube.com/@MyDFIR)
- [Starting a process at random times with PowerShell](https://devblogs.microsoft.com/scripting/use-powershell-to-start-a-process-at-random-times/)
