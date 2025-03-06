---
{"dg-publish":true,"permalink":"/endpoint-security/soc-101-windows-event-logs-challenge/","tags":["endpoint"]}
---

[[endpoint-security/Endpoint Security\|Endpoint Security]]

> What is the **hostname** of the computer that generated the logs in the `challenge.evtx` file?

DESKTOP-1M5L0T9 

> What is the **Process ID (PID)** of the execution process that cleared the security event log?

![SOC 101 - Windows Event Logs Challenge-2.png](/img/user/endpoint-security/images/SOC%20101%20-%20Windows%20Event%20Logs%20Challenge-2.png)

> Which user account was added to the **Backup Operators** group?

note: There may be cases where the system can't resolve the **MemberName** field. However, you can still **correlate** a user account's unique Security Identifier (SID) from the user creation event.

sysadmin since in the account creation:

![SOC 101 - Windows Event Logs Challenge.png](/img/user/endpoint-security/images/SOC%20101%20-%20Windows%20Event%20Logs%20Challenge.png)
Then here:

![SOC 101 - Windows Event Logs Challenge-1.png](/img/user/endpoint-security/images/SOC%20101%20-%20Windows%20Event%20Logs%20Challenge-1.png)


