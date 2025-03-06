---
{"dg-publish":true,"permalink":"/zzzz/background-noise-and-attack-randomization/"}
---

[[README\|README]]
### Introduction
---
The problem with my current simulation is I know what happens, everything is planned out since I am performing both as attacker and defender, in short I know what to expect in the blue team side.
## Objective
---
- Replicate enterprise normal environment noise.
	- What's the criteria?
- Make it automated and possibly random as well such as random Google searches.
	- It is important to not make the script not botlike add some intervals between noises when using the Internet as for local area network or endpoint activities it does not matter.
	- Create both for Windows and Linux prioritise Windows.
- A great way to test created alerts or rules.
# The Criteria

#### Local Endpoint Activity
---
**File Operations**
- File operations such as creation, modification, and deletion on temp files, office documents and more.
**Process Launcher**
- Common processes such as `explorer.exe`, `notepad.exe`, web browsers, and email clients.
- Add scheduled tasks.
**User Logins**
- Succesful/Fail login attempts.
#### Network Traffic
---
**Web Browsing**
- Random Google Searches, harmless websites only.
**DNS queries**
**SMB/FTP**
**Email Traffic**

