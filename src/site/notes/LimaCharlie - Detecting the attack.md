---
{"dg-publish":true,"permalink":"/lima-charlie-detecting-the-attack/"}
---

[[LimaCharlie - Staging the attack\|LimaCharlie - Staging the attack]]

Here is our objective:

- Report any modification or access to the registry (commonly used for persistence mechanism) and to our sensitive files or folders.
- Report every network connection from the attacker's IP address.
### File & Registry Monitoring
---
**Automation** > **Registry Integrity Monitoring** > **Add Monitoring Rule:**

- **name**: registry
- **platforms:** Windows
- **tags:** windows
- **patterns:**

```C
\\Registry\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*
```

In HKEY_LOCAL_MACHINE (HKLM) contains system wide run or run once tasks and HKEY_CURRENT_USER (HKCU) is for the current user only, the `*` wildcard ensures that it matches both hives and keys, they are commonly used for persistence mechanism.

Creating the detection & response rule referencing the document [here](https://docs.limacharlie.io/docs/ext-integrity):

![Pasted image 20250316174959.png](/img/user/x/images/Pasted%20image%2020250316174959.png)
After succesfully adding the FIM/RIM rule, we can modify the persistence mechanism by using `regedit.exe`:

![Pasted image 20250316201507.png](/img/user/x/images/Pasted%20image%2020250316201507.png)
Then before making a detection & response rule, we can navigate to the said **sensor** (Windows machine) then **timeline** and search for the key name:

![Pasted image 20250316201610.png](/img/user/x/images/Pasted%20image%2020250316201610.png)
Now that we know what fields exist, we can create our detection & rules now:

```
event: FIM_HIT
op: exists
path: event/REGISTRY_KEY

# Response
- action: report
  name: Registry AutoRuns Activty - {{ .event.ACTION }}
```

- `{{ .event.ACTION }}` display the value of ACTION key.
- `op: exists` in other words as long as the condition exist which is the value found in `path`.

Try and modify the AutoRun persistence mechanism and go back to LimaCharlie:

![Pasted image 20250316210006.png](/img/user/x/images/Pasted%20image%2020250316210006.png)

**Note:** we can also check for changes in AutoRun using the bulit-in event: AUTORUN_CHANGE [here](https://docs.limacharlie.io/v2/docs/reference-edr-events#autorunchange).

Let's add another rule for monitoring any access to our `C:\SensitiveData` directory:

- name: sensitive-folder
- **platforms:** Windows
- **tags:** windows
- **pattern:** `?:\\SensitiveData`
	- `?` is used to match any single character.

The goal in cybersecurity is to gain visibility throughout our network however monitoring for file changes on the whole disk is not feasible and it will generate a lot of noise, therefore the blacklist method is great solution, we want to monitor for specific directories such as directories that contains sensitive data this is important for_compliances_.

- One example of compliance is **PCI DSS** standard basically it ensures that you satifies the required security controls needed when dealing with payment card data.
	- _Regulations_ are the rules.
	- _Compliance_ is the action of following the rules.

![Pasted image 20250316153944.png](/img/user/x/images/Pasted%20image%2020250316153944.png)
Then create a new **Detection & Rules**:

```C
# Detect
event: FIM_HIT
op: exists
path: event/FILE_PATH
# Response
- action: report
  name: FIM Hit - {{ .event.FILE_PATH }}
```

![Pasted image 20250316200243.png](/img/user/x/images/Pasted%20image%2020250316200243.png)
#### Detecting Network Connection from Attacker
---
One of the best practices after a security especially during the **recovery phase** of the incident response process, is increase monitoring, we want to make sure that there is no traces of the attack left after the **eradication phase**, so what should we monitor? Indicators of Compromise (IOCs) such as IP address or the hash of a malicious file, specific behaviors, and/or patterns:

Again the best way to create a detection & response rule is to navigate to an endpoint's **timeline**:

![Pasted image 20250319150025.png](/img/user/x/images/Pasted%20image%2020250319150025.png)

```
# Detect
event: NETWORK_CONNECTIONS
op: is
path: event/NETWORK_ACTIVITY/?/DESTINATION/IP_ADDRESS
value: 10.0.2.15

# Response
- action: report
  name: network connection to 10.0.2.15
```

The `?` is used so we don't have to specify the index number and then back to our Attacker's machine rerun the `exploit` command and re-execute our `payload.exe`:

![Pasted image 20250319160948.png](/img/user/x/images/Pasted%20image%2020250319160948.png)
















