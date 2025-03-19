---
{"dg-publish":true,"permalink":"/google-cloud/cloud-shell-and-gcloud/","tags":["gcloud"]}
---

[[]]

### Configuring our environment
---
**Note:** It is important to set the environment near our customers.
```bash
gcloud config set compute/region us-west1
```

Show project region:
```bash
gcloud config get-value compute/region
```

Setting the zone:
```bash
gcloud config set compute/zone us-west1-a
```

Show project zone:
```bash
gcloud config get-value compute/zone
```

**View Project ID**
```bash
gcloud config get-value project
```

**View details about the project**
```C
gcloud compute project-info describe --project $(gcloud config get-value project)
```

Output:
![Pasted image 20250312150449.png](/img/user/x/images/Pasted%20image%2020250312150449.png)
#### Setting Environment Variables
---
Store project ID:
```bash
export PROJECT_ID=$(gcloud config get-value project)
```

```bash
export ZONE=$(gcloud config get-value compute/zone)
```

Verify with the following command:
```bash
echo -e "PROJECT ID: $PROJECT_ID\nZONE: $ZONE"
```

![Pasted image 20250312150634.png](/img/user/x/images/Pasted%20image%2020250312150634.png)
### Creating a Virtual Machine
---

```bash
gcloud compute instances create gcelab2 --machine-type e2-medium --zone $ZONE
```

- `gcloud compute` basically this is the command line version of creating VM instances.
- `instances create` creates a new instance.
- `gcelab2` is the name of the VM.
- The `--machine-type` flag specifies the machine type as _e2-medium_.
- The `--zone` flag specifies where the VM is created.

the man page about `instance create`:
```c
gcloud compute instances create --help
```

**View all available instances in the project**
```C
gcloud compute instances list
```

![Pasted image 20250312151347.png](/img/user/x/images/Pasted%20image%2020250312151347.png)

Filter out the **gcelab2** machine:
```
gcloud compute instances list --filter="name=('gcelab2')"
```

List all the firewall rules in this project:
```
gcloud compute firewall-rules list
```

List the firewall for the `default` network:
```C
gcloud compute firewall-rules list --filter="network='default'"
```

Another filter using the `AND` operator:
```
gcloud compute firewall-rules list --filter="NETWORK:'default' AND ALLOW:'icmp'"
```

Connect to the machine via ssh:
```
gcloud compute ssh gcelab2 --zone $zone
```

Accessing the `nginx` server is impossible as the firewall does not allow connection to tcp:80:

![Pasted image 20250312151848.png](/img/user/x/images/Pasted%20image%2020250312151848.png)
To allow this we simply need to do first is to create a tag then reference it when adding the firewall rules
```bash
gcloud compute instances add-tags gcelab2 --tags http-server,https-server
```

Firewall rule to allow  http.
```bash
gcloud compute firewall-rules create default-allow-http --direction=INGRESS --priority=1000 --network=default --action=ALLOW --rules=tcp:80 --source-ranges=0.0.0.0/0 --target-tags=http-server
```

![Pasted image 20250312152118.png](/img/user/x/images/Pasted%20image%2020250312152118.png)
### Accessing and Viewing Logs
---

```C
gcloud logging logs list
```

![Pasted image 20250312152216.png](/img/user/x/images/Pasted%20image%2020250312152216.png)

View logs specific to **compute** resources:

```C
gcloud logging logs list --filter="compute"
```

![Pasted image 20250312152254.png](/img/user/x/images/Pasted%20image%2020250312152254.png)

