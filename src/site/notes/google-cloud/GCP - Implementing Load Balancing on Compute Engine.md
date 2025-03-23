---
{"dg-publish":true,"permalink":"/google-cloud/gcp-implementing-load-balancing-on-compute-engine/","tags":["gcloud"]}
---

[[google-cloud/Google Cloud\|Google Cloud]]

1. Ensure region and zones are all set.
2.  For this scenario: creating three web server instances using the compute engine.

Replace `ww1` with another name such as `ww2`, and `ww3`:
```
  gcloud compute instances create www1 \
    --zone=us-central1-c \
    --tags=network-lb-tag \
    --machine-type=e2-small \
    --image-family=debian-11 \
    --image-project=debian-cloud \
    --metadata=startup-script='#!/bin/bash
      apt-get update
      apt-get install apache2 -y
      service apache2 restart
      echo "
<h3>Web Server: www1</h3>" | tee /var/www/html/index.html'
```

After creating three instances of web server, we need to allow external traffic through port 80:

**Note:** the `network-lb-tag` is used to refer to all three web server instances:
```C
gcloud compute firewall-rules create www-firewall-network-lb \
    --target-tags network-lb-tag --allow tcp:80
```

Determine the external IP address of each instance and make a GET request using `curl`:

```C
gcloud compute instances list
```

![Pasted image 20250320171225.png](/img/user/x/images/Pasted%20image%2020250320171225.png)
Then with curl:

![Pasted image 20250320171336.png](/img/user/x/images/Pasted%20image%2020250320171336.png)
### Configuring Load Balancing Service
---
_Load Balancing_ is the distribution of incoming network traffic across similar instances, which in the case of Google Cloud are what is called **backends**, backends are VM instances or containers to ensure reliability, scalability, and performance.

Create a static external IP address for our load balancer:
```C
gcloud compute addresses create network-lb-ip-1 \
  --region us-central1
```

- `gcloud compute addresses create` creates a new external IP address.
- `network-lb-ip-1` the name assigned to the IP address.
- `--region us-central1` specifies the region where the static IP will be created.

Output:
```C
Created [https://www.googleapis.com/compute/v1/projects/qwiklabs-gcp-03-xxxxxxxxxxx/regions/us-central1/addresses/network-lb-ip-1].
```

**Add a legacy HTTP health check resource:**
```C
gcloud compute http-health-checks create basic-check
```

- `basic-check` is the name.
- `http-health-checks` is used by Google Cloud to monitor the health of your backend services by sending an HTTP request.

**Add a target pool in the same region as your instances. Run the following to create the target pool and use the health check, which is required for the service to function:**

A _target pool_ is a collection of virtual machine (VM) instances used by a **Network Load Balancer** to distribute incoming traffic

```C
gcloud compute target-pools create www-pool \
  --region us-central1 --http-health-check basic-check
```

- `create www-pool` the name of the target pool.
- ` --region us-central1` the region where the target pool is created.
- `--http-health-check basic-check` → Associates the previously created **HTTP health check** (`basic-check`) with this target pool.

**Add the instances to the target pool:**

```
gcloud compute target-pools add-instances www-pool \
    --instances www1,www2,www3
```

**Add a forwarding rule**

This command make use of the static IP address created using it's friendly name and the load balancing services will choose from the target pool if needed:

```
gcloud compute forwarding-rules create www-rule \
    --region  us-central1 \
    --ports 80 \
    --address network-lb-ip-1 \
    --target-pool www-pool
```

### Send Traffic
---
Enter the following command to view the external IP address of the www-rule forwarding rule used by the load balancer:
```
gcloud compute forwarding-rules describe www-rule --region us-central1
```

![Pasted image 20250320173301.png](/img/user/x/images/Pasted%20image%2020250320173301.png)
Store the above output in an environment variable:
```C
IPADDRESS=$(gcloud compute forwarding-rules describe www-rule --region us-central1 --format="json" | jq -r .IPAddress)
```

Send some traffic, we should expect the response from curl have alternating IP address using the static IP address:

```C
while true; do curl -m1 $IPADDRESS; done
```

![Pasted image 20250320173507.png](/img/user/x/images/Pasted%20image%2020250320173507.png)
### Creating an Application Load Balancer
---
_Application Load Balancer_, it is managed by Google Front End (GFE), allows to smartly distributes traffic such as ability to route requests based on configurable **URL rules**, and intelligently routes requests to the nearest instance group using a concept called **proximity-based routing** the request is sent to the closest group that **does** have capacity.

**Create a load balancer template:**

```
gcloud compute instance-templates create lb-backend-template \
   --region=us-central1 \
   --network=default \
   --subnet=default \
   --tags=allow-health-check \
   --machine-type=e2-medium \
   --image-family=debian-11 \
   --image-project=debian-cloud \
   --metadata=startup-script='#!/bin/bash
     apt-get update
     apt-get install apache2 -y
     a2ensite default-ssl
     a2enmod ssl
     vm_hostname="$(curl -H "Metadata-Flavor:Google" \
     http://169.254.169.254/computeMetadata/v1/instance/name)"
     echo "Page served from: $vm_hostname" | \
     tee /var/www/html/index.html
     systemctl restart apache2'
```

- `gcloud compute instance-templates create lb-backend-template`
	- This creates an **instance template** named `lb-backend-template`.
	- Instance templates are blueprints for creating VM instances with pre-defined settings.
- `--network=default` & `--subnet=default`
	- Specifies that the VM instances will be on the **default VPC network** and **default subnet**.
- `--tags=allow-health-check`
	- Tags are labels used for network firewall rules.
-  `--machine-type=e2-medium` →
    - Specifies the machine type (**e2-medium**) with **2 vCPUs** and **4 GB RAM**.
    - This is a cost-effective machine for basic applications.
- `--image-family=debian-11` & `--image-project=debian-cloud`
    - It uses **Debian 11** (a Linux distribution) as the operating system.

**Managed Instance Groups (MIGs):**
- MIGs use instance templates to deploy multiple identical VMs.
- They ensure high availability by automatically scaling VMs based on traffic.

**Create a managed instance group based on template:**
```C
gcloud compute instance-groups managed create lb-backend-group \
   --template=lb-backend-template --size=2 --zone=us-central1-c
```

**Create a firewall rule to allow health checks:**
```
gcloud compute firewall-rules create fw-allow-health-check \
  --network=default \
  --action=allow \
  --direction=ingress \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 \
  --target-tags=allow-health-check \
  --rules=tcp:80
```

- `--source-ranges=130.211.0.0/22,35.191.0.0/16` - These are specific IP address ranges used by **Google Cloud health check systems**.
- **Target tags** are labels used to apply firewall rules to specific VMs.

Set up a global static external IP address that your customers use to reach your load balancer:

```
gcloud compute addresses create lb-ipv4-1 \
  --ip-version=IPV4 \
  --global
```

Then view the IP address with this command:
```C
gcloud compute addresses describe lb-ipv4-1 \
  --format="get(address)" \
  --global
```

![Pasted image 20250320175143.png](/img/user/x/images/Pasted%20image%2020250320175143.png)
**Create a health check for the load balancer:**
```
gcloud compute health-checks create http http-basic-check \
  --port 80
```

**Create a backend service:**

```
gcloud compute backend-services create web-backend-service \
  --protocol=HTTP \
  --port-name=http \
  --health-checks=http-basic-check \
  --global
```

**Add your instance group as the backend to the backend service:**

```C
gcloud compute backend-services add-backend web-backend-service \
  --instance-group=lb-backend-group \
  --instance-group-zone=us-central1-c \
  --global
```

**Create a URL map to route incoming requests to the default backend service:**
```C
gcloud compute url-maps create web-map-http \
    --default-service web-backend-service
```

> [!NOTE]- URL MAP
> **Note:** URL map is a Google Cloud configuration resource used to route requests to backend services or backend buckets. For example, with an external Application Load Balancer, you can use a single URL map to route requests to different destinations based on the rules configured in the URL map:
> 
> - Requests for https://example.com/video go to one backend service.
> - Requests for https://example.com/audio go to a different backend service.
> - Requests for https://example.com/images go to a Cloud Storage backend bucket.
> - Requests for any other host and path combination go to a default backend service.

Create a target HTTP proxy to route requests to your URL map:
```
gcloud compute target-http-proxies create http-lb-proxy \
    --url-map web-map-http
```

Create a global forwarding rule to route incoming requests to the proxy:
```
gcloud compute forwarding-rules create http-content-rule \
   --address=lb-ipv4-1\
   --global \
   --target-http-proxy=http-lb-proxy \
   --ports=80
```

##### Testing the configuration
---

1. On the Google Cloud console title bar, type **Load balancing** in the **Search** field, then choose **Load balancing** from the search results.
    
2. Click on the load balancer that you just created, **web-map-http**.
    
3. In the **Backend** section, click on the name of the backend and confirm that the VMs are **Healthy**. If they are not healthy, wait a few moments and try reloading the page.
    
4. When the VMs are healthy, test the load balancer using a web browser, going to `http://IP_ADDRESS/`, replacing `IP_ADDRESS` with the load balancer's IP address that you copied previously.


