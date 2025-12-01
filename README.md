# Infra Automation Toolkit  

*A collection of Python and Bash automation tools designed to diagnose, validate, and recover infrastructure servers in large-scale compute environments.*



## Overview

The **Infra Automation Toolkit** is a modular set of automation scripts created to standardize troubleshooting workflows, accelerate server bring-up, and reduce manual operational work across HPC, compute, and enterprise infrastructure.



These tools support environments where hundreds of servers require consistent checks, metadata validation, Redfish power operations, DNS consistency tests, rebuilds, and automated diagnostics.



This toolkit also serves as the automation backend for the **AutoOps Resolver** systems (PowerShell and Web versions).



---



## Key Capabilities



### **1. Host & Network Diagnostics**

- ICMP ping reachability  

- SSH connectivity tests  

- DNS lookup (forward and reverse)  

- Host vs BMC DNS consistency checks  

- MAC/IP address validation  

- BMC network reachability  



### **2. Redfish Power Operations**

- Power On  

- Graceful shutdown  

- Hard reset  

- AC Cycle  

- Boot mode configuration  

- Status polling with error handling  



### **3. Cobbler / PXE Rebuild Automation**

- Trigger PXE restart  

- Validate next-boot config  

- Poll server after boot  

- Return structured results  



### **4. Metadata Validation**

- Extract serial numbers  

- Validate node-to-serial mapping  

- FQDN format validation  

- BMC/Host record consistency  



### **5. Logging & Structured Output**

- JSON logs  

- Human-readable summaries  

- Categorized errors  

- Timestamped logging  



---



## 🛠️ Technology Stack



### **Python**

- Python 3  

- Subprocess orchestration  

- JSON output handling  

- Redfish API triggers  

- Optional parallel execution  



### **Bash**

- Ping tests  

- DNS (nslookup/dig)  

- BMC reachability  

- MAC/IP extraction  



### **External Tools**

- Redfish utilities  

- ipmitool / curl  

- NetBatch integration  

- Replaceable metadata sources  



---



## Repository Structure



```

infra-automation-toolkit/

├── python/

│   ├── check_hosts.py

│   ├── server_health_profile.py

│   ├── invoke_power_on.py

│   ├── invoke_fix_cobbler.py

│   ├── run_action_nb.py

│   └── utils/

│       ├── dns_utils.py

│       ├── redfish_utils.py

│       ├── network_utils.py

│       └── output.py

├── bash/

│   ├── check_ping.sh

│   ├── check_dns.sh

│   ├── check_bmc.sh

│   ├── check_mac_ip.sh

│   └── common.sh

└── examples/

&nbsp;   ├── sample_output.json

&nbsp;   ├── session_demo.txt

&nbsp;   └── troubleshooting_flow.md

```



---



## Skills Demonstrated



### **DevOps / SRE**

- Automated diagnostics  

- Redfish integration  

- PXE automation  

- Metadata consistency checks  



### **Python Engineering**

- Modular utilities  

- Clean architecture  

- JSON logging  

- Error grouping  



### **Linux / Networking**

- DNS validation  

- SSH/BMC checks  

- MAC/IP consistency  



### **Automation Design**

- Defensive scripting  

- Reusable components  

- Operator-friendly outputs  



---



## Getting Started



### **Clone Repository**

```

git clone https://github.com/yourusername/infra-automation-toolkit.git

cd infra-automation-toolkit

```



---



## Running Python Scripts



### **Check host**

```

python3 python/check_hosts.py scce01120103

```



### **Health profile**

```

python3 python/server_health_profile.py --node scce01120103 --site sc

```



### **PXE rebuild**

```

python3 python/invoke_fix_cobbler.py --node scce01120103

```



### **Redfish power**

```

python3 python/invoke_power_on.py --server scce01120103 --action PowerOn

```



---



## Running Bash Scripts



```

bash bash/check_bmc.sh scce01120103

bash bash/check_dns.sh scce01120103

```



---



## Sample Output



```

=== Host Diagnostics ===

Host: scce01120103

Site: sc



[Network]

✓ Ping reachable

✓ SSH reachable



[DNS]

✓ Forward lookup OK

✓ Reverse lookup OK

✓ Host/BMC DNS match



[BMC]

✓ Reachable

✓ Redfish auth OK



[MAC/IP]

✓ Host MAC matches metadata

✓ BMC MAC matches metadata



Result: Host is healthy.

```



---



## Integrations

- AutoOps PowerShell  

- AutoOps Web (.NET)  

- ServiceNow automations  

- NetBatch queueing  



---



## License

MIT License





