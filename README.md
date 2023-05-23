# ACI-Fabric-ELAM
ACI Fabric ELAM simplified and central from APIC

**Introduction**

ACI ELAM is a useful tool in identifying in packet is entering and exiting ACI Leaf or Spine as expected.
ELAM is run by executing set of commands and setting conditions in switch. Post execution it is important to decode and analyse ELAM output to under if packet is processed as expected.
ACI Fabric ELAM script automates ELAM capture and parsing in one go making it easier to understand for Engineers as well as customers.

---
**Features**

Script has two main features:
1. ELAM trigger centrally from APIC: Works for Pizza Box Leaf & Spine, as well Modular Spine.
2. Parse ELAM report and display important fields: Works for pizza Box Leaf switches. In case of Spine, report will be saved on respective Spine.

Killer Features:
1. BUM traffic ELAM analysis for Leaf is simplified to great extent
2. In case of Modular spine, script takes care of triggering ELAM on all line cards and simplifies ELAM set-up

---
**Testing**

Script is tested on APIC M2/L2 and M3/L3.

---
**Steps to copy Script to APIC**
 
Script can be copied to controller by SCP or by creating a new file and copying content.

Method-1: Copy attached ACI_FABRIC_ELAM.py file via SCP client like Filezilla or winscp to APIC Controller /tmp or /data/techsupport

Method-2: Create a new file in APIC /tmp or /data/techsupport and copy entire script content:

```
  apic1# cd /data/techsupport
  apic1# vim ACI_FABRIC_ELAM.py
  <Press Esc+i to get into Intert Mode>
  <Copy - Paste entire scipt content>
  <Press :wq! to save the file> 
 ```
 
 ---
**Script Execution Demo**

**Tips:**      
Script gives list of parameters which are usually set for configuring ELAM. In case you don't need to set that particular paramenter, leave it blank.   
Use **TAB** for auto complition of pre-defined fileds like node id-name, protocol.    

**Example-1:** Leaf ELAM for packet coming from outside

```
apic1# python ACI_FABRIC_ELAM.py
Enter the username:admin
Enter the password:
Enter the leaf node ID/name in the format NODEID-NODENAME, please use tab for auto completion:101-BGL-JPMC-LEAF1
INFO - 06:04:45.627: Connecting to the Device
INFO - 06:04:47.039: Getting Node details
INFO - 06:04:47.879: Device Role: leaf | Model: N9K-C93180YC-EX | Asic: tah
INFO - 06:04:47.879: Now Ready..!! Please provide input for setting Elam
Capture inner or outer : outer
Enter the interface name(Ethx/y) for srcid capture:
Select protocol - l2/ipv4/l4/arp : ipv4
Enter src ip: 50.50.50.3
Enter dst ip: 50.50.50.1
Enter protocol <0-255>:
Enter DSCP(Diff. Serv. Code Point <0-64>):
Enter packet length <0-65535>:
Enter ttl(Time to live <0-255>):
Capture outer packet (type "exit" to stop selecting further filters and start triggering elam, type "outer" to set more elam filters):exit
INFO - 06:05:08.376: Setting Elam for leaf
INFO - 06:05:08.376: Setting Elam | cmds ['set outer ipv4 src_ip 50.50.50.3 dst_ip 50.50.50.1']
INFO - 06:05:16.106: Getting Status
INFO - 06:05:16.212: ELAM not triggered yet
INFO - 06:05:16.317: ELAM not triggered yet
INFO - 06:05:16.422: ELAM not triggered yet
INFO - 06:05:16.527: ELAM not triggered yet
INFO - 06:05:16.632: ELAM not triggered yet
INFO - 06:05:16.737: ELAM not triggered yet
INFO - 06:05:16.842: ELAM not triggered yet
INFO - 06:05:16.948: ELAM not triggered yet
INFO - 06:05:17.053: Elam triggered
INFO - 06:05:17.053: Generating report

INFO - 06:05:27.489: Ereport generated
Do you want to parse this report(Y/N):Y
Copying ELAM File to /data/techsupport
ELAM File copied to the APIC
Following are the available options to parse the elam
node -> node details
ii -> Incoming Interface
head -> Headers
pctag -> Class Lookup
src -> Source Lookup
dst -> Destination Lookup
con -> Contract Lookup
res -> Result section, includes Outgoing interface, Multicast Lookup
sup -> Sup Hit
all -> Runs entire lookup
exit -> exit the parsing
Please provide the option to parse(please enter values with comma seperated to parse with more than 1 option):all

ELAM FILE : pretty_elam_2023-03-20-39m-06h-06s.txt
----------------------------------------------------------------
Node Details:
----------------------------------------------------------------
Node ID:101 Node Name: BGL-JPMC-LEAF1


----------------------------------------------------------------
Incoming Interface: Eth1/21
----------------------------------------------------------------
Packet arrived from Front Pannel port


Packet is NOT encapsulated.
----------------------------------------------------------------
Printing outer header details
----------------------------------------------------------------
Outer L3 Type : IPv4

Outer DSCP : 0

Outer TTL : 255

Outer TTL : 255

Outer IP Protocol Number : ICMP

Outer Source IP : 50.50.50.3

Outer Source MAC : 00DE.FB66.0BC1

Outer Destination IP : 50.50.50.1

Outer Destination MAC : 0022.BDF8.19FF

----------------------------------------------------------------
Printing PCTAG Lookup
----------------------------------------------------------------


PCTAG Lookup for Sclass: 49159
Tenant: Richita
App: Richita_AP
EPG: Richita_EPG1


PCTAG Lookup for Dclass: 1
Reserved pcTag: 1 used. Cannot perform Destination PCTAG Lookup


----------------------------------------------------------------
Printing Destination Lookup
----------------------------------------------------------------


Destination VRF: Richita:Richita_VRF1
Dst mac lookup not done
Destination IP HIT is: YES
Could not find Dst IP hit in HAL!


----------------------------------------------------------------
Printing Source Lookup
----------------------------------------------------------------


Source VRF: Richita:Richita_VRF1
Souce BD: Richita:Richita_BD50
Source IP HIT is: YES
.
.
<SNIP>
.
.
----------------------------------------------------------------
Printing Result Section
----------------------------------------------------------------


Outgoing Interface for Ovec 0 is: Eth1/17
Since Ovec is 0x0 packet might be destined to CPU or hitting a Met Pointer. Check OPCODE!!
Opcode : OPCODE_LCPU

Outgoing Interface: None


apic1#
```


**Example-2:** Modular Spine ELAM for inner packet

```
apic1# python ACI_FABRIC_ELAM.py 
Enter the username:admin
Enter the password:
Enter the leaf node ID/name in the format NODEID-NODENAME, please use tab for auto completion:201-BGL-JPMC-SPINE1
INFO - 03:44:55.370: Connecting to the Device
INFO - 03:44:56.618: Getting Node details
INFO - 03:44:57.459: Device Role:spine | Model: N9K-C9504
INFO - 03:44:57.459: Getting Module details from spine
INFO - 03:44:58.017: Getting ASIC details for the modules
INFO - 03:45:00.016: All mod-mappings are present
INFO - 03:45:00.016: Now Ready..!! Please provide input for setting Elam
Capture inner or outer : inner
Select protocol - l2/ipv4/l4/arp: arp
Enter src ip: 
Enter Target ip: 
Enter src mac: 
Enter target mac: 
Enter ARP opcode <0-65535> :
Capture inner or outer packet (type "exit" to stop capturing input and start triggering elam): exit
INFO - 03:45:16.005: Setting Elam on Module 1 Asic 2 | Cmds ['set inner arp']
INFO - 03:45:16.047: Setting Elam on Module 1 Asic 0 | Cmds ['set inner arp']
INFO - 03:45:16.103: Setting Elam on Module 22 Asic 0 | Cmds ['set inner arp']
INFO - 03:45:16.122: Setting Elam on Module 1 Asic 3 | Cmds ['set inner arp']
INFO - 03:45:16.151: Setting Elam on Module 23 Asic 0 | Cmds ['set inner arp']
INFO - 03:45:16.160: Setting Elam on Module 26 Asic 0 | Cmds ['set inner arp']
INFO - 03:45:16.211: Setting Elam on Module 24 Asic 0 | Cmds ['set inner arp']
INFO - 03:45:16.228: Setting Elam on Module 1 Asic 1 | Cmds ['set inner arp']
INFO - 03:45:21.529: Waiting 5 seconds for elam to trigger
INFO - 03:45:22.142: Waiting 5 seconds for elam to trigger
INFO - 03:45:22.757: Waiting 5 seconds for elam to trigger
INFO - 03:45:23.202: Waiting 5 seconds for elam to trigger
INFO - 03:45:23.217: Waiting 5 seconds for elam to trigger
INFO - 03:45:23.311: Waiting 5 seconds for elam to trigger
INFO - 03:45:23.367: Waiting 5 seconds for elam to trigger
INFO - 03:45:23.372: Waiting 5 seconds for elam to trigger
INFO - 03:45:27.297: Not triggered on Module 1 Asic 2
INFO - 03:45:27.699: Triggered on Module 1 Asic 0  <=================================
INFO - 03:45:27.699: Saving Report in /data/techsupport/mod1-asic0elam_27-04-2023T03:45:12.txt for Module 1 Asic 0
INFO - 03:45:28.525: Not triggered on Module 1 Asic 3
INFO - 03:45:28.755: Triggered on Module 26 Asic 0  <=================================
INFO - 03:45:28.756: Saving Report in /data/techsupport/mod26-asic0elam_27-04-2023T03:45:12.txt for Module 26 Asic 0
INFO - 03:45:28.773: Triggered on Module 22 Asic 0  <=================================
INFO - 03:45:28.774: Saving Report in /data/techsupport/mod22-asic0elam_27-04-2023T03:45:12.txt for Module 22 Asic 0
INFO - 03:45:28.867: Triggered on Module 23 Asic 0  <=================================
INFO - 03:45:28.867: Saving Report in /data/techsupport/mod23-asic0elam_27-04-2023T03:45:12.txt for Module 23 Asic 0
INFO - 03:45:28.938: Triggered on Module 24 Asic 0  <=================================
INFO - 03:45:28.938: Saving Report in /data/techsupport/mod24-asic0elam_27-04-2023T03:45:12.txt for Module 24 Asic 0
INFO - 03:45:44.123: Not triggered on Module 1 Asic 1
INFO - 03:45:51.113: Report generated for module 1 asic 0
INFO - 03:45:51.114: Done for Module 1 Asic 1. Closing Session to Module
INFO - 03:45:51.114: Done for Module 1 Asic 2. Closing Session to Module
INFO - 03:45:51.114: Done for Module 1 Asic 3. Closing Session to Module
INFO - 03:45:51.114: Report generated for module 24 asic 0
INFO - 03:45:51.114: Report generated for module 26 asic 0
INFO - 03:45:51.114: Report generated for module 22 asic 0
INFO - 03:45:51.114: Report generated for module 23 asic 0
apic1#
 

For Spine,  if ELAM is triggered, report will be saved in respective SPINE in /data/techsupport directory.

BGL-JPMC-SPINE1# ls -la mod*elam*
-rw------- 1 admin admin 1392110 Apr 27 11:11 mod1-asic0elam_27-04-2023T03:45:12.txt
-rw------- 1 admin admin  587438 Apr 27 11:11 mod22-asic0elam_27-04-2023T03:45:12.txt
-rw------- 1 admin admin  389621 Apr 27 11:11 mod23-asic0elam_27-04-2023T03:45:12.txt
-rw------- 1 admin admin  389632 Apr 27 11:11 mod24-asic0elam_27-04-2023T03:45:12.txt
-rw------- 1 admin admin  389636 Apr 27 11:11 mod26-asic0elam_27-04-2023T03:45:12.txt
BGL-JPMC-SPINE1# 
```

---
**Contributors:**

- Devi S devs2@cisco.com
- Narendra Yerra nyerra@cisco.com
- Richita Gajjar rgajjar@cisco.com
- Savinder Singh savsingh@cisco.com

**Company:**
Cisco Systems, Inc.

**Version:**
v1.0

**Date:**
23rd May, 2023

**Disclaimer:**
Code provided as-is. No warranty implied or included. Use the code for production at your own risk.
