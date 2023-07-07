## Script to collect and Parse ACI ELAM Centrally from APIC controller
'''
###########################################################################
Copyright (c) 2023 Cisco and/or its affiliates
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
###########################################################################
Version: v1.0
Created on: 20th Mar, 2023
Script Tested on: 
	APIC M2/L2
	APIC M3/L3
Contributors:
    Savinder Singh savsingh@cisco.com
    Takuya Kishida tkishida@cisco.com
    Narendra Yerra nyerra@cisco.com
    Devi S devs2@cisco.com
    Richita Gajjar rgajjar@cisco.com
'''

import os
import ipaddress
import pexpect
import re
import os
import getpass
import json
import sys
import pexpect
import argparse
import time
import collections
import ipaddress 
import re
import datetime
import readline
import sys
import logging
from signal import SIGKILL
from multiprocessing import Pool

readline.parse_and_bind("tab: complete")
lst=[]

class Ssh():
    
    """This class connects to the leaf and get the command output
       usage:
              ssh = Ssh("<USERNAME>","<PASSWORD>","<DEVICE IP>")
              session = ssh.connect()
              out = ssh.send_command(session,"show module")
              
              """
    
    prompt = ["[^#]#[ ]*$",pexpect.TIMEOUT]
    #prompt="[^#]#[ ]*$"
    #prompt="[^#]#[ ]*$"	

    def __init__(self,username,password,host):
        
        self.username = username
        self.password = password
        self.host = host
        self.myTopSys = json.loads(os.popen('''icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=eq(topSystem.name,"'"$HOSTNAME"'")' 2>/dev/null''').read())
        self.myAddr = self.myTopSys['imdata'][0]['topSystem']['attributes']['address']
        
        

    def send_command(self,session,cmd):
        #session.logfile = sys.stdout
        session.sendline(cmd)
        session.expect(Ssh.prompt)
        try:
            return str((session.before.decode("utf-8")))
        except Exception as e:
            return str((session.before))
    

    def send_command_stat(self,session,cmd):
        session.sendline(cmd)
        session.expect("#")
        return ((session.before.decode("utf-8")))
    
    def connect(self):
        ssh_unknown_key = "Are you sure you want to continue connecting"
        conn_params = "ssh " + self.username + "@" + self.host + " -b {}".format(self.myAddr)
        session = pexpect.spawn(conn_params)
        response = session.expect([pexpect.TIMEOUT, ssh_unknown_key, '[P|p]assword:'])
        if response == 0:
            print("Error connecting to the node!")
            sys.exit(0)
        if response == 1:
            session.sendline('yes')
            response = session.expect([pexpect.TIMEOUT, '[P|p]assword:'])
            if response == 0:
                print("Error connecting to the node!")
                sys.exit(0)
        session.sendline(self.password)
        sess=session.expect(Ssh.prompt,timeout=10)
		if sess!=0:
			print("Invalid credentials!!!")
			sys.exit(0) 
		return session

        
class ElamCommand(object):

    # -- deb_cmd -- #
    ASIC_TYPE = "asic_type"
    ASIC_INST = "asic_inst"
    SLICE = "slice_id"
    # -- tri_cmd -- #
    INSELECT = "inselect"
    OUTSELECT = "outselect"
    # -- set_cmds -- #
    SRCID = "src_id"
    INNER = "inner"
    OUTER = "outer"
    L2 = "l2"
    IPVx = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    L4 = "l4"
    ARP = "arp"

    # ==== Supported Parameters ==== #
    PROTOCOLS = [L2, IPV4, IPV6, IPVx, L4, ARP]
    # l2 parameters
    L2KEYSo = ["src_mac", "dst_mac", "cos", "vlan", "vntag_vld"]
    L2KEYSi = ["src_mac", "dst_mac", "cos", "vlan"]
    # ipv4 parameters (inselect 6 and 14)
    L3KEYSo = {
        "6": ["dscp", "dst_ip", "next-protocol", "packet-len", "src_ip", "ttl"],
        "14": ["df", "dscp", "dst_ip", "next-protocol", "src_ip", "ttl"],
    }
    L3KEYSi = {
        "6": [],
        "14": ["df", "dscp", "dst_ip", "next-protocol", "src_ip", "ttl"],
    }
    # l4 parameters
    L4KEYSo = {
        "6": ["dst-port", "src-port"],
        "14": ["nonce-dl", "nonce-sp", "sclass", "tn-seg-id"],
    }
    L4KEYSi = {"6": [], "14": ["dst-port", "src-port"]}
    # arp parameters
    ARPKEYS = ["target-ip", "target-mac", "source-ip", "source-mac", "opcode"]

    def __init__(self, elam_options):
        self.param = elam_options

        self.bad_param = self.verify_elam_options()
        if self.bad_param is None:
            self.deb_cmd = self.create_deb_cmd()
            self.tri_cmd = self.create_tri_cmd()
            self.set_cmds = self.create_set_cmds()
        else:
            self.deb_cmd = ""
            self.tri_cmd = ""
            self.set_cmds = ""

    def verify_elam_options(self):
        # check if any mandatory information is missing in elam_options
        missing_info = []
        if not self.param.get(self.ASIC_TYPE):
            missing_info.append(self.ASIC_TYPE)
        if not self.param.get(self.ASIC_INST):
            missing_info.append(self.ASIC_INST)
        if not self.param.get(self.INSELECT):
            missing_info.append(self.INSELECT)
        if not self.param.get(self.OUTSELECT):
            missing_info.append(self.OUTSELECT)

        if len(missing_info) > 0:
            return missing_info

        # check if any unsupported protocol/key is in elam_options
        inselect = self.param.get(self.INSELECT)
        unsupported_prot = []
        unsupported_keys = []
        inner_key_dict = self.param.get(self.INNER)
        if inner_key_dict:
            for prot in inner_key_dict:
                # FIXME: Add check so that both prot ipv4 and ipv6 are not sent
                if prot not in self.PROTOCOLS:
                    unsupported_prot.append(prot)
                    continue
                for key in inner_key_dict[prot]:
                    if prot == self.L2:
                        if key not in self.L2KEYSi:
                            unsupported_keys.append(key)
                    if prot == self.IPVx:
                        if key not in self.L3KEYSi[inselect]:
                            unsupported_keys.append(key)
                    if prot == self.IPV4:
                        if key not in self.L3KEYSi[inselect]:
                            unsupported_keys.append(key)
                    if prot == self.IPV6:
                        if key not in self.L3KEYSi[inselect]:
                            unsupported_keys.append(key)
                    if prot == self.L4:
                        if key not in self.L4KEYSi[inselect]:
                            unsupported_keys.append(key)
                    if prot == self.ARP:
                        if key not in self.ARPKEYS:
                            unsupported_keys.append(key)

        outer_key_dict = self.param.get(self.OUTER)
        if outer_key_dict:
            for prot in outer_key_dict:
                # FIXME: Add check so that both prot ipv4 and ipv6 are not sent
                if prot not in self.PROTOCOLS:
                    unsupported_prot.append(prot)
                    continue
                for key in outer_key_dict[prot]:
                    if prot == self.L2:
                        if key not in self.L2KEYSo:
                            unsupported_keys.append(key)
                    if prot == self.IPVx:
                        if key not in self.L3KEYSo[inselect]:
                            unsupported_keys.append(key)
                    if prot == self.IPV4:
                        if key not in self.L3KEYSo[inselect]:
                            unsupported_keys.append(key)
                    if prot == self.IPV6:
                        if key not in self.L3KEYSo[inselect]:
                            unsupported_keys.append(key)
                    if prot == self.L4:
                        if key not in self.L4KEYSo[inselect]:
                            unsupported_keys.append(key)
                    if prot == self.ARP:
                        if key not in self.ARPKEYS:
                            unsupported_keys.append(key)

        bad_param = {
            "missing_info": missing_info,
            "unsupported_param": unsupported_prot + unsupported_keys,
        }
        if len(bad_param["missing_info"]) > 0:
            return bad_param
        if len(bad_param["unsupported_param"]) > 0:
            return bad_param
        return None

    def create_deb_cmd(self):
        asic_type = self.param.get(self.ASIC_TYPE)
        asic_inst = self.param.get(self.ASIC_INST)
        slice_id = self.param.get(self.SLICE)
        if slice_id:
            cmd = "debug platform internal {} elam asic {} slice {}".format(
                asic_type, asic_inst,slice_id
            )
        else:
            cmd = "debug platform internal {} elam asic {}".format(asic_type, asic_inst)

        return cmd

    def create_tri_cmd(self):
        insel = self.param[self.INSELECT]
        outsel = self.param[self.OUTSELECT]
        cmd = "trigger init in-select {} out-select {}".format(insel, outsel)
        return cmd

    def create_set_cmds(self):
        cmds = []
        if self.param.get(self.SRCID):
            src_id ="0x"+ self.param.get(self.SRCID)
            cmds.append("set srcid {}".format(src_id))
        inner_keys = self.param[self.INNER]
        for prot, key in list(inner_keys.items()):
            if (prot == self.IPV4 or prot == self.IPVx) and self.param.get(self.SRCID):
               if key:
                   cmd = "set inner ipv{}".format(ip_version(key[next(iter(key))]))
               else:
                   cmd = "set inner {}".format(prot) 
            elif (prot == self.IPV4 or prot == self.IPVx): 
                if key:
                   cmd = "set inner ipv{}".format(ip_version(key[next(iter(key))])) 
                else:
                   print("Please ensure atleast one parameter is given..!!")
                   sys.exit(0)
            else:
                cmd = "set inner {}".format(prot)
            for k, v in list(key.items()):
                cmd += " {} {}".format(k, v)
            cmds.append(cmd)

        outer_keys = self.param[self.OUTER]
        for prot, key in list(outer_keys.items()):
            if (prot == self.IPV4 or prot == self.IPVx) and self.param.get(self.SRCID):
                if key:
                   cmd = "set outer ipv{}".format(ip_version(key[next(iter(key))]))
                else:
                   cmd = "set outer {}".format(prot)
            elif (prot == self.IPV4 or prot == self.IPVx):
                if key:
                   cmd = "set outer ipv{}".format(ip_version(key[next(iter(key))]))
                else:
                   print("Please ensure atleast one option is given..!!")
                   sys.exit(0)
            else:
                cmd = "set outer {}".format(prot)
            for k, v in list(key.items()):
                cmd += " {} {}".format(k, v)
            cmds.append(cmd)
        if len(cmds)==0:
            print("No options are selected for ELAM. Select inputs to trigger elam for specific scenarios")
            sys.exit(0)
        return cmds



def getModel(nodeName):
    fabricNode = json.loads(os.popen('''icurl 'http://localhost:7777/api/class/fabricNode.json?query-target-filter=eq(fabricNode.name,"{}")' 2>/dev/null'''.format(nodeName)).read())
    model = fabricNode["imdata"][0]["fabricNode"]["attributes"]["model"]
    role = fabricNode["imdata"][0]["fabricNode"]["attributes"]["role"]
    return (model,role)


asics = [
    {
        "id": 4,
        "full": "Lacrosse",
        "type": "lac",
        "family": "tah",
        "cpu_srcid": "127",  # on FC (based on dme/cli/controller/ftriage/fcls.py)
        "pids": ["N9K-C9504-FM-E", "N9K-C9508-FM-E"],
    },
    {
        "id": 6,
        "full": "Sugarbowl",
        "type": "sug",
        "family": "tah",
        "cpu_srcid": "72",  # based on lab tests
        "pids": [
            "N9K-C93180YC-EX",
            "N9K-C93108TC-EX",
            "N9K-C93180LC-EX",
            "N9K-X9732C-EX",
        ],
    },
    {
        "id": 8,
        "full": "Homewood",
        "type": "hom",
        "family": "roc",
        "cpu_srcid": "144",
        "pids": [
            "N9K-C93180YC-FX",
            "N9K-C93180YC-FX-24",
            "N9K-C93108TC-FX",
            "N9K-C9348GC-FXP",
            "N9K-X9736C-FX",
        ],
    },
    {
        "id": 9,
        "full": "Bigsky",
        "type": "bky",
        "family": "roc",
        "cpu_srcid": "127",
        "pids": ["N9K-C9364C", "N9K-C9332C", "N9K-C9516-FM-E2", "N9K-C9508-FM-E2"],
    },
    {
        "id": 10,
        "full": "Heavenly",
        "type": "hea",
        "family": "roc",
        "cpu_srcid": "144",
        "pids": ["N9K-C9336C-FX2", "N9K-C93240YC-FX2", "N9K-93216TC-FX2", "N9K-C93360YC-FX2"],
    },
    {
        "id": 11,
        "full": "Sundown",
        "type": "sun",
        "family": "roc",
        "cpu_srcid": "144",
        "pids": ["N9K-C93180YC-FX3", "N9K-C93180TC-FX3", "N9K-C93180YC-FX3S", "N9K-C93108TC-FX3P"],
    },
    {
        "id": 12,
        "full": "Sundown_1",
        "type": "sun",
        "family": "roc",
        "cpu_srcid": "144",
        "pids": ["N9K-C93360YC-FX3"],
    },
    {
        "id": 13,
        "type": "wol",
        "full": "Wolfridge",
        "family": "app",
        "cpu_srcid": "32",
        "pids": [
            "N9K-C93600CD-GX",
            "N9K-C9364C-GX",
            "N9K-C9316D-GX",
            "N9K-X9716D-GX",
            "N9K-C9504-FM-G",
            "N9K-C9508-FM-G"],
    },
    {
        "id": 14,
        "type": "qua",
        "full": "QuadPeaks",
        "family": "cho",
        "cpu_srcid": "74",
        "pids": ["N9K-C9364D-GX2A", "N9K-C9332D-GX2B"],
    },
]


def get_asic_by_pid(pid):
    for asic in asics:
        if "pids" in asic and pid in asic["pids"]:
            return asic["family"]


class IP(ipaddress.IPv4Address):
    def __init__(self, ip):
        try:
            super(IP, self).__init__(ip)
        except BaseException:
            raise ValueError("")

def ip_version((ip)):
    try:
        return IP(unicode(ip)).version
    except BaseException:
        raise ValueError("")
        



def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(unicode(address))
        return True
    except ValueError:
        return False


def validate_mac_address(str):
    regex = ("^([0-9A-Fa-f]{2}[:-])" +
             "{5}([0-9A-Fa-f]{2})|" +
             "([0-9a-fA-F]{4}\\." +
             "[0-9a-fA-F]{4}\\." +
             "[0-9a-fA-F]{4})$")
 
    p = re.compile(regex)
    if (str == None):
        return False
    if(re.search(p, str)):
        return True
    else:
        return False
    
    
def Check(hex):
    if not hex[0:2] == "0x":
        return False
    else:
        try:
            int(hex,16)
            return True
        except ValueError:
            return False


def getProtocol():
    while True:
        protocol = (raw_input("Enter protocol: "))
        if not protocol:
            break
        else:
            try:
                int(protocol)
            except ValueError:
                print("Invalid input. Value should be between <0-255>")
                continue
            else:
                #outer_dict["ipv4"].update({"next-protocol": protocol})
                return True
                break
        

def get_inner():
    inner_dict = {}
    proto = ""
    global lst
    lst=["l2","ipv4","l4","arp"]
    readline.set_completer(complete)
    proto = raw_input("Select protocol - l2/ipv4/l4/arp: ").lower()
    lst=[]
    readline.set_completer(complete)
    if proto == "l2":
        inner_dict.update({"l2": {}})
        ##Input Source MAC Address 
        src_mac = raw_input("Enter src mac: ")
        if src_mac:
            if not validate_mac_address(src_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else:
                inner_dict["l2"].update({"src_mac": src_mac})
                      
        ##Input Destination MAC Address             
        dst_mac = raw_input("Enter dst mac: ")
        if dst_mac:
            if not validate_mac_address(dst_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else:
                inner_dict["l2"].update({"dst_mac": dst_mac})
                        
        ##Input COS Value               
        cos = raw_input("Enter COS(Class of Service<0-7>): ")
        if cos:
            try:
                int(cos)
            except ValueError:
                print("Invalid input. Value should be between <0-7>")
                sys.exit(0)
            else:
                inner_dict["l2"].update({"cos": cos})
                       
        ##Input VLAN                
            
        vlan = raw_input("Enter vlan")
        if vlan:
            try:
                int(vlan)
            except ValueError:
                print("Invalid input. Value should be between <0-4096>")
                sys.exit(0)
            else:
                inner_dict["l2"].update({"vlan": vlan})


    elif proto == "ipv4":
        inner_dict.update({"ipv4": {}})
            
        ##Input Source Ip
        src_ip = raw_input("Enter src ip: ")
        if src_ip:
            if not validate_ip_address(src_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                inner_dict["ipv4"].update({"src_ip": src_ip})
                    
        ##Input Destination Ip               
        dst_ip = raw_input("Enter dst ip: ")
        if dst_ip:
            if not validate_ip_address(dst_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                inner_dict["ipv4"].update({"dst_ip": dst_ip})
                        
        ##Input protocol   
            
        protocol = (raw_input("Enter protocol: "))
        if protocol:
            try:
                int(protocol)
            except ValueError:
                print("Invalid input. Value should be between <0-255>")
                sys.exit(0)
            else:
                inner_dict["ipv4"].update({"next-protocol": protocol})
                       
        ##Input DSCP
            
        dscp = raw_input("Enter DSCP(Diff. Serv. Code Point <0-64>): ")
        if dscp:
            try:
                int(dscp)
            except ValueError:
                print("Invalid input. Value should be between <0-64>")
                sys.exit(0)
            else:
                inner_dict["ipv4"].update({"dscp": dscp})
                     
            
        ##Input DF value   
        df = raw_input("Enter DF(Fragments available <0-1>: ")
        if df:
            try:
                int(df)
            except ValueError:
                print("Invalid input. Value should be between <0-1>")
                sys.exit(0)
            else:
                inner_dict["ipv4"].update({"df": df})
            
        ##Input TTL Value
        ttl = (raw_input("Enter ttl(Time to live <0-255>: "))
        if ttl:
            try:
                int(ttl)
            except ValueError:
                print("Invalid input. Value should be between <0-255>")
                sys.exit(0)
            else:
                inner_dict["ipv4"].update({"ttl": ttl})
                         

    elif proto == "l4":
        inner_dict.update({"l4": {}})
         
        ##Input source port
        src_port = raw_input("Enter src port <0-65535>: ")
        if src_port:
            try:
                int(src_port)
            except ValueError:
                print("Invalid input. Value should be between <0-65535>")
                sys.exit(0)
            else:
                inner_dict["l4"].update({"src-port": src_port})
            
        ##Input destination port
        dst_port = raw_input("Enter dst port <0-65535>: ")
        if dst_port:
            try:
                int(dst_port)
            except ValueError:
                print("Invalid input. Value should be between <0-65535>")
                sys.exit(0)
            else:
                inner_dict["l4"].update({"dst-port": dst_port})
                     
            

    elif proto == "arp":
        inner_dict.update({"arp": {}})
        ## Input source ip
        src_ip = raw_input("Enter src ip: ")
        if src_ip:
            if not validate_ip_address(src_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                inner_dict["arp"].update({"source-ip": src_ip})
                       
            
        ##Input target ip
        target_ip = raw_input("Enter Target ip: ")
        if target_ip:
            if not validate_ip_address(target_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                inner_dict["arp"].update({"target-ip": target_ip})
 
        
        ##Input Source MAC 
          
       
        src_mac = raw_input("Enter src mac: ")
        if src_mac:
            if not validate_mac_address(src_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else: 
                inner_dict["arp"].update({"source-mac": src_mac})
                   
        
        ##Input Target MAC      
            
        target_mac = raw_input("Enter target mac: ")
        if target_mac:
            if not validate_mac_address(target_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else:
                inner_dict["arp"].update({"target-mac": target_mac})
                       
        ##Input ARP opcode   
        opcode = raw_input("Enter ARP opcode <0-65535> :")
        if opcode:
            try:
                int(opcode)
            except ValueError:
                print("Invalid input. Value should be between <0-65535>")
                sys.exit(0)
            else:
                inner_dict["arp"].update({"opcode": opcode})
    elif len(proto)==0:
        pass
    else:
        print("Invalid Protocol. Please select value among \"l2/ipv4/l4/arp\"")              
        sys.exit(0)                   
    return inner_dict


def get_outer():
    outer_dict = {}
    proto = ""
    global lst
    lst=["l2","ipv4","l4","arp"]
    readline.set_completer(complete)
    proto = raw_input("Select protocol - l2/ipv4/l4/arp : ").lower()
    lst=[]
    readline.set_completer(complete)
    if proto == "l2":
        outer_dict.update({"l2": {}})
        
        ##Input Source MAC Address 
        src_mac = raw_input("Enter src mac: ")
        if src_mac:
            if not validate_mac_address(src_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else:
                outer_dict["l2"].update({"src_mac": src_mac})
                      
        ##Input Destination MAC Address             
        dst_mac = raw_input("Enter dst mac: ")
        if dst_mac:
            if not validate_mac_address(dst_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else:
                outer_dict["l2"].update({"dst_mac": dst_mac})
                     
        ##Input COS Value               
        cos = raw_input("Enter COS(Class Of Service <0-7>): ")
        if cos:
            try:
                int(cos)
            except ValueError:
                print("Invalid input. Value should be between <0-7>")
                sys.exit(0)
            else:
                outer_dict["l2"].update({"cos": cos})
                       
        ##Input VLAN                
            
        vlan = raw_input("Enter vlan")
        if vlan:
            try:
                int(vlan)
            except ValueError:
                print("Invalid input. Value should be between <0-4096>")
                sys.exit(0)
            else:
                outer_dict["l2"].update({"vlan": vlan})
                
            
    elif proto == "ipv4":
        outer_dict.update({"ipv4": {}})
        ##Input Source Ip
        src_ip = raw_input("Enter src ip: ")
        if src_ip:
            if not validate_ip_address(src_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                outer_dict["ipv4"].update({"src_ip": src_ip})
                    
        ##Input Destination Ip               
        dst_ip = raw_input("Enter dst ip: ")
        if dst_ip:
            if not validate_ip_address(dst_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                outer_dict["ipv4"].update({"dst_ip": dst_ip})
                        
        ##Input protocol   
            
        protocol = (raw_input("Enter protocol <0-255>: "))
        if protocol:
            try:
                int(protocol)
            except ValueError:
                print("Invalid input. Value should be between <0-255>")
                sys.exit(0)
            else:
                outer_dict["ipv4"].update({"next-protocol": protocol})
                       
        ##Input DSCP
            
        dscp = raw_input("Enter DSCP(Diff. Serv. Code Point <0-64>): ")
        if dscp:
            try:
                int(dscp)
            except ValueError:
                print("Invalid input. Value should be between <0-64>")
                sys.exit(0)
            else:
                outer_dict["ipv4"].update({"dscp": dscp})
            
        ##Input packet length
        packet_len = (raw_input("Enter packet length <0-65535>: "))
        if packet_len:
            try:
                int(packet_len)
            except ValueError:
                print("Invalid input. Value should be between <0-65535>")
                sys.exit(0)
            else:
                outer_dict["ipv4"].update({"packet-len": packet_len})
                      
                    
        ##Input TTL Value           
           
        ttl = (raw_input("Enter ttl(Time to live <0-255>): "))
        if ttl:
            try:
                int(ttl)
            except ValueError:
                print("Invalid input. Value should be between <0-255>")
                sys.exit(0)
            else:
                outer_dict["ipv4"].update({"ttl": ttl})
                      
                        
                        
    elif proto == "l4":
        outer_dict.update({"l4": {}})
        ##Input source port
        src_port = raw_input("Enter src port: ")
        if src_port:
            try:
                int(src_port)
            except ValueError:
                print("Invalid input. Value should be between <0-65535>")
                sys.exit(0)
            else:
                outer_dict["l4"].update({"src-port": src_port})
            
        ##Input destination port

        dst_port = raw_input("Enter dst port: ")
        if dst_port:
            try:
                int(dst_port)
            except ValueError:
                print("Invalid input. Value should be between <0-65535>")
                sys.exit(0)
            else:
                outer_dict["l4"].update({"dst-port": dst_port})
                
                

    elif proto == "arp":
        outer_dict.update({"arp": {}})
        ## Input source ip
        src_ip = raw_input("Enter src ip: ")
        if src_ip:
            if not validate_ip_address(src_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                outer_dict["arp"].update({"source-ip": src_ip})
                        
            
        ##Input target ip
        target_ip = raw_input("Enter Target ip: ")
        if target_ip:
            if not validate_ip_address(target_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                outer_dict["arp"].update({"target-ip": target_ip})
    
        
        ##Input Source MAC 
          
       
        src_mac = raw_input("Enter src mac: ")
        if src_mac:
            if not validate_mac_address(src_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else: 
                outer_dict["arp"].update({"source-mac": src_mac})
                   
        
        ##Input Target MAC      
            
        target_mac = raw_input("Enter target mac: ")
        if target_mac:
            if not validate_mac_address(target_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else:
                outer_dict["arp"].update({"target-mac": target_mac})
                       
        ##Input ARP opcode   
        opcode = raw_input("Enter ARP opcode <0-65535>: ")
        if opcode:
            try:
                int(opcode)
            except ValueError:
                print("Invalid input. Value should be between <0-65535>")
                sys.exit(0)
            else:
                outer_dict["arp"].update({"opcode": opcode})

    elif len(proto)==0:
        pass
    else:
        print("Invalid Protocol. Please select value among \"l2/ipv4/l4/arp\"")  
        sys.exit(0)
    return  outer_dict


def get_outer_vxlan():
    outer_vxlan_dict = {}
    proto = ""
    global lst
    lst=["l2","ipv4","l4"]
    readline.set_completer(complete)
    proto = raw_input("Select protocol - l2/ipv4/l4: ").lower()
    if proto == "l2":
        outer_vxlan_dict.update({"l2": {}})
        ##Input Source MAC Address 
        src_mac = raw_input("Enter src mac: ")
        if src_mac:
            if not validate_mac_address(src_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else:
                outer_vxlan_dict["l2"].update({"src_mac": src_mac})
                        
        ##Input Destination MAC Address             
        dst_mac = raw_input("Enter dst mac: ")
        if dst_mac:
            if not validate_mac_address(dst_mac):
                print("MAC address is not valid!")
                sys.exit(0)
            else:
                outer_vxlan_dict["l2"].update({"dst_mac": dst_mac})
                     
        ##Input COS Value               
        cos = raw_input("Enter COS(Class of Service <0-7>): ")
        if cos:
            try:
                int(cos)
            except ValueError:
                print("Invalid input. Value should be between <0-7>")
                sys.exit(0)
            else:
                outer_vxlan_dict["l2"].update({"cos": cos})   
                
            

    elif proto == "ipv4":
        outer_vxlan_dict.update({"ipv4": {}})
        ##Input Source Ip
        src_ip = raw_input("Enter src ip: ")
        if src_ip:
            if not validate_ip_address(src_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                outer_vxlan_dict["ipv4"].update({"src_ip": src_ip})
                    
        ##Input Destination Ip               
        dst_ip = raw_input("Enter dst ip: ")
        if dst_ip:
            if not validate_ip_address(dst_ip):
                print("IP address is not Valid!")
                sys.exit(0)
            else:
                outer_vxlan_dict["ipv4"].update({"dst_ip": dst_ip})
                            
 
                       
        ##Input DSCP
            
        dscp = raw_input("Enter DSCP(Diff. Serv. Code Point <0-64>): ")
        if dscp:
            try:
                int(dscp)
            except ValueError:
                print("Invalid input. Value should be between <0-64>")
                sys.exit(0)
            else:
                outer_vxlan_dict["ipv4"].update({"dscp": dscp})
            

                                         
        ##Input TTL Value           
           
        ttl = (raw_input("Enter ttl(Time to live <0-255>): "))
        if ttl:
            try:
                int(ttl)
            except ValueError:
                print("Invalid input. Value should be between <0-255>")
                sys.exit(0)
            else:
                outer_vxlan_dict["ipv4"].update({"ttl": ttl})
            

    elif proto == "l4":
        outer_vxlan_dict.update({"l4": {}})
        
        ##Input Dont learn Bit
        nonce_dl = raw_input("Dont learn Bit <0-1>: ")
        if nonce_dl:
            try:
                int(nonce_dl)
            except ValueError:
                print("Invalid input. Value should be between <0-1>")
                sys.exit(0)
            else:
                outer_vxlan_dict["l4"].update({"nonce-dl": nonce_dl})
                   
        ##Input Policy applied bit
        nonce_sp = raw_input("Policy applied bit <0-1>: ")
        if nonce_sp:
            try:
                int(nonce_sp)
            except ValueError:
                print("Invalid input. Value should be between <0-1>")
                sys.exit(0)
            else:
                outer_vxlan_dict["l4"].update({"nonce-sp": nonce_sp})
                
        ##Input Sclass
                        
        sclass = raw_input("Enter Sclass(Src PcTag <0-65535>): ")
        if sclass:
            try:
                int(sclass)
            except ValueError:
                print("Invalid input. Value should be between <0-65535>")
                sys.exit(0)
            else:
                outer_vxlan_dict["l4"].update({"sclass": sclass})
                                    
        ##Input Vxlan Vnid
         
        tn_seg = raw_input("Enter Segment Id <0x0-0xffffff>: ")
        if tn_seg:        
            if not Check(tn_seg):
                print("Invalid Value. Please enter Hex in 0x format. Range <0x0-0xffffff>")
                sys.exit(0)
            else:
                outer_vxlan_dict["l4"].update({"tn-seg-id": tn_seg})

    elif len(proto)==0:
	    pass
    else:
        print("Invalid Protocol. Please select value among \"l2/ipv4/l4\"")                                           
        sys.exit(0)       
        
    return outer_vxlan_dict

def get_srcid(interface,insel,asic):
    cmd='''vsh_lc -c "show platform internal hal l2 port gpd" | awk '/==/'{{i++}}i==2 | tail -n+2 | awk '$2 ~ "^{}$"' | awk '{{print $6 " " $8 " " $10}}' '''.format(interface)
    gpd=ssh.send_command(session,cmd)
    try:
        src_id=gpd.split("\n")[1].split()[2] 
        slice_id = gpd.split("\n")[1].split()[1]
        return src_id,slice_id
    except:
        print("Interface provided for src_id is not valid!!Validate the src port and start ELAM again")
        sys.exit(0)

def setLeafElam(debcmd,tricmd,setcmds):
    vsh= ssh.send_command(session,"vsh_lc")
    deb = ssh.send_command(session,debcmd)
    reset = ssh.send_command(session,"trigger reset")
    tricmd = ssh.send_command(session,tricmd)
    for cmds in setcmds:
        setcmds = ssh.send_command(session,cmds)
    start = ssh.send_command(session,"start")
    return start


def getElamStatus(debcmd,tricmd):
    status = ssh.send_command(session,"status")
    return status


def generateEreport(debcmd,tricmd):
    status = ssh.send_command(session,"ereport | no-more")
    end = ssh.send_command(session,"end")
    out = ssh.send_command(session,"exit")
    return status


def process_diag(data):
    global lst
    lst = data.splitlines()
    res = dict()
    #print(lst)
    for i in range(0,len(lst)):
       if lst[i].startswith('-'):
         start=i+1
    #print(start)
    for i in range(start, len(lst)):
        if len(lst[i].strip())==0:
            break
        lst[i] = re.sub(' +', ' ', lst[i])
        lst[i] = lst[i].strip()
        names = lst[i].split(' ')
        res[names[0]+'-'+names[2]]=names[4].split('/')[0]
    return res


def complete(text,state):
    global lst
    results = [x for x in lst if x.startswith(text)] + [None]
    return results[state]


def deep_update(source, overrides):
    """
    Update a nested dictionary or similar mapping.
    Modify ``source`` in place.
    """
    for key, value in overrides.items():
        if isinstance(value, collections.Mapping) and value:
            returned = deep_update(source.get(key, {}), value)
            source[key] = returned
        else:
            source[key] = overrides[key]
    return source


##################################################################SPINE FUCTIONS#############################################################

def check_if_output(arg):
    return((arg[arg.find('\n')+1:arg.rfind('\n')]).strip().replace('\\', '/'))


def getModList():
    mod_list = []
    lc = '''icurl 'http://localhost:7777/api/class/eqptLCSlot.json?rsp-subtree=children&rsp-subtree-filter=eq(eqptLC.operSt,"online")&rsp-subtree-include=required' 2>/dev/null | python -m json.tool | grep physId | egrep -o "[0-9]+"'''
    lc_out = ssh.send_command(session,lc)
    lc_out = check_if_output(lc_out).split()
    for x in lc_out:
        mod_list.append(x)

    fc = '''icurl 'http://localhost:7777/api/class/eqptFCSlot.json?rsp-subtree=children&rsp-subtree-filter=eq(eqptFC.operSt,"online")&rsp-subtree-include=required' 2>/dev/null | python -m json.tool | grep physId | egrep -o "[0-9]+"'''
    fc_out = ssh.send_command(session,fc)
    fc_out = check_if_output(fc_out).split()
    for y in fc_out:
        mod_list.append(y)

    return mod_list



def getAsicDict(mod_list):
    asic_dict = {}
    for mod in mod_list:
        asiccmd = '''icurl 'http://localhost:7777/api/class/eqptCh.json?query-target=children&target-subtree-class=eqptFCSlot,eqptLCSlot&query-target-filter=or(and(eq(eqptFCSlot.physId,"'{}'"))and(eq(eqptLCSlot.physId,"'{}'")))&rsp-subtree=full&target-subtree-class=eqptSensor&rsp-subtree-filter=eq(eqptSensor.type,"asic")' 2>/dev/null | python -m json.tool | egrep "model.*instance" | awk -F "\\"" '{{print $4}}' | awk '{{print $1}}' | uniq'''.format(mod,mod)
        asic_out = ssh.send_command(session,asiccmd)
        asic_out = check_if_output(asic_out)

        if asic_out == "Sugarbowl" or asic_out == "LAC":
            asic_family = "tah"
        elif asic_out == "Homewood":
            asic_family = "roc"
        elif asic_out == "Wolfridge":
            asic_family = "app"

        asic_dict[mod] = asic_family

    return asic_dict


# def getNumberOfAsic(mod_number):
#     lst = []
#     with open("/data/techsupport/mod-mapping{}.txt".format(mod_number)) as f:
#         mod_mapping = f.readlines()
#         for line in mod_mapping:
#             lst.append(line.split()[1])
        
#     return(sorted(set(lst)))

def getNumberOfAsic(mod_number):
    lst = []

    # with open("/data/techsupport/mod-mapping{}.txt".format(mod_number)) as f:
    out = ssh.send_command(session,"cat /data/techsupport/mod-mapping{}.txt".format(mod_number))
    out = check_if_output(out).splitlines()
    for line in out:
        lst.append(line.split()[1])
    return(sorted(set(lst)))



def getHalOutputs(mod,uName,password,hostIp):

    prompt = "[^#]#[ ]*$"

    def send_command(session,cmd):
        try:
            session.sendline(cmd)
        except (KeyboardInterrupt):
            print("Error in sending command")
            print("Killing session: {}".format(session.pid))
            try:
                os.popen("kill {}".format(session.pid))
            except Exception:
                print("Could not kill process: {}".format(session.pid))
        else:
            try:
                session.expect(prompt)
            except (KeyboardInterrupt):
                print("Error getting prompt")
                print("Killing session: {}".format(session.pid))
                try:
                    os.popen("kill {}".format(session.pid))
                except Exception:
                    print("Could not kill process: {}".format(session.pid))
            else:
                return str((session.before.decode("utf-8")))


    def connect(username,password,host):
        conn_params = ('ssh -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {}@{}'.format(username,host))
        try:
            session = pexpect.spawn(conn_params)
            time.sleep(2)
        except (KeyboardInterrupt):
            print("Error while spawning")
            print("Killing session: {}".format(session.pid))
            try:
                os.popen("kill {}".format(session.pid))
            except Exception:
                print("Could not kill process: {}".format(session.pid))
        except (Exception):
            print("Error while spawning")
            print("Killing session: {}".format(session.pid))
            try:
                os.popen("kill {}".format(session.pid))
            except Exception:
                print("Could not kill process: {}".format(session.pid))
        else:
            try:
                session.expect('Password:')
            except (KeyboardInterrupt):
                print("Error in expect password")
                print("Killing session: {}".format(session.pid))
                try:
                    os.popen("kill {}".format(session.pid))
                except Exception:
                    print("Could not kill process: {}".format(session.pid))
            except (Exception):
                print("Error in expect password")
                print("Killing session: {}".format(session.pid))
                try:
                    os.popen("kill {}".format(session.pid))
                except Exception:
                    print("Could not kill process: {}".format(session.pid))
            else:
                try: 
                    session.sendline(password)
                except (KeyboardInterrupt):
                    print("Error in sending password")
                    print("Killing session: {}".format(session.pid))
                    try:
                        os.popen("kill {}".format(session.pid))
                    except Exception:
                        print("Could not kill process: {}".format(session.pid))
                except (Exception):
                    print("Error in sending password")
                    print("Killing session: {}".format(session.pid))
                    try:
                        os.popen("kill {}".format(session.pid))
                    except Exception:
                        print("Could not kill process: {}".format(session.pid))
                else:
                    try:
                        session.expect(prompt)
                    except (KeyboardInterrupt):
                        print("Error getting prompt")
                        print("Killing session: {}".format(session.pid))
                        try:
                            os.popen("kill {}".format(session.pid))
                        except Exception:
                            print("Could not kill process: {}".format(session.pid))
                    except (Exception):
                        print("Error getting prompt")
                        print("Killing session: {}".format(session.pid))
                        try:
                            os.popen("kill {}".format(session.pid))
                        except Exception:
                            print("Could not kill process: {}".format(session.pid))
                    else:
                        return session


    x = mod
    try:
        session = connect(uName,password,hostIp)
    except Exception:
        print("Error happend while connecting in the main function")
        try:
            os.popen("kill {}".format(session.pid))
        except Exception:
            print("Could not kill process: {}".format(session.pid))
    else:
        try:
            # check if control master is present, if yes use control master for sshcmd, else create control master
            # controlmaster = "ls /tmp/ssh-root@mod{}:22".format(mod)
            # checkcontrolmasterout = send_command(session,controlmaster).strip()
            # checkcontrolmasterout = check_if_output(checkcontrolmasterout)
            # if not "No such file or directory" in checkcontrolmasterout:
            #     root_login = '''ssh -S /tmp/ssh-root@mod{}:22 root@mod{}'''.format(mod,mod)
            # else:
            #     root_login = '''sshpass -p "root" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o controlMaster=yes -o controlPath=/tmp/ssh-root@mod{}:22 -o controlPersist=yes -q root@mod{}'''.format(mod,mod)
            

            root_login = '''sshpass -p "root" ssh -q -o ServerAliveInterval=30 -o ServerAliveCountMax=0 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@mod{}'''.format(mod)
            logging.info("Getting Hal outputs for Module{}".format(x))
            send_command(session,root_login)
            send_command(session,"echo 'show platform internal hal l2 port gpd' >> /tmp/haloutmod{}.txt".format(x))
            send_command(session,"vsh_lc -c 'show platform internal hal l2 port gpd' >> /tmp/haloutmod{}.txt".format(x))
            send_command(session,"echo 'show platform internal hal l2 internal-port pi' >> /tmp/haloutmod{}.txt".format(x))
            send_command(session,"vsh_lc -c 'show platform internal hal l2 internal-port pi' >> /tmp/haloutmod{}.txt".format(x))
            send_command(session,"exit")

            #Since control master is already build using above rootlogin_ this should use control master and must be faster, if control master is not presernt it will create it again

            # checkcontrolmasterout = send_command(session,controlmaster).strip()
            # checkcontrolmasterout = check_if_output(checkcontrolmasterout)
            # if not "No such file or directory" in checkcontrolmasterout:
            #     root_login = '''ssh -S /tmp/ssh-root@mod{}:22 root@mod{}'''.format(mod,mod)
            # else:
            #     root_login = ''' -p "root" ssh -o StrictsshpassHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o controlMaster=yes -o controlPath=/tmp/ssh-root@mod{}:22 -o controlPersist=yes -q root@mod{}'''.format(mod,mod)
            
            
            copy_halout_to_sup = '''{} "cat /tmp/haloutmod{}.txt" | tee -a /data/techsupport/haloutmod{}.txt'''.format(root_login,x,x)
            send_command(session,copy_halout_to_sup)

            if int(x) > 20:
                logging.info("Creating Module Mapping for Module{}".format(x))
                cmd = '''grep -A 10000 "show platform internal hal l2 port gpd" /data/techsupport/haloutmod{}.txt | grep -B 10000 "show platform internal hal l2 internal-port pi" | grep "fc" | sed -e 's/^.*fc/fc/g' | awk '{{print $1" "$5" "$7" "$9" "$10}}' > /data/techsupport/mod-mapping{}.txt'''.format(x,x)
                send_command(session,cmd)
            elif int(x) < 20:
                logging.info("Creating Module Mapping for Module{}".format(x))
                cmd1 = '''grep -A 10000 "show platform internal hal l2 port gpd" /data/techsupport/haloutmod{}.txt | grep -B 10000 "show platform internal hal l2 internal-port pi" | grep "Eth" | sed -e 's/^.*Eth//g' | awk '{{print $1" "$5" "$7" "$9" "$10}}' > /data/techsupport/mod-mapping{}.txt'''.format(x,x)
                send_command(session,cmd1)
                cmd2 = '''grep -A 10000 "show platform internal hal l2 internal-port pi" /data/techsupport/haloutmod{}.txt | egrep "lc\([0-9]+\)\-fc\([0-9]+\)" | awk '{{print $2" "$3" "$5" "$7" "$8}}' >> /data/techsupport/mod-mapping{}.txt'''.format(x,x)
                send_command(session,cmd2)

            #Since control master is already build using above rootlogin_ this should use control master and must be faster, if control master is not presernt it will create it again
            
            # checkcontrolmasterout = send_command(session,controlmaster).strip()
            # checkcontrolmasterout = check_if_output(checkcontrolmasterout)
            # if not "No such file or directory" in checkcontrolmasterout:
            #     root_login = '''ssh -S /tmp/ssh-root@mod{}:22 root@mod{}'''.format(mod,mod)
            # else:
            #     root_login = '''sshpass -p "root" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o controlMaster=yes -o controlPath=/tmp/ssh-root@mod{}:22 -o controlPersist=yes -q root@mod{}'''.format(mod,mod)
            

            cleanup_hal_from_mod = '''{} "rm /tmp/haloutmod{}.txt"'''.format(root_login,x)
            send_command(session,cleanup_hal_from_mod)
            #ssh.send_command(session,"ssh -O stop -o controlPath=/tmp/slogging.info("Done for module{}".format(x))
        except Exception:
            logging.info("Exception in the calling function getHalOutputs. Closing session")
            send_command(session,"ssh -O stop -o controlPath=/tmp/ssh-root@mod{}:22 root@mod{} 2>/dev/null".format(mod,mod))
                #session.close(force=True)
            try:
                logging.info("Exception in getHalOut, cleaning up")
                send_command(session,"rm /data/techsupport/halout* /data/techsupport/mod-mapp*")
                logging.info("Killing {}".format(session.pid))
                try:
                    os.popen("kill {}".format(session.pid))
                except Exception:
                    print("Could not kill process: {}".format(session.pid))
            except:
                pass
            else:
                print("Terminating process {}".format(session.pid))
        else:
            return("Done for module{}".format(x))


def setElam(mod,deb,tri,setlst,asic,uName,password,hostIp,date):

    prompt = "[^#]#[ ]*$"

    def send_command(session,cmd):
        try:
            session.sendline(cmd)
        except (KeyboardInterrupt):
            print("Error in sending command")
            print("Killing session: {}".format(session.pid))
            try:
                os.popen("kill {}".format(session.pid))
            except Exception:
                print("Could not kill process: {}".format(session.pid))
        else:
            try:
                session.expect(prompt)
            except (KeyboardInterrupt):
                print("Error getting prompt")
                print("Killing session: {}".format(session.pid))
                try:
                    os.popen("kill {}".format(session.pid))
                except Exception:
                    print("Could not kill process: {}".format(session.pid))
            else:
                return str((session.before.decode("utf-8")))


    def connect(username,password,host):
        conn_params = ('ssh -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {}@{}'.format(username,host))
        try:
            session = pexpect.spawn(conn_params)
            time.sleep(2)
        except (KeyboardInterrupt):
            print("Error while spawning")
            print("Killing session: {}".format(session.pid))
            try:
                os.popen("kill {}".format(session.pid))
            except Exception:
                print("Could not kill process: {}".format(session.pid))
        except (Exception):
            print("Error while spawning")
            print("Killing session: {}".format(session.pid))
            try:
                os.popen("kill {}".format(session.pid))
            except Exception:
                print("Could not kill process: {}".format(session.pid))
        else:
            try:
                session.expect('Password:')
            except (KeyboardInterrupt):
                print("Error in expect password")
                print("Killing session: {}".format(session.pid))
                try:
                    os.popen("kill {}".format(session.pid))
                except Exception:
                    print("Could not kill process: {}".format(session.pid))
            except (Exception):
                print("Error in expect password")
                print("Killing session: {}".format(session.pid))
                try:
                    os.popen("kill {}".format(session.pid))
                except Exception:
                    print("Could not kill process: {}".format(session.pid))
            else:
                try: 
                    session.sendline(password)
                except (KeyboardInterrupt):
                    print("Error in sending password")
                    print("Killing session: {}".format(session.pid))
                    try:
                        os.popen("kill {}".format(session.pid))
                    except Exception:
                        print("Could not kill process: {}".format(session.pid))
                except (Exception):
                    print("Error in sending password")
                    print("Killing session: {}".format(session.pid))
                    try:
                        os.popen("kill {}".format(session.pid))
                    except Exception:
                        print("Could not kill process: {}".format(session.pid))
                else:
                    try:
                        session.expect(prompt)
                    except (KeyboardInterrupt):
                        print("Error getting prompt")
                        print("Killing session: {}".format(session.pid))
                        try:
                            os.popen("kill {}".format(session.pid))
                        except Exception:
                            print("Could not kill process: {}".format(session.pid))
                    except (Exception):
                        print("Error getting prompt")
                        print("Killing session: {}".format(session.pid))
                        try:
                            os.popen("kill {}".format(session.pid))
                        except Exception:
                            print("Could not kill process: {}".format(session.pid))
                    else:
                        return session
    
    try:
        session = connect(uName,password,hostIp)
    except Exception:
        print("Error happend while connecting in the main function")
        try:
            os.popen("kill {}".format(session.pid))
        except Exception:
            print("Could not kill process: {}".format(session.pid))
    else:
        try:
            logging.info("Setting Elam on Module {} Asic {} | Cmds {}".format(mod,asic,setlst))
            # controlmaster = "ls /tmp/ssh-root@mod{}:22".format(mod)
            # checkcontrolmasterout = send_command(session,controlmaster).strip()
            # checkcontrolmasterout = check_if_output(checkcontrolmasterout)
            # if not "No such file or directory" in checkcontrolmasterout:
            #     root_login = '''ssh -S /tmp/ssh-root@mod{}:22 root@mod{}'''.format(mod,mod)
            # else:
            #     root_login = '''sshpass -p "root" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o controlMaster=yes -o controlPath=/tmp/ssh-root@mod{}:22 -o controlPersist=yes -q root@mod{}'''.format(mod,mod)
            
            root_login = '''sshpass -p "root" ssh -q -o ServerAliveInterval=30 -o ServerAliveCountMax=0 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@mod{}'''.format(mod)
            
            send_command(session,root_login)
            send_command(session,"vsh_lc")
            send_command(session,deb)
            send_command(session,"trigger reset")
           
            send_command(session,tri)
            for cmd in setlst:
                send_command(session,cmd)
          
            send_command(session,"start")
            send_command(session,"end")
            send_command(session,"exit")

            logging.info("Waiting 5 seconds for elam to trigger")
            time.sleep(5)

            cmd_status = 'vsh_lc -c "{} ; {} ; status"'.format(deb,tri)
            status = send_command(session,cmd_status)
            status = check_if_output(status)
            pattern = r"((Asic )(\d).+(Triggered))"
            triggered = re.search(pattern,check_if_output(status))
            if triggered:
                triggeredstr = ("{} on Module {} Asic {}  <=================================".format(triggered.group(4),mod,triggered.group(3)))
                logging.info(triggeredstr)
                #return(mod,triggered.group(3))

                cmd_report = 'vsh_lc -c "{} ; {} ; report detail | no-more" > /tmp/mod{}-asic{}elam_{}.txt'.format(deb,tri,mod,asic,date)
                logging.info("Saving Report in /data/techsupport/mod{}-asic{}elam_{}.txt for Module {} Asic {}".format(mod,asic,date,mod,asic))
                send_command(session,root_login)
                send_command(session,cmd_report)
                send_command(session,"end")
                send_command(session,"exit")

                #Checking root login command
                # controlmaster = "ls /tmp/ssh-root@mod{}:22".format(mod)
                # checkcontrolmasterout = send_command(session,controlmaster).strip()
                # checkcontrolmasterout = check_if_output(checkcontrolmasterout)
                # if not "No such file or directory" in checkcontrolmasterout:
                #     root_login = '''ssh -S /tmp/ssh-root@mod{}:22 root@mod{}'''.format(mod,mod)
                # else:
                #     root_login = '''sshpass -p "root" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o controlMaster=yes -o controlPath=/tmp/ssh-root@mod{}:22 -o controlPersist=yes -q root@mod{}'''.format(mod,mod)
                    
            
                savetosupcmd = '''{} "cat /tmp/mod{}-asic{}elam_{}.txt" > /data/techsupport/mod{}-asic{}elam_{}.txt'''.format(root_login,mod,asic,date,mod,asic,date)
                send_command(session,savetosupcmd)
                #send_command(session,"ssh -O stop -o controlPath=/tmp/ssh-root@mod{}:22 root@mod{} 2>/dev/null".format(mod,mod))
                send_command(session,"sshpass -p \"root\" ssh -q -o ServerAliveInterval=30 -o ServerAliveCountMax=0 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@mod{} \"rm /tmp/mod*\" ".format(mod))
                return ("Report generated for module {} asic {}".format(mod,asic))

            else:
                send_command(session,"end")
                send_command(session,"exit")
                logging.info("Not triggered on Module {} Asic {}".format(mod,asic))
                #send_command(session,"ssh -O stop -o controlPath=/tmp/ssh-root@mod{}:22 root@mod{} 2>/dev/null".format(mod,mod))
                
        except KeyboardInterrupt:
            logging.info("Exception in the calling function setElam. Closing session")
            #print(send_command(session,"ssh -O stop -o controlPath=/tmp/ssh-root@mod{}:22 root@mod{} 2>/dev/null".format(mod,mod)))
            #session.close(force=True)

            try:
                logging.info("Killing {}".format(session.pid))
                try:
                    os.popen("kill {}".format(session.pid))
                except Exception:
                    print("Could not kill process: {}".format(session.pid))
            except:
                pass
            else:
                print("Terminating process {}".format(session.pid))

        #ssh.send_command(session,"ssh -O stop -o controlPath=/tmp/ssh-root@mod{}:22 root@mod{} 2>/dev/null".format(mod,mod))
        #logging.info("Stopping {} for Mod {} Asic {}".format(name,mod,asic))
        else:
            #closessh = "ssh -O stop -o controlPath=/tmp/ssh-root@mod{}:22 root@mod{} 2>/dev/null".format(mod,mod)
            #send_command(session,closessh)
            return "Done for Module {} Asic {}. Closing Session to Module".format(mod,asic)
            



def setElam_wrapper(args):
    return setElam(*args)

def getHalOutputs_wrapper(args):
    return getHalOutputs(*args)

def deep_update(source, overrides):
        """
        Update a nested dictionary or similar mapping.
        Modify ``source`` in place.
        """
        for key, value in overrides.items():
            if isinstance(value, collections.Mapping) and value:
                returned = deep_update(source.get(key, {}), value)
                source[key] = returned
            else:
                source[key] = overrides[key]
        return source

    
##################################################################################PARSING ELAM##############################################################

class Ereport():
    
    """This is the Base class which gets data from the ereport and prepares the command
       Other Subclasses inherits from this class and send commands to get the data from the devices, this class only gets data from ereport"""

    def __init__(self,data):
        self.data = data

    #Some of the show commands output do not need 0x in the hex value for grep. Get data from bracket and remove  0x
    @classmethod
    def data_in_brackets_rem_0(cls,key):
        res = re.search(r'\((.*?)\)',key).group(1)[3:]

        return(str(' '+res))    

        
    def getTep(self):
        for i,my_tep_idx in enumerate(self.data):
            if "MY TEP Index " in my_tep_idx:
                regex = re.compile("(MY TEP Index)[\s:]+(?P<tep_idx>\w+)")
                match = regex.match(my_tep_idx)
                
                if match:
                    my_tep_idx_cmd = 'show interface loopback{} | grep -Eo "[0-9]{{1,3}}\.[0-9]{{1,3}}\.[0-9]{{1,3}}\.[0-9]{{1,3}}"'.format(match.group('tep_idx'))
                    return my_tep_idx_cmd
                else:
                    raise ValueError("Could not get TEP index from line number {} in Ereport".format(i))
        else:
            raise ValueError("TEP Index not found in Ereport")
            
            
    def getAsicType(self):
        for i,asic_type in enumerate(self.data):
            if 'Triggered ASIC type' in asic_type:
                regex = re.compile("(Triggered ASIC type)[\s:]+(?P<asic_type>\w+)")
                match = regex.match(asic_type)
                if match:
                    asic_type = match.group("asic_type")
                    return asic_type.lower()[0:3]
                else:
                    raise ValueError("Could not get Asic type from line number {} in Ereport".format(i))
        else: 
            raise ValueError("ASIC Type not found in Ereport")
            
      
    def getAsicIns(self):
        for i,asic_inst in enumerate(self.data):
            if "Triggered ASIC instance" in asic_inst:
                regex = re.compile("(Triggered ASIC instance)[\s:]+(?P<asic_inst>\w+)")
                match = regex.match(asic_inst)
                if match:
                    asic_inst = match.group("asic_inst")
                    return asic_inst
                else:
                    raise ValueError("Could not get Asic Instance from line number {} in Ereport".format(i))
        else: 
            raise ValueError("ASIC Type not found in Ereport")
                
    
    def getSliceIns(self):
        for i,slice_inst in enumerate(self.data):
            if "Triggered Slice " in slice_inst:
                regex = re.compile("(Triggered Slice)[\s:]+(?P<triggered_slice>\w+)")
                match = regex.match(slice_inst)
                if match:
                    triggered_slice = match.group("triggered_slice")
                    return triggered_slice
                else:
                    raise ValueError("Could not get Triggered Slice from line number {} in Ereport".format(i))
        else: 
            raise ValueError("ASIC Type not found in Ereport")
            
            
            
    def getIncInt(self,triggered_asic,triggered_slice):
        for i,inc_int in enumerate(self.data):
            if "Incoming Interface " in inc_int:
                regex = re.compile("(Incoming Interface)[\s:]+([\w]+)\(\s0x(?P<inc_int>\w+)")
                match = regex.match(inc_int)
                if match:
                    inc_int = (match.group('inc_int'))
                    inc_int_cmd=("vsh_lc -c 'show plat int hal l2 port gpd' | awk '/==/'{{i++}}i==2 | tail -n+2 | awk '$10 ~ \"^{}$\" && $8 ~ \"^{}$\" && $6 ~ \"^{}$\"'").format(inc_int, triggered_asic, triggered_slice) + "| awk '{print $2}'"
                    return inc_int_cmd
                else:
                    raise ValueError("Could not get incoming interface from line {} in Ereport".format(i))
        else:
            raise ValueError("Could not find incoming interface in Ereport")
            
            
            
    def checkPacketFromCpu(self):
        for i,check_pkt_from_cpu in enumerate(self.data):
            if "Packet from CPU" in check_pkt_from_cpu:
                regex = re.compile("(Packet from CPU)[\s:]+(?P<check_pkt_from_cpu>[\w]+)")
                match = regex.match(check_pkt_from_cpu)
                if match:
                    check_pkt_from_cpu = match.group("check_pkt_from_cpu")
                    
                    if check_pkt_from_cpu == "yes":
                        return True
                    else:
                        return False
                else:
                    raise ValueError("Could not check if packet from CPU using line {} in Ereport".format(i))

        else: 
            raise ValueError("Could not detect if packet was from CPU. Sufficient Info not found in Ereport")

            
            
    def getAccessVlan(self):
        for i,access_vlan in enumerate(self.data):
            if "Access Encap VLAN" in access_vlan:
                regex = re.compile("(Access Encap VLAN)[\s:]+(?P<access_vlan>[\d]+)")
                match = regex.match(access_vlan)
                if match:
                    return (match.group("access_vlan"))
                else:
                    raise ValueError("Could not get access vlan from line {} in Ereport".format(i))
            
        else:
            raise ValueError("Could not find Access Vlan in Ereport")
            
            
    def getVnid(self):
        for i,vnid in enumerate(self.data):
            if "VRF or BD VNID" in vnid:
                regex = re.compile("(VRF or BD VNID)[\s:]+(?P<vnid>[\d]+)")
                match = regex.match(vnid)
                if match:
                    return match.group("vnid")
                else:
                    raise ValueError("Could not get vnid from line {} in Ereport".format(i))
            
        else:
            raise ValueError("Could not find Vnid in Ereport")
            
            
    def getSclass(self):
        for i,sclass in enumerate(self.data):
            if "Source      EPG pcTag (sclass)" in sclass:
                regex = re.compile("(Source      EPG pcTag \(sclass\))[\s:]+(?P<sclass>[\d]+)")
                match = regex.match(sclass)
                if match:
                    return match.group("sclass")
                else:
                    raise ValueError("Could not get Sclass from line {} in Ereport".format(i))
        else:
            raise ValueError("Could not find Sclass in Ereport")
            

    def getDclass(self):
        for i,dclass in enumerate(self.data):
            if "Destination EPG pcTag (dclass)" in dclass:
                regex = re.compile("(Destination EPG pcTag \(dclass\))[\s:]+(?P<dclass>[\d]+)")
                match = regex.match(dclass)
                if match:
                    return match.group("dclass")
                else:
                    raise ValueError("Could not get Dclass from line {} in Ereport".format(i))
        else:
            raise ValueError("Could not find Dclass in Ereport")
            
            
            
    def checkDstIpVrfLookupKey(self):
        for i,dst_ip_lookup_vrf_check in enumerate(self.data):
            if "Dst IP Lookup was performed" in dst_ip_lookup_vrf_check:
                regex = re.compile("(Dst IP Lookup was performed)[\s:]+(?P<dst_ip_lookup_vrf_check>[\w]+)")
                match = regex.match(dst_ip_lookup_vrf_check)
                if match:
                    dst_ip_lookup_vrf_check = match.group("dst_ip_lookup_vrf_check")
                    if dst_ip_lookup_vrf_check == "no":
                        return False
                    else:
                        return True
                else: 
                    raise ValueError("Could not check DstIpVrfLookupKey from line {} in Ereport".format(i))
        else:
            raise ValueError("Sufficient data not available to check Dst IP vrf lookup key")
            
            
            
    def checkDstIpLookupResult(self):
        for i,dst_ip_lookup_result in enumerate(self.data):
            if "Dst IP Lookup was not performed" in dst_ip_lookup_result:
                regex = re.compile("(Dst IP Lookup was not performed)[\s:]+(?P<dst_ip_lookup_result>[\w]+)")
                match = regex.match(dst_ip_lookup_result)
                if match:
                    dst_ip_lookup_result = match.group("dst_ip_lookup_result")
                    if dst_ip_lookup_result == "no":
                        return False
                    else:
                        return True
                else: 
                    raise ValueError("Could not check DstIpLookupResult from line {} in Ereport".format(i))
                
        #else:
            #raise ValueError("Sufficient data not available to check Dst IP vrf lookup Result")
            
            
    def getDstIpVrfLookup(self):
        for i,dst_ip_lookup_vrf in enumerate(self.data):
            if "Dst IP Lookup VRF" in dst_ip_lookup_vrf:
                regex = re.compile("(Dst IP Lookup VRF)[\s:]+([\w]+)(\(\s0x)(?P<dst_ip_lookup_vrf>\w+)")
                match = regex.match(dst_ip_lookup_vrf)
                if match:
                    self.idx = match.group("dst_ip_lookup_vrf")
                    dst_vrf_cmd_id = ("vsh_lc -c 'show plat int hal l3 vrf pi' | awk '/==/'{{i++}}i==2 | tail -n+2 | awk '$3 ~ \"^{}$\"'").format(self.idx) + "| awk '{print $1}'"
                    return dst_vrf_cmd_id
                else:
                    raise ValueError("Could not get DstIpVrfLookup from line {} in Ereport".format(i))
            

        else:
            raise ValueError("Could not find Dst IP Lookup VRF in Ereport")
            
            
                
    def checkDstMacLookup(self):
        for i,dst_mac_lookup_bd_check in enumerate(self.data):
            if "Dst MAC Lookup was performed" in  dst_mac_lookup_bd_check:
                regex = re.compile("(Dst MAC Lookup was performed)[\s:]+(?P<dst_mac_lookup_bd_check>[\w]+)")
                match = regex.match(dst_mac_lookup_bd_check)
                if match:
                    dst_mac_lookup_bd_check = match.group("dst_mac_lookup_bd_check")
                    if dst_mac_lookup_bd_check == 'no':
                        return False
                    else:
                        return True
                else:
                    raise ValueError("Could not get DstMacLookup from line {} in Ereport".format(i))
                
        else:
            raise ValueError("Sufficient data not available to check Dst MAC lookup")
            
            
    def getDstMacBdLookup(self):
        for i,dst_mac_bd in enumerate(self.data):
            if "Dst MAC Lookup BD" in dst_mac_bd:
                regex = re.compile("(Dst MAC Lookup BD)[\s:]+([\w]+)(\(\s0x)(?P<dst_mac_bd>\w+)")
                match = regex.match(dst_mac_bd)
                if match:
                    dst_mac_bd = match.group("dst_mac_bd")
                    dst_mac_bd_cmd = (("vsh_lc -c 'show plat int hal l2 bd pi' | awk '/==/'{{i++}}i==2 | tail -n+2 | awk '$4 ~ \"^{}$\"'").format(dst_mac_bd) + "| awk '{print $2}'")
                    return dst_mac_bd_cmd
                else:
                    raise ValueError("Could not get DstMacBdLookup from line {} in Ereport".format(i))
            
        else:
            raise ValueError("Could not find getDstMacBdLookup in Ereport")
            
            
    
    def checkDstIpHit(self):
        for i,dst_ip_hit in enumerate(self.data):
            if "Dst IP is Hit    " in dst_ip_hit:
                regex = re.compile("(Dst IP is Hit    )[\s:]+(?P<dst_ip_hit>[\w]+)")
                match = regex.match(dst_ip_hit)
                if match:
                    dst_ip_hit = match.group("dst_ip_hit")
                
                    if dst_ip_hit == "no":
                        return False
                    else:
                        return True
                else:
                    raise ValueError("Could not check Dst Ip Hit from line {} in Ereport".format(i))

        else:
            raise ValueError("Could not find Dst IP hit in Ereport")
            
            
            
    def getDstIpHit(self):
        for i,dst_ip_hal_route in enumerate(self.data):
            if "Dst IP Hit Index" in dst_ip_hal_route:
                regex = re.compile("(Dst IP Hit Index)[\s:]+([\w]+)(\(\s0x)(?P<dst_ip_hal_route>\w+)")
                match = regex.match(dst_ip_hal_route)
                if match:
                    dst_ip_hal_route = match.group("dst_ip_hal_route")
                    dst_ip_hal_route_cmd = "vsh_lc -c 'show plat int hal l3 routes' | egrep \"{}|VRF\" | tail -n+2 | awk -F '|' '$10 == {} {{ print $0 }}'".format((((dst_ip_hal_route.lower())).strip()),(((dst_ip_hal_route.lower())).strip()))
                    return dst_ip_hal_route_cmd
                else:
                    raise ValueError("Could not get Dst Ip Hit from line {} in Ereport".format(i))
            
        else:
            raise ValueError("Could not find Dst IP Hit Index in Ereport")
            
            
            
    def checkSrcIpVrfLookupKey(self):
        for i,src_ip_lookup_vrf_check in enumerate(self.data):
            if "Src IP Lookup was performed" in src_ip_lookup_vrf_check:
                regex = re.compile("(Src IP Lookup was performed)[\s:]+(?P<src_ip_lookup_vrf_check>[\w]+)")
                match = regex.match(src_ip_lookup_vrf_check)
                if match:
                    src_ip_lookup_vrf_check = match.group("src_ip_lookup_vrf_check")
                
                    if src_ip_lookup_vrf_check == "no":
                        return False
                    else:
                        return True
                else:
                    raise ValueError("Could not check SrcIpVrfLookupKey from line {} in Ereport".format(i))
                
        else:
            raise ValueError("Insufficient data to check if Src IP VRF lookup was performed")
            

    def checkSrcIpLookupResult(self):
        for i,src_ip_lookup_result in enumerate(self.data):
            if "Src IP Lookup was not performed" in src_ip_lookup_result:
                regex = re.compile("(Src IP Lookup was not performed)[\s:]+(?P<src_ip_lookup_result>[\w]+)")
                match = regex.match(src_ip_lookup_result)
                if match:
                    src_ip_lookup_result = match.group("src_ip_lookup_result")
                    if src_ip_lookup_result == "yes":
                        return True
                    else:
                        return False
                else:
                    raise ValueError("Could not get SrcIpLookupResult from line {} in Ereport".format(i))
        #else:
         #   raise ValueError("Insufficient data to check if Src IP lookup Result was performed")
            
            
    def getSrcIpVrfLookup(self):
        for i,src_ip_lookup_vrf in enumerate(self.data):
            if "Src IP Lookup VRF" in src_ip_lookup_vrf:
                regex = re.compile("(Src IP Lookup VRF)[\s:]+([\w]+)(\(\s0x)(?P<src_ip_lookup_vrf>\w+)")
                match = regex.match(src_ip_lookup_vrf)
                if match:
                    src_ip_lookup_vrf = match.group("src_ip_lookup_vrf")
                    src_vrf_cmd_id = ("vsh_lc -c 'show plat int hal l3 vrf pi' | awk '/==/'{{i++}}i==2 | awk '$3 ~ \"^{}$\"'").format(((src_ip_lookup_vrf.lower())).strip()) + "| awk '{print $1}'"
                    return src_vrf_cmd_id
                else:
                    raise ValueError("Could not get SrcIpVrfLookup from line {} in Ereport".format(i))
        else:
            raise ValueError("Source IP lookup not found in Ereport")
            
            
            
    def checkSrcMacLookup(self):
        for i,src_mac_lookup_bd_check in enumerate(self.data):
            if "Src MAC Lookup was performed" in  src_mac_lookup_bd_check:
                regex = re.compile("(Src MAC Lookup was performed)[\s:]+(?P<src_mac_lookup_bd_check>[\w]+)")
                match = regex.match(src_mac_lookup_bd_check)
                if match:
                    src_mac_lookup_bd_check = match.group("src_mac_lookup_bd_check")
                    if src_mac_lookup_bd_check == 'no':

                        return False
                    else:
                        return True
                else:
                    raise ValueError("Could not check SrcMacLookup from line {} in Ereport".format(i))
        else:
            raise ValueError("Insufficient data to check if Src MAC lookup was performed")
            
            
    def getSrcMacBdLookup(self):
        for i,src_mac_bd in enumerate(self.data):
            if "Src MAC Lookup BD" in src_mac_bd:
                src_mac_bd1 = (src_mac_bd.split(":")[-1].strip())
                if src_mac_bd1 == "0( 0x0 )":
                    return src_mac_bd
                else:
                    regex = re.compile("(Src MAC Lookup BD)[\s:]+([\w]+)(\(\s0x)(?P<src_mac_bd>\w+)")
                    match = regex.match(src_mac_bd)
                    if match:
                        src_mac_bd = match.group("src_mac_bd")
                        src_mac_bd_cmd = (("vsh_lc -c 'show plat int hal l2 bd pi' | awk '/==/'{{i++}}i==2 | tail -n+2 | grep -v PBR | awk '$4 ~ \"^{}$\"'").format(((src_mac_bd.lower())).strip()) + "| awk '{print $2}'")
                        return src_mac_bd_cmd
                    else:
                        raise ValueError("Could not get SrcMacBdLookup from line {} in Ereport".format(i))
                
        else:
            raise ValueError("Src MAC BD not found in Ereport")
            
            
    
    def checkSrcIpHit(self):
        for i,src_ip_hit in enumerate(self.data):
            if "Src IP is Hit    " in src_ip_hit:
                regex = re.compile("(Src IP is Hit    )[\s:]+(?P<src_ip_hit>[\w]+)")
                match = regex.match(src_ip_hit)
                if match:
                    src_ip_hit = match.group("src_ip_hit")
                    if src_ip_hit == "no":
                        return False
                    else:
                        return True
                else:
                    raise ValueError("Could not check SrcIpHit from line {} in Ereport".format(i))
                
        else:
            raise ValueError("Insufficient data to check if Src IP lookup HIT was performed")
                

    def getSrcIpHit(self):
        for i,src_ip_hal_route in enumerate(self.data):
            if "Src IP Hit Index" in src_ip_hal_route:
                regex = re.compile("(Src IP Hit Index)[\s:]+([\w]+)(\(\s0x)(?P<src_ip_hal_route>\w+)")
                match = regex.match(src_ip_hal_route)
                if match:
                    self.srcIphitIndex = match.group("src_ip_hal_route")
                    src_ip_hal_route_cmd = ("vsh_lc -c 'show plat int hal l3 routes' | egrep \"{}|VRF\" | tail -n+2 ").format(self.srcIphitIndex.lower())
                    return src_ip_hal_route_cmd
                else:
                    raise ValueError("Could not get SrcIpHit from line {} in Ereport".format(i))
            
        else:
            raise ValueError("Could not find Src IP Hit Index in Ereport")
            
            
                
    def checkContractHit(self):
        for i,check_contract_hit in enumerate(self.data):
            if "Contract Hit" in check_contract_hit:
                regex = re.compile("(Contract Hit)[\s:]+(?P<check_contract_hit>[\w]+)")
                match = regex.match(check_contract_hit)
                if match:
                    contract_hit = match.group("check_contract_hit")
                    if contract_hit == "no":
                        return False
                    else:
                        return True
                else:
                    raise ValueError("Could not check ContractHit from line {} in Ereport".format(i))
        else:
            raise ValueError("Insufficient data to check if Contract HIT was performed")
            
            
    def getRuleId(self):
        i = 1
        for aclqos_contract in self.data:
            if "Contract Aclqos Stats Index" in aclqos_contract:
                value = (aclqos_contract.split(":")[-1]).strip()
                aclqos_contract_cmd = ("vsh_lc -c 'show sys int aclqos zoning-rules' | grep -B 9 \"Idx: {}\"").format(value)
                return aclqos_contract_cmd
            i = i + 1
        
        else:
            raise ValueError("Could not find Aclqos Stats Index in Ereport")
            
            
    def getSupTcamHit(self):
        for sup_tcam in self.data:
            if 'show plat int hal tcam ac-tcam' in sup_tcam:
                regex = re.compile("(show plat int hal tcam ac-tcam \| egrep )\"(?P<sup_tcam>Stats.\*\w+)\"")
                match = regex.match(sup_tcam)
                if match:
                    self.stats_index = match.group("sup_tcam")
                    #Stats.*1397
                    #sup_tcam_cmd = 'vsh_lc -c \'' + sup_tcam.split('|')[0].strip('\n') + "'" + '|' + sup_tcam.split('|')[1].strip('\n')
                    #self.stats_index = (sup_tcam_cmd.split("egrep")[1]).replace('"', '').strip()
                    sup_tcam_cmd = ("vsh_lc -c 'show plat int hal tcam ac-tcam '| sed -n -e '/{}/,/'Stats'/{{/^$/q; p}}'").format(self.stats_index)
                    return sup_tcam_cmd
            
        else:
            raise ValueError("Could not find 'show plat int hal tcam ac-tcam' in Ereport ")
            
            
    def checkDstFloodPtr(self):
        for i,dst_flood_ptr in enumerate(self.data):
            if "Dst Pointer is Flood Pointer" in dst_flood_ptr:
                regex = re.compile("(Dst Pointer is Flood Pointer)[\s:]+(?P<dst_flood_ptr>[\w]+)")
                match = regex.match(dst_flood_ptr)
                if match:
                    check_dst_flood_ptr = match.group("dst_flood_ptr")
                    if check_dst_flood_ptr == "yes":
                        return True
                    else:
                        return False
                else:
                    raise ValueError("Could not check DstFloodPtr from line {} in Ereport".format(i))
                
        else:
            raise ValueError("Insufficient data to check if Dst Pointer is Flood Pointer")
            
            
    
    def getOvector(self):
        for i,ovector in enumerate(self.data):
            if 'ovector' in ovector:
                regex = re.compile("(ovector)[\s:]+([\w]+)(\(\s0x)(?P<ovector>\w+)")
                match = regex.match(ovector)
                if match:
                    self.ovec = (match.group("ovector").strip()).lower()
                    out_int_cmd=("vsh_lc -c 'show plat int hal l2 port gpd' | awk '/==/'{{i++}}i==2 | tail -n+2 | awk '$11 ~ \"^{}$\"'").format(self.ovec) + "| awk '{print $2}'"
                    return out_int_cmd
                else:
                    raise ValueError("Could not get Ovector from line {} in Ereport".format(i))
        else:
            raise ValueError("Could not find ovector in Ereport")
            
            
    def getMetPtr(self):
        for i,met_ptr in enumerate(self.data):
            if 'MET Pointer' in met_ptr:
                regex = re.compile("(MET Pointer)[\s:]+(?P<met_ptr>[\d]+)(\(\s0x)(\w+)")
                match = regex.match(met_ptr)
                if match:
                    met_ptr = match.group("met_ptr")
                    return (met_ptr)
                else:
                    raise ValueError("Could not get Met Pointer from line {} in Ereport".format(i))
        else:
            raise ValueError("Could not find Met Pointer in Ereport")
            
            
    def getFtag(self):
        for i,ftag in enumerate(self.data):
            if 'FTAG' in ftag:
                regex = re.compile("(FTAG)[\s:]+(?P<ftag>[\d]+)(\(\s0x)(\w+)")
                match = regex.match(ftag)
                if match:
                    ftag_id = match.group("ftag")
                    return ftag_id
                else:
                    raise ValueError("Could not get ftag from line {} in Ereport".format(i))
        else:
            raise ValueError("Could not find Ftag in Ereport")


class Interface(Ereport):

    @classmethod
    def check_if_output(cls,arg):
        return((arg[arg.find('\n')+1:arg.rfind('\n')]).strip().replace('\\', '/'))

    def tepIp(self):
        try:
            cmd = self.getTep()
        except ValueError as ex:
            print((ex))

        tepIpOut = ssh.send_command(session,cmd)
        if Interface.check_if_output(tepIpOut):
            return Interface.check_if_output(tepIpOut)
        else:
            raise ValueError("Could not find TEP IP")

    def nodeName(self):
        try:
            tep = Interface.tepIp(self)
        except ValueError as ex:
            print((ex))
            
        nodeNamecmd = ("acidiag fnvread | grep {} | awk '{{print \"Node ID:\" $1 \"   Node Name: \" $3}}'").format(tep)
        nodeNameCmdOut = ssh.send_command(session,nodeNamecmd.strip())
        if (Interface.check_if_output(nodeNameCmdOut)):
            return Interface.check_if_output(nodeNameCmdOut)
        else:
            raise ValueError("Could not find Node Name in 'fnvread' for tep " + tep)

    def IncInt(self):
        try:
            asicIns = Interface.getSliceIns(self)
            sliceIns = Interface.getAsicIns(self)
            cmd = Interface.getIncInt(self,asicIns,sliceIns)
        except ValueError as ex:
            print((ex))
            
        incIntOut = ssh.send_command(session,cmd)

        if Interface.check_if_output(incIntOut):
            return Interface.check_if_output(incIntOut)
        else:
            raise ValueError("Could not find Incoming interface")

       
    def checkIfFabricPort(self):
        try:
            incoming_intf = Interface.IncInt(self)        
        except ValueError as ex:
            print((ex))
        incoming_intf1 = incoming_intf.split("Eth")[1].strip()
        check_is_fabric_port_cmd = ("vsh_lc -c 'show system internal eltmc info interface ethernet {}' | grep fabric_port | awk -F ':::' '{{print $2}}' | awk -F ':' '{{print $2}}'").format(incoming_intf1)
        check_is_fabric_port_cmd_out = Interface.check_if_output(ssh.send_command(session,check_is_fabric_port_cmd))
        if check_is_fabric_port_cmd_out:
            return check_is_fabric_port_cmd_out
        else:
            raise ValueError("Could not detect port type for port " + incoming_intf)

    def ovector(self):
        cmd = Interface.getOvector(self)
        ovec = self.ovec
        if not ovec == '0':
                out_int_cmd__out = ssh.send_command(session,cmd)
                return Interface.check_if_output((out_int_cmd__out))
        else:
            out_int_cmd__out = ssh.send_command(session,cmd)
            out_int_cmd__out = Interface.check_if_output(out_int_cmd__out)
            print("\n")
            print("Outgoing Interface for Ovec 0 is: " + out_int_cmd__out)
            print("Since Ovec is 0x0 packet might be destined to CPU or hitting a Met Pointer. Check OPCODE!!")
            for opcode in data:
                if 'Opcode' in opcode:
                    print(opcode)
                    break

    def SupTcamHit(self):
        try:
            cmd = Interface.getSupTcamHit(self)
            self.stats_index = (self.stats_index).split("*")[1].strip()
        except ValueError as ex:
            print(ex)
        else:
            out = ssh.send_command(session,cmd)
            out = Interface.check_if_output(out)
            if out:
                return out
            else:
                raise ValueError("Could not get Sup TCAM details")


class L2L3Header(Ereport):
    
    """This class gets important L2,L3, inner or outer header from the Ereport"""


    def checkEncapsulation(self):
        for inner_l2_header in data:
            if 'Inner L2 Header' in inner_l2_header:
                return True
        else:
            return False
    '''
    def checkIfArp(self):
        for outer_l3_type in self.data:   
            if "L3 Type" in outer_l3_type:
                if not "ARP" in outer_l3_type:
                    continue
                else:
                    return False
                    break
            else:
                return True
       ''' 

    def checkIfArp(self):
        arp_check_list = []
        for outer_l3_type in self.data:   
            if "L3 Type" in outer_l3_type:
                arp_check_list.append(outer_l3_type.split(":")[1].strip())   

        if "ARP" in  arp_check_list:
            return True
        else:
            return False
        
    
    def find_outer_arp_header(self,word):
        i = 1
        var = ("outer_{}").format(word)
        for var in self.data:   
            if re.match(word, var):
                if i == 1:
                    return var
                i = i+1
        else:
            raise ValueError("Could not find Outer ARP header details")
            
        

    def find_inner_arp_header(self,word):
        var = ("outer_{}").format(word)
        for var in self.data:   
            if re.match(word, var):
                    return var
        else:
            raise ValueError("Could not find Inner ARP header details")



    def find_outer_ipv4_header(self,word):
        i = 1
        var = ("outer_{}").format(word)
        for var in self.data:   
            if re.match(word, var):
                if i == 1:
                    return var
                i = i+1
        else:
            raise ValueError("Could not find Outer IPv4 Header details")

    def find_inner_ipv4_header(self,word):
        i = 1
        var = ("outer_{}").format(word)
        for var in self.data:   
            if re.match(word, var):
                if i == 2:
                    return var

                i = i+1
        else:       
            raise ValueError("Could not find Inner IPv4 Header details")


    def getOuterArpHeader(self):

        print('----------------------------------------------------------------')
        print("Printing ARP Outer header details")
        print('----------------------------------------------------------------')

        try:
            print("Outer " + str(L2L3Header.find_outer_arp_header(self,"L3 Type")))
            print("Outer " + str(L2L3Header.find_outer_arp_header(self,"ARP Opcode")))
            print("Outer " + str(L2L3Header.find_outer_arp_header(self,"ARP Sender MAC")))
            print("Outer " + str(L2L3Header.find_outer_arp_header(self,"ARP Sender IP")))
            print("Outer " + str(L2L3Header.find_outer_arp_header(self,"ARP Target MAC")))
            print("Outer " + str(L2L3Header.find_outer_arp_header(self,"ARP Target IP")))
        except ValueError as ex:
            print((ex))
            print("\n")



    def getInnerArpHeader(self):

        print('----------------------------------------------------------------')
        print("Printing ARP Inner header details")
        print('----------------------------------------------------------------')
        i = 1
        for var in data:   
            if re.match("L3 Type ", var):
                if i == 2:
                    print("Inner " + var)
                i = i+1
                
        try:
            #print("Inner " + str(find_inner_arp_header("L3 Type")))
            print("Inner " + str(L2L3Header.find_inner_arp_header(self,"ARP Opcode")))
            print("Inner " + str(L2L3Header.find_inner_ipv4_header(self,"Source MAC  ")))
            for inner_dst_mac in data:
                if "Inner Destination MAC   " in inner_dst_mac:
                        print(inner_dst_mac)
            print("Inner " + str(L2L3Header.find_inner_arp_header(self,"ARP Sender IP")))
            print("Inner " + str(L2L3Header.find_inner_arp_header(self,"ARP Target MAC")))
            print("Inner " + str(L2L3Header.find_inner_arp_header(self,"ARP Target IP")))
            
        except ValueError as ex:
            print((ex))
            print("\n")


    def getOuterHeader(self):
        print('----------------------------------------------------------------')
        print("Printing outer header details")
        print('----------------------------------------------------------------')
                  
        try:

            print("Outer " + str(L2L3Header.find_outer_ipv4_header(self,"L3 Type  ")))
            print("Outer " + str(L2L3Header.find_outer_ipv4_header(self,"DSCP    ")))
            print("Outer " + str(L2L3Header.find_outer_ipv4_header(self,"TTL   ")))
            print("Outer " + str(L2L3Header.find_outer_ipv4_header(self,"TTL   ")))
            print("Outer " + str(L2L3Header.find_outer_ipv4_header(self,"IP Protocol Number     ")))
            print("Outer " + str(L2L3Header.find_outer_ipv4_header(self,"Source IP   ")))

            outer_src_mac = L2L3Header.find_outer_ipv4_header(self,"Source MAC    ")
            outer_src_mac_only = (outer_src_mac.split(':')[1]).strip()
            if outer_src_mac_only == '000D.0D0D.0D0D' or outer_src_mac_only == '000C.0C0C.0C0C':
                print ('Outer Source MAC                    : ' + outer_src_mac_only + "   # Hint: This is a reserved mac used in outer header for leafs and spines communication.")
                print("\n")
            else:
                print ('Outer ' + outer_src_mac)

            print("Outer " + (L2L3Header.find_outer_ipv4_header(self,"Destination IP    ")))

            outer_dst_mac = L2L3Header.find_outer_ipv4_header(self,"Destination MAC    ")
            outer_dst_mac_only = (outer_dst_mac.split(':')[1]).strip()
            if outer_dst_mac_only == '000D.0D0D.0D0D' or outer_dst_mac_only == '000C.0C0C.0C0C':
                print ('Outer Source MAC                    : ' + outer_dst_mac_only + "   # Hint: This is a reserved mac used in outer header for leafs and spines communication.")
                print("\n")
            else:
                print ('Outer ' + outer_dst_mac)
                  
        except ValueError as ex:
            print((ex))
            print("\n")



    def getInnerHeader(self):
        print('----------------------------------------------------------------')
        print("Printing Inner Header details")
        print('----------------------------------------------------------------')

        try:
            print("Inner " + str(L2L3Header.find_inner_ipv4_header(self,"L3 Type")))
            print("Inner " + str(L2L3Header.find_inner_ipv4_header(self,"DSCP     ")))
            print("Inner " + str(L2L3Header.find_inner_ipv4_header(self,"TTL     ")))
            print("Inner " + str(L2L3Header.find_inner_ipv4_header(self,"IP Protocol Number     ")))
            print("Inner " + str(L2L3Header.find_inner_ipv4_header(self,"Source IP     ")))
            print("Inner " + str(L2L3Header.find_inner_ipv4_header(self,"Source MAC    ")))
            print("Inner " + str(L2L3Header.find_inner_ipv4_header(self,"Destination IP    ")))
            for inner_dst_mac in data:
                if "Inner Destination MAC   " in inner_dst_mac:
                        print(inner_dst_mac)

            #print('----------------------------------------------------------------')
            print("\n")
    
        except ValueError as ex:
            print((ex))
            print("\n")
            
            
    def checkEncapsulation(self):
        for inner_l2_header in self.data:
            if 'Inner L2 Header' in inner_l2_header:
                return True
        else:
            return False

class DstL2L3Lookup(Ereport):

    @classmethod
    def check_if_output(cls,arg):
        return((arg[arg.find('\n')+1:arg.rfind('\n')]).strip().replace('\\', '/'))
    
    def dstIpVrfLookup(self):
        try:
            if DstL2L3Lookup.checkDstIpVrfLookupKey(self) == False:
                return("Destination IP VRF Lookup was not performed")

        except ValueError as ex:
            print((ex))

        else:
            try:
                cmd = DstL2L3Lookup.getDstIpVrfLookup(self)
            except ValueError as ex:
                print((ex))
            else:
                dstVrfOutId = ssh.send_command(session,cmd)
                dstVrfOutId = DstL2L3Lookup.check_if_output(dstVrfOutId).strip()
                if dstVrfOutId:
                    dstVrfNameCmd = ("vsh_lc -c 'show platform internal hal objects l3 vrf id 0x{}'").format(dstVrfOutId.strip().lower()) + " | grep vrfname"
                    dstVrfNameCmdOut = ssh.send_command(session,dstVrfNameCmd)
                    dstVrfNameCmdOut = DstL2L3Lookup.check_if_output(dstVrfNameCmdOut)
                    if dstVrfNameCmdOut:
                        dstVrfName = dstVrfNameCmdOut.split(":",1)[1].strip()
                        return dstVrfName
                    else:
                        raise ValueError("Could not find VRF in 'show platform internal hal objects l3 vrf' for id: "+ dstVrfOutId)
                else:
                    raise ValueError("Could not find Vrf index in 'show plat int hal l3 vrf pi', index: "+ self.idx)
          


    def dstMacBdLookup(self):
        try:
            cmd = DstL2L3Lookup.getDstMacBdLookup(self)
        except ValueError as ex:
            print((ex))
        else:
            if cmd == "0( 0x0 )":
                return "NA"
            else:
                dstMacBdLookup = ssh.send_command(session,cmd)
                dstMacBdLookup = DstL2L3Lookup.check_if_output(dstMacBdLookup)
                if dstMacBdLookup:
                    cmd = dstMacBdLookup.split('-')[1].strip()
                    dstbdnameCmd =  (("show vlan extended | sed 's/ //' | awk '/---/'{{i++}}i==1 | tail -n+2 | awk '$1 ~ \"^{}$\" {{print;getline;print}}'").format(cmd))
                    dstbdnameCmdOut = ssh.send_command(session,dstbdnameCmd)
                    dstbdnameCmdOut = DstL2L3Lookup.check_if_output(dstbdnameCmdOut)
                    if dstbdnameCmdOut:
                        try:
                            if dstbdnameCmdOut.split("\n")[1].split()[0].isdigit() == False:
                                b = re.findall(r'(\w+) *:(?: *([\w.-]+))?', dstbdnameCmdOut)
                                name = []
                                for x in b:
                                    for y in x:
                                        name.append(y+":")
                                return("Destination BD: "+''.join(name)[:-1])
                        except IndexError:
                            print("Issue Joining BD names")

                        try:
                            if dstbdnameCmdOut.split("\n")[0].split()[0].isdigit() == True:
                                x = dstbdnameCmdOut.split("\n")[0]
                                c = re.findall(r'(\w+) *:(?: *([\w.-]+))?', x)
                                name = []
                                for x in c:
                                    for y in x:
                                        name.append(y+":")
                                return("Destination BD: "+''.join(name)[:-1])
                        except IndexError:
                            print("Issue Joining BD names")
                                
                    else:
                        return("Could not find BD in Show vlan extended, key: ",dstMacBdLookup)
                else:
                        return("Could not find BD Index in show plat int hal l2 bd pi")

     


    def dstIpHit(self):
        try:
            if DstL2L3Lookup.checkDstIpLookupResult(self) == False:
                print("Destination IP Lookup was not performed")
            else:
                try:
                    if DstL2L3Lookup.checkDstIpHit(self) == False:
                        print("Destination IP HIT is: NO")
                    else:
                        print("Destination IP HIT is: YES")
                        try:
                            dstIpHitCmd = DstL2L3Lookup.getDstIpHit(self)
                        except ValueError as ex:
                            print((ex))

                        else:
                            dstIpHitCmdOut = ssh.send_command(session,dstIpHitCmd)
                            dstIpHitCmdOut = DstL2L3Lookup.check_if_output(dstIpHitCmdOut)
                            if not dstIpHitCmdOut:
                                print("Could not find Dst IP hit in HAL!")
                            else:
                                print('Destination HAL Route info: ')
                                print('-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
                                print ('''| VRF |                 Prefix/Len                | RT| RID |    LID   | Type| PID | FPID/| HIT |N|  NB-ID  |  NB Hw | PID | FPID/|   TBI   |TRO|Ifindex|CLSS|CLP| AI |SH|DH| Flags            |''')
                                print (dstIpHitCmdOut)
                                print('-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
                                print("\n") 
                except ValueError as ex:
                    print(ex)
        except (ValueError,IndexError) as ex:
            print("Could not find if Destination IP lookup was performed",ex)


    def dstNexthop(self):
        try:
            if DstL2L3Lookup.checkDstNexthop(self) == False:
                return("NextHop L2 Pointer is NOT valid")
            else:
                try:
                    dstNexthopCmd = DstL2L3Lookup.getDstNexthop(self)
                except ValueError as ex:
                    print(ex)
                else:
                    dstNexthopCmdOut = ssh.send_command(session,dstNexthopCmd)
                    dstNexthopCmdOut = DstL2L3Lookup.check_if_output(dstNexthopCmdOut)
                    if not dstNexthopCmdOut:
                        return("Could not find Next Hop L2 details in HAL 'show platform internal hal l3 nexthop' for index: " + self.NextHopL2Ptr)
                    else:
                        return dstNexthopCmdOut
        except ValueError as ex:
            print(ex)
      
           

class SrcL2L3Lookup(Ereport):

    @classmethod
    def check_if_output(cls,arg):
        return((arg[arg.find('\n')+1:arg.rfind('\n')]).strip().replace('\\', '/'))


    def srcIpVrfLookup(self):
        try:
            if SrcL2L3Lookup.checkSrcIpVrfLookupKey(self) == False:
                return("Source IP VRF Lookup was not performed")

        except ValueError as ex:
            print(ex)

        else:
            try:
                cmd = SrcL2L3Lookup.getSrcIpVrfLookup(self)
            except ValueError as ex:
                print((ex))
            else:
                srcVrfOutId = ssh.send_command(session,cmd)
                srcVrfOutId = SrcL2L3Lookup.check_if_output(srcVrfOutId).strip()
                if srcVrfOutId:
                    srcVrfNameCmd = ("vsh_lc -c 'show platform internal hal objects l3 vrf id 0x{}'").format(srcVrfOutId.strip().lower()) + " | grep vrfname"
                    srcVrfNameCmdOut = ssh.send_command(session,srcVrfNameCmd)
                    srcVrfNameCmdOut = SrcL2L3Lookup.check_if_output(srcVrfNameCmdOut)
                    if srcVrfNameCmdOut:
                        srcVrfName = srcVrfNameCmdOut.split(":",1)[1].strip()
                        return srcVrfName
                    else:
                        raise ValueError("Could not find VRF in 'show platform internal hal objects l3 vrf' for id: "+ srcVrfOutId)
                else:
                    raise ValueError("Could not find Vrf index in 'show plat int hal l3 vrf pi', index: ")
          

    
    def srcMacBdLookup(self):
        try:
            cmd = SrcL2L3Lookup.getSrcMacBdLookup(self)
        except ValueError as ex:
            print((ex))
        else:
            if "0( 0x0 )" in cmd:
                return "NA"
            else:
                srcMacBdLookup = ssh.send_command(session,cmd)
                self.srcMacBdLookupOut = SrcL2L3Lookup.check_if_output(srcMacBdLookup)
                

                if self.srcMacBdLookupOut:
                    cmd = self.srcMacBdLookupOut.split('-')[1].strip()
                    #srcbdnameCmd =  ("show vlan extended | awk '/---/'{{i++}}i==1 | tail -n+2 | awk '$1 ~ \"^{}$\"'").format(srcMacBdLookup.split('-')[1].strip()) + "| awk '{print $2}'"
                    srcbdnameCmd = (("show vlan extended | sed 's/ //' | awk '/---/'{{i++}}i==1 | tail -n+2 | awk '$1 ~ \"^{}$\" {{print;getline;print}}'").format(cmd))
                    srcbdnameCmdOut = ssh.send_command(session,srcbdnameCmd)
                    srcbdnameCmdOut = SrcL2L3Lookup.check_if_output(srcbdnameCmdOut)
                    if srcbdnameCmdOut:
                        # If the name spills to name line, below lines gets it and joins the name
                        try:
                            if srcbdnameCmdOut.split("\n")[1].split()[0].isdigit() == False:
                                b = re.findall(r'(\w+) *:(?: *([\w.-]+))?', srcbdnameCmdOut)
                                name = []
                                for x in b:
                                    for y in x:
                                        name.append(y+":")
                                return("Souce BD: "+''.join(name)[:-1])
                        except IndexError:
                            print("Issue Joining BD names")

                        try:
                            if srcbdnameCmdOut.split("\n")[0].split()[0].isdigit() == True:
                                x = srcbdnameCmdOut.split("\n")[0]
                                c = re.findall(r'(\w+) *:(?: *([\w.-]+))?', x)
                                name = []
                                for x in c:
                                    for y in x:
                                        name.append(y+":")
                                return("Souce BD: "+''.join(name)[:-1])
                        except IndexError:
                            print("Issue Joining BD names")
                            

                    else:
                        print("Could not find BD in Show vlan extended, key: ",srcMacBdLookup)
                else:
                        print("Could not find BD Index in show plat int hal l2 bd pi")


   
    def srcIpHit(self):
        try:
            if SrcL2L3Lookup.checkSrcIpLookupResult(self) == False:
                print("Source IP Lookup was not performed")
            else:
                try:
                    if SrcL2L3Lookup.checkSrcIpHit(self) == False:
                        print("Source IP HIT is: NO")
                    else:
                        print("Source IP HIT is: YES")
                        try:
                            srcIpHitCmd = SrcL2L3Lookup.getSrcIpHit(self)
                        except ValueError as ex:
                            print((ex))

                        else:
                            SrcIpHitCmdOut = ssh.send_command(session,srcIpHitCmd)
                            SrcIpHitCmdOut = SrcL2L3Lookup.check_if_output(SrcIpHitCmdOut)
                            if not SrcIpHitCmdOut:
                                print("Could not find Src IP hit in HAL for index: ",self.srcIphitIndex)
                            else:
                                print('Source HAL Route info: ')
                                print('-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
                                print('''| VRF |                 Prefix/Len                | RT| RID |    LID   | Type| PID | FPID/| HIT |N|  NB-ID  |  NB Hw | PID | FPID/|   TBI   |TRO|Ifindex|CLSS|CLP| AI |SH|DH| Flags            |''')
                                print(SrcIpHitCmdOut)
                                print('-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
                                print("\n") 
                except ValueError as ex:
                    print((ex))

        except (ValueError,IndexError) as ex:
            print("Could not find if Source IP lookup was performed")



class Contract(Ereport):

    @classmethod
    def check_if_output(cls,arg):
        return((arg[arg.find('\n')+1:arg.rfind('\n')]).strip().replace('\\', '/'))
    

    def ruleId(self):
        i =1
        try:
            aclQosCmd = Contract.getRuleId(self)
        except ValueError as ex:
            print((ex))
        else:
            aclQosCmdOut = ssh.send_command(session,aclQosCmd)
            if not aclQosCmdOut:
                raise ValueError("Could not find Rule ID")
            else:
                if i == 1:
                    ruleIdCmd = aclQosCmd + ' | grep "Rule ID" | awk \'{print $3}\''
                    ruleIdCmdOut = ssh.send_command(session,ruleIdCmd)
                    if Contract.check_if_output(ruleIdCmdOut):
                        return Contract.check_if_output(ruleIdCmdOut)
                    else:
                        raise ValueError("Coud not find Rule ID")
                i = i+1
    


    def zoningRule(self,ruleId):
        zoning_rule_cmd = ("show zoning-rule | egrep '{}| Rule ID'").format(ruleId)
        #zoning_rule_cmd_out = os.popen(zoning_rule_cmd).read().strip().replace('\\', '/')
        zoning_rule_cmd_out = ssh.send_command(session,zoning_rule_cmd)
        if Contract.check_if_output(zoning_rule_cmd_out):
            return Contract.check_if_output(zoning_rule_cmd_out)
        else:
            print ("Could not find Zoning Rule with Rule ID: ", ruleId)

    def getFilter(self,zoning_rule):
        try:
            filterid = (zoning_rule.split('\n')[1].split('|')[4]).strip()
        except IndexError as ex:
            print("Error Calculating Filter ID from Zoning Rule..!!")
        else:
            filter_cmd = ("show zoning-filter filter {}").format(filterid)
            #filter_cmd_out = os.popen(filter_cmd).read().strip().replace('\\', '/')
            filter_cmd_out = ssh.send_command(session,filter_cmd)
            if Contract.check_if_output(filter_cmd_out):
                return Contract.check_if_output(filter_cmd_out)
            else:
                print("Could not find Filter ID for Zoning Rule")




class Pctag(Ereport):

    @classmethod
    def check_if_output(cls,arg):
        return((arg[arg.find('\n')+1:arg.rfind('\n')]).strip().replace('\\', '/'))


    def getVrfScope(self,dn):
        #this function get the VRF scope using a Dn) Dn will be created using SRC vrf lookup which
        # gives tenant and VRF, this scope will be used in PCTAG lookup
        vrf_scope_cmd = ("moquery -d {}").format(dn) + " | grep scope | awk -F \":\" '{{print $2}}'"
        vrf_scope_cmd_out = os.popen(vrf_scope_cmd).read().strip().replace('\\', '/')
        if (vrf_scope_cmd_out):
            return vrf_scope_cmd_out
        else:
            raise ValueError("Could not find VRF scope for dn: " + dn)


    def checkWhichVnid(self,vnid):

        # Whenever packet comes from fabric, it includes a Vnid, This function checks if this Vnid is
        # VRF / BD / EPG vnid and returns a dict 

        dict = {}
        #checking in FvBD
        check_bd_vnid_cmd = ("moquery -c fvBD -f 'fv.BD.seg==\"{}\"' | egrep '^scope|^seg'").format(vnid)
        check_bd_vnid_cmd_out = os.popen(check_bd_vnid_cmd).read().strip().replace('\\', '/')
        if check_bd_vnid_cmd_out:
            check_bd_vnid_cmd_out = check_bd_vnid_cmd_out.splitlines()
            bd = check_bd_vnid_cmd_out[1].split(":")[1].strip()
            vrf = check_bd_vnid_cmd_out[0].split(":")[1].strip()
            dict.update({"bd_vnid":bd})
            dict.update({"vrf_vnid":vrf})
        else:
            #checking in fvCtx
            check_vrf_vnid_cmd = ("moquery -c fvCtx -f 'fv.Ctx.seg==\"{}\"' | grep \"^scope \"").format(vnid)
            check_vrf_vnid_cmd_out = os.popen(check_vrf_vnid_cmd).read().strip().replace('\\', '/')
            
            if check_vrf_vnid_cmd_out:
                check_vrf_vnid_cmd_out = check_vrf_vnid_cmd_out.splitlines()
                vrf = check_vrf_vnid_cmd_out[0].split(":")[1].strip()
                dict.update({"vrf_vnid":vrf})
            else:
                #checking in vlanCktEp
                check_epg_vnid_cmd = ("moquery -c vlanCktEp -f 'vlan.CktEp.fabEncap==\"vxlan-{}\"' | grep ^name | head -n 1 ").format(vnid)
                check_epg_vnid_cmd_out = os.popen(check_epg_vnid_cmd).read().strip().replace('\\', '/')
                if check_epg_vnid_cmd_out:
                    check_epg_vnid_cmd_out = check_epg_vnid_cmd_out.splitlines()
                    fabencap = check_epg_vnid_cmd_out[0].split(":")[1][7:]
                    dict.update({"epg_vnid":fabencap})
                else:
                    raise ValueError("Could not find if Vnid belongs to BD/VRF/EPG")
        return dict


    def getFvAEPg(self,pctag,scope):
    # global range 16-16385, if class is in global range then check without scope, else chech with scope.
        global_range = range(16,16385)
        if int(pctag) in global_range:
            print("This is a Global PcTag")
            fvaepg_cmd = ("moquery -c fvAEPg -f 'fv.AEPg.pcTag==\"{}\"' | egrep \"^dn\" ").format(pctag)
            fvaepg_cmd_out = os.popen(fvaepg_cmd).read().strip().replace('\\', '/')
            if fvaepg_cmd_out:
                out =  fvaepg_cmd_out.split("/")
                return("Tenant: "+out[-3], "APP: "+out[-2], "EPG: "+out[-1])
            else:
                raise ValueError("Could not find EPG in fvAEPg for pctag {}. Checking in getL3extInstp".format(pctag))

        elif int(pctag) not in global_range:
            
            fvaepg_cmd = ("moquery -c fvAEPg -f 'fv.AEPg.pcTag==\"{}\" and fv.AEPg.scope==\"{}\"' | egrep \"^dn\" ").format(pctag,scope)
            fvaepg_cmd_out = os.popen(fvaepg_cmd).read().strip().replace('\\', '/')
            if fvaepg_cmd_out:
                out =  fvaepg_cmd_out.split("/")
                return("Tenant: "+out[-3], "APP: "+out[-2], "EPG: "+out[-1])
            else:
                raise ValueError("Could not find EPG in fvAEPg for pctag {} and scope {}. Checking in getL3extInstp".format(pctag,scope))
                


    def getL3extInstp(self,pctag,scope):
        global_range = range(16,16385)
        if int(pctag) in global_range:
            l3extinstp_cmd = ("moquery -c l3extInstP -f 'l3ext.InstP.pcTag==\"{}\"' | egrep \"^dn\" ").format(pctag)
            l3extinstp_cmd_out = os.popen(l3extinstp_cmd).read().strip().replace('\\', '/')
            if l3extinstp_cmd_out:
                out =  l3extinstp_cmd_out.split("/")
                return("Tenant: "+out[-3], "APP: "+out[-2], "EPG: "+out[-1])
            else:
                raise ValueError("Could not find EPG in L3extInstp for pctag {}. Checking in getFvCtx".format(pctag,scope))

        else:
            l3extinstp_cmd = ("moquery -c l3extInstP -f 'l3ext.InstP.pcTag==\"{}\" and l3ext.InstP.scope==\"{}\"' | egrep \"^dn\" ").format(pctag,scope)
            l3extinstp_cmd_out = os.popen(l3extinstp_cmd).read().strip().replace('\\', '/')
            if l3extinstp_cmd_out:
                out =  l3extinstp_cmd_out.split("/")
                return("Tenant: "+out[-3], "APP: "+out[-2], "EPG: "+out[-1])
            else:
                raise ValueError("Could not find EPG in L3extInstp for pctag {} and scope {}. Checking in getFvCtx".format(pctag,scope))



    def getFvCtx(self,pctag,scope):
        global_range = range(16,16385)
        if int(pctag) in global_range:
            fvctx_cmd = ("moquery -c fvCtx -f 'fv.Ctx.pcTag==\"{}\"' | egrep \"^dn\" ").format(pctag)
            fvctx_cmd_out = os.popen(fvctx_cmd).read().strip().replace('\\', '/')
            if fvctx_cmd_out:
                return(fvctx_cmd_out)
            else:
                raise ValueError("Could not find EPG in fvCtx for pctag {}".format(pctag,scope))
        else:
            fvctx_cmd = ("moquery -c fvCtx -f 'fv.Ctx.pcTag==\"{}\" and fv.Ctx.scope==\"{}\"' | egrep \"^dn\" ").format(pctag,scope)
            fvctx_cmd_out = os.popen(fvctx_cmd).read().strip().replace('\\', '/')
            if fvctx_cmd_out:
                out =  fvctx_cmd_out.split("/")
                return("Tenant: "+out[-2], "Ctx: "+out[-1])
            else:
                raise ValueError("Could not find EPG in fvCtx for pctag {} and scope {}".format(pctag,scope))


    def getVlanCktEp(self,access_vlan,pctag):
        #moquery -c vlanCktEp -f 'vlan.CktEp.encap=="vlan-80" and vlan.CktEp.pcTag=="32772"' | egrep "^dn|^name"
        vlancktep_cmd = ("moquery -c vlanCktEp -f 'vlan.CktEp.encap==\"vlan-{}\" and vlan.CktEp.pcTag==\"{}\"' | egrep \"^dn|^name\"").format(access_vlan,pctag)
        vlancktep_cmd_out = os.popen(vlancktep_cmd).read().strip().replace('\\', '/')
        if vlancktep_cmd_out:
            return ((vlancktep_cmd_out))
        else:
            raise ValueError("Could not find EPG Dn in vlanCktEp for vlan {} and class {}".format(access_vlan,pctag))



    def getClasslookup(self,pctag=None,scope=None):
        try:
            return Pctag.getFvAEPg(self,pctag,scope)
        except ValueError as ex:
            print(ex)
            try:
                return Pctag.getL3extInstp(self,pctag,scope)
            except ValueError as ex:
                print(ex)
                try:
                    return Pctag.getFvCtx(self,pctag,scope)
                except ValueError as ex:
                    print(ex)
            
        

class Multicast(Ereport):

    @classmethod
    def check_if_output(cls,arg):
        return((arg[arg.find('\n')+1:arg.rfind('\n')]).strip().replace('\\', '/'))

    def get_asic_table_alias(self,chip):
        asic = '_'+chip+'_'
        asic_table_alias_cmd = ("vsh_lc -c 'show platform internal {} table list'").format(chip)
        #asic_table_alias_cmd_out = os.popen(asic_table_alias_cmd).read().strip().replace('\\', '/')
        asic_table_alias_cmd_out = ssh.send_command(session,asic_table_alias_cmd)
        asic_table_alias_cmd_out = Multicast.check_if_output(asic_table_alias_cmd_out)
        asic_table_alias_cmd_out = asic_table_alias_cmd_out.split("\n")
        for alias in asic_table_alias_cmd_out:
            if asic in alias:
                return(alias[0:8])
                break
    
    def get_ftag(self):
        ftag_lst = []
        for ftag in self.data:
            if 'FTAG' in ftag:
                ftag_id = ftag.split(':')[1].split('(')[0].strip()
                ftag_lst.append(ftag_id)
                
        if len(ftag_lst) == 0:
            if intf.checkIfFabricPort() == True:
                for i,ip in enumerate(self):
                        for j,item in enumerate(self):
                            if j == i+7:
                                gipo_from_ts = (item.split(':')[1].strip())

                #since we carry last 4 bits as ftag calculating ftag
                if ipaddress.ip_address(unicode(gipo_from_ts)).is_multicast == True:
                    last_oct = int(gipo_from_ts.split('.')[3])
                    ftag = int((bin(last_oct)[-4:]),2)
                    return(ftag)

                else:
                    raise ValueError("No FTAG info in Ereport, Could not Calculate FTAG from BD GIPO")

            else:
                raise ValueError("Could not determine port type, Issues in determining BD GIPO and FTAG")

        else:
            for ftag in ftag_lst:
                return ftag
            else:
                raise ValueError("Could not get FTAG from Ereport")


    def getGipoFromBdFloodList(self,bd):
        try:
            splitbd = (bd.split("-")[1].strip())
        except IndexError:
            print("Could not find GIPO from BD since BD lookup was not done")
        else:
            bd_floodlist_cmd = ("vsh_lc -c 'show platform internal hal l2 mcast bd_flood_list bd {}'| awk '/==/'{{i++}}i==2 | tail -n+2 | grep -Eo \"[0-9]{{1,3}}\.[0-9]{{1,3}}\.[0-9]{{1,3}}\.[0-9]{{1,3}}\" | uniq").format(splitbd)
            #print(bd_floodlist_cmd)
            #gipo_from_bd_flood_list = os.popen(bd_floodlist_cmd).read().strip().replace('\\', '/')
            gipo_from_bd_flood_list = ssh.send_command(session,bd_floodlist_cmd)
            if gipo_from_bd_flood_list:
                return (Multicast.check_if_output(gipo_from_bd_flood_list))
            else:
                raise ValueError("Could not find GPIO from BD Floodlist with BD ID: " + bd)

    def getIsisMcastRoute(self,gipo):
        isis_mcast_route_cmd = ("vsh -c 'show isis internal mcast routes gipo' | sed -n -e '/{}/,/'GIPo'/{{/^$/q; p}}'").format(gipo)
        #print(isis_mcast_route_cmd)
        #isis_mcast_route_cmd_out = os.popen(isis_mcast_route_cmd).read().strip().replace('\\', '/')
        isis_mcast_route_cmd_out = ssh.send_command(session,isis_mcast_route_cmd)
        if isis_mcast_route_cmd_out: 
            return (Multicast.check_if_output(isis_mcast_route_cmd_out))
        else:
            raise ValueError ("Could find isis mcast route for GIPO: " + gpio)

    def getIsisFtagRoute(self,ftag):
        isis_ftag_route_cmd = ("vsh -c 'show isis internal mcast routes ftag'| tr -s ' ' | sed -n -e '/ID: {}/,/'FTAG'/{{/^$/q; p}}'").format(ftag)
        #print(isis_ftag_route_cmd)
        #isis_ftag_route_cmd_out = os.popen(isis_ftag_route_cmd).read().strip().replace('\\', '/')
        isis_ftag_route_cmd_out = ssh.send_command(session,isis_ftag_route_cmd)
        if isis_ftag_route_cmd_out:
            return (Multicast.check_if_output(isis_ftag_route_cmd_out))
        else:
            raise ValueError("Could not find isis ftag route for ftag: "+ ftag)

    def getMcastReplListHandle(self,gipo):
        repl_lst_id_cmd  = ("vsh_lc -c 'show platform internal hal objects mcast l3mcastroute groupaddr {}/32 extensions' | grep mcast_repl_list-id | awk -F ':' '{{print $2}}'").format(gipo)
        #repl_lst_id_cmd_out = os.popen(repl_lst_id_cmd).read().strip().replace('\\', '/')
        repl_lst_id_cmd_out = ssh.send_command(session,repl_lst_id_cmd)
        repl_lst_id_cmd_out = Multicast.check_if_output (repl_lst_id_cmd_out)
        if repl_lst_id_cmd_out:
            return repl_lst_id_cmd_out
        else:
            raise ValueError("Could not find Mcast repl-list handle for GPIO: "+ gipo)


    def getMcastReplLstObj(self,mcast_repl_list_handle_id):
        mcast_repl_lst_obj_cmd = ("vsh_lc -c 'show platform internal hal objects mcast mcastrepllist id  {} extensions'").format(mcast_repl_list_handle_id)
        #mcast_repl_lst_obj_cmd_out = os.popen(mcast_repl_lst_obj_cmd).read().strip().replace('\\', '/')
        mcast_repl_lst_obj_cmd_out = ssh.send_command(session,mcast_repl_lst_obj_cmd)
        mcast_repl_lst_obj_cmd_out = Multicast.check_if_output(mcast_repl_lst_obj_cmd_out)
        if "OBJECT" in mcast_repl_lst_obj_cmd_out:
            return (mcast_repl_lst_obj_cmd_out)
        else:
            raise ValueError("Could not get mcast_repl_lst_obj for handle: "+  mcast_repl_list_handle_id)


    def getMcIdLst(self,mcast_repl_lst_obj):
        mcast_repl_lst_obj_lst = mcast_repl_lst_obj.split('\n')
        mc_id_lst = []
        for mc_id in mcast_repl_lst_obj_lst:
            if "Mc Id:" in mc_id:
                mc_id_lst.append((mc_id.split(":")[1].strip().split()[0]))
        return mc_id_lst
        
    def getMcastPortFanout(self,mc_id):
        mcast_port_fanout_cmd = ("vsh_lc -c 'show platform internal hal objects mcast mcastportsfanout mc_idx {} extensions'").format(mc_id)
        #print(mcast_port_fanout_cmd)
        #mcast_port_fanout_cmd_out = os.popen(mcast_port_fanout_cmd).read().strip().replace('\\', '/')
        mcast_port_fanout_cmd_out = (ssh.send_command(session,mcast_port_fanout_cmd))
        #print(mcast_port_fanout_cmd_out)
        mcast_port_fanout_cmd_out = Multicast.check_if_output(mcast_port_fanout_cmd_out)
        #print(mcast_port_fanout_cmd_out)
        if "OBJECT" in mcast_port_fanout_cmd_out:
            return (mcast_port_fanout_cmd_out)
        else:
            raise ValueError ("Could not find mcastPortFanout for McId: " + mc_id)


    def getMcastIfmapArgs(self,cmd_out):
        args = []
        for item in cmd_out:
            if "Asic-Id" in item:
                asic = [x for x in item.split(' ') if x is not ''][2]
            if "Slice-Id" in item:
                x = [x for x in item.split(' ') if x is not '']
                if len(x) == 9:
                    x[8] = x[8].rstrip()
                    if x[8] is not "0":
                        args.append(asic + " " + x[2] + " " + x[8] + " " + x[5])
                elif len(x) == 8:
                    x[7] = x[7].rstrip()
                    if x[7] is not "0":

                        args.append(asic + " " + x[2] + " " + x[7] + "  " + x[5])
                elif len(x) == 6:
                    x[5] = x[5].rstrip()
                    if x[5] is not "0":
                        args.append(asic + " " + x[2] + " " + x[5])      
        if len(args)<1:
            raise ValueError ("Could not get Ifmaps Args")
        else:                        
            return(args)

    def getIfmapToIfname(self,args):
        a = []
        res = []
        intf = []
        for item in args:
            ifmap_to_ifname_cmd = ("vsh_lc -c 'show platform internal hal l2 ifmap-to-ifname " + item + "'")
            # node.sh_cmd('vsh_lc', '# ')
            #ifmap_to_ifname_cmd_output = os.popen(get_ifmap_to_ifname.ifmap_to_ifname_cmd).read().strip().replace('\\', '/')
            ifmap_to_ifname_cmd_output = ssh.send_command(session,ifmap_to_ifname_cmd)
            # node.sh_cmd('exit', '# ')
            ifmap_to_ifname_cmd_output = Multicast.check_if_output(ifmap_to_ifname_cmd_output)
            ifmap_to_ifname_cmd_output = ifmap_to_ifname_cmd_output.split("\n")
            for line in ifmap_to_ifname_cmd_output:
                if "Eth" in line:
                    res = [y for y in line.split(' ') if "Eth" in y]
            if res != []:
                a.append(res)
        for list1 in a:
            for item in list1:
                intf.append(item)

        if len(intf)<1:
            raise ValueError("Could not get ifmap to ifname")
        else:
            return intf


    def get_ovindx_list(self,met): 

        if met == '0x0':
            return                        
        
        qsmt_met_cmd = ("vsh_lc -c 'show platform internal {} table {}qsmt_met " + met + "'").format(chip,table_alias)
        #qsmt_met_cmd_out = os.popen(qsmt_met_cmd).read().strip().replace('\\', '/')
        qsmt_met_cmd_out = ssh.send_command(session,qsmt_met_cmd)
        #print(qsmt_met_cmd_out)
        #print("\n")
        qsmt_met_cmd_out = Multicast.check_if_output(qsmt_met_cmd_out)
        qsmt_met_cmd_out = qsmt_met_cmd_out.splitlines()
        regex_str = u'.*next_ptr=(\S+)|.*ovidx=(\S+)'
        ovidx_list = []
        for line in qsmt_met_cmd_out:
            if 'ENTRY' in line:
                regex_match = re.findall(regex_str, line)
                if regex_match:
                    if len(regex_match) == 1:
                        next_met = '0x0'
                        ovidx = regex_match[0][1]
                    else:
                        next_met = regex_match[0][0]
                        ovidx = regex_match[1][1]
                    if ovidx != '0x1ffc' and ovidx != '0x1fff':
                        print("Ovidx from QSMT_MET table is: " + ovidx)
                        ovidx_list.append(ovidx)
                    Multicast.get_ovindx_list(self,next_met)
                    return ovidx_list


    def get_ifmap_list_from_qsmt_ovtbl(self,ovidx):
        regex_str = u'.*data=0x(\S+)'
        intf_list = []
        ifmap_list = []
        one_ifmap_list = []
        qsmt_ovtbl_cmd = ("vsh_lc -c 'show platform internal {} table {}qsmt_ovtbl " + ovidx + "'" ).format(chip,table_alias)
        print("Getting " + qsmt_ovtbl_cmd)
        #qsmt_ovtbl_cmd_out = os.popen(qsmt_ovtbl_cmd).read().strip().replace('\\', '/')
        qsmt_ovtbl_cmd_out = ssh.send_command(session,qsmt_ovtbl_cmd)
        #print(qsmt_ovtbl_cmd_out)
        qsmt_ovtbl_cmd_out = Multicast.check_if_output(qsmt_ovtbl_cmd_out)
        qsmt_ovtbl_cmd_out = qsmt_ovtbl_cmd_out.splitlines()
        for line in qsmt_ovtbl_cmd_out:
            if 'ENTRY' in line:
                regex_match = re.match(regex_str, line)
                if regex_match:
                    one_ifmap_list.append(regex_match.group(1))
        if one_ifmap_list != []:

            ifmap_list.append(one_ifmap_list)

        if len(ifmap_list)<1:
            raise ValueError ("Could not get ifmap from qsmt table")
        else:
            return (ifmap_list)


    def get_ifmap_args_list_from_ifmap_list(self,ifmap):
        ifmap_args_list = []
        slice_arg = [' 0 0 ',' 0 1 ']
        for ifmap in ifmap_list:
            for i in range(0,len(ifmap)):
                if len(ifmap[i]) > 16:
                    ifmap1 = '0x' + (ifmap[i])[len(ifmap[i])-16:len(ifmap[i])]
                    ifmap2 = '0x' + (ifmap[i])[0:len(ifmap[i])-16]
                else:
                    ifmap1 = ''
                    ifmap2 = '0x' + ifmap[i]
                    ifmap_args_list.append(slice_arg[i] + ' ' + ifmap2 + ' ' +ifmap1)
        if len(ifmap_args_list) < 1:
            raise ValueError("Could not get ifmap args from ifmap list")
        else:
            return(ifmap_args_list)

##################################################################################End of functions##############################################################


def main(uName,password,hostIp):

    logging.info("Getting Node details")
    model,role = getModel(lName[4:])
    a=lName[:3]
    sh=pexpect.run('moquery -c eqptFC')
    flag_sp = a in sh
    if role == "leaf" or not flag_sp:

        asic = get_asic_by_pid(model)
        logging.info("Device Role: {} | Model: {} | Asic: {}".format(role,model,asic))
        logging.info("Now Ready..!! Please provide input for setting Elam")

        layer = ''
        final_dict = {}
        layer_list = []
        global lst
        lst=["inner","outer"]
        readline.set_completer(complete)
        layer = raw_input("Capture inner or outer : ").lower()
        lst=[]
        interface=""
        if layer!="inner" and layer!="outer":
            print("Invalid option entered")
            sys.exit(0)
        if layer == "inner":
            layer_list.append(layer)
            final_dict.update({"inner": {}}) 
            if role=="leaf":
                interface = raw_input("Enter the interface name(Ethx/y) for srcid capture:")
                interface=interface.capitalize()
            final_dict["inner"].update(get_inner())
            lst=["inner","outer","exit"]
            readline.set_completer(complete)
            layer = raw_input("Capture inner or outer packet (type \"exit\" to stop capturing input and start triggering elam): ").lower()
            if layer!="inner" and layer!="outer" and layer!="exit":
                print("Invalid option entered")
                sys.exit(0)
            
            if layer == "inner":
                final_dict["inner"].update(get_inner())
            elif layer == "outer":
                final_dict.update({"outer": {}})
                final_dict["outer"].update(get_outer_vxlan())
        elif layer == "outer":
            layer_list.append(layer)
            final_dict.update({"outer": {}}) 
            if role=="leaf":
                interface = raw_input("Enter the interface name(Ethx/y) for srcid capture:")
                interface = interface.capitalize()
            final_dict["outer"].update(get_outer())
            lst=["outer","exit"]
            readline.set_completer(complete)
            layer = raw_input("Capture outer packet (type \"exit\" to stop selecting further filters and start triggering elam, type \"outer\" to set more elam filters):").lower()
            if layer!="outer"  and layer!="exit":
                print("Invalid Option")
                sys.exit(0)
            if layer == "outer":
                final_dict["outer"].update(get_outer())
            
        try:
            if not final_dict["outer"]:
                del(final_dict["outer"])
            elif not final_dict["inner"]:
                del(final_dict["inner"])

        except:
            pass


        if layer_list[0] == "outer":
            insel = "6"   
        elif layer_list[0] == "inner":
            insel = "14"

        if role == "leaf" or not flag_sp:

            init_dict = {"asic_type": asic,
                    "asic_inst": "0",
                    "inselect": insel,
                    "outselect": "0",
                    "slice_id":None,
                    "inner":{},
                    "outer":{},
                    }
            
            if interface:
                init_dict['src_id'],init_dict["slice_id"]=get_srcid(interface,insel,asic)                
                
            a = (deep_update(init_dict,final_dict))
            #print(a)

            ec = ElamCommand(a)
            if ec.bad_param is not None:
                print("--failed--")
                print(("missing info : {}".format(ec.bad_param["missing_info"])))
                print(("unsupported param : {}".format(ec.bad_param["unsupported_param"])))
            else:               
                logging.info("Setting Elam for {}".format(role))
                logging.info("Setting Elam | cmds {}".format(ec.set_cmds))
                start=setLeafElam(ec.deb_cmd,ec.tri_cmd,ec.set_cmds)
                #print(start)
                status = (getElamStatus(str(ec.deb_cmd).strip(),str(ec.tri_cmd).strip()))
                logging.info("Getting Status")                      
                while(True):
                    flag=0
                    start_time=datetime.datetime.now()
                    while((datetime.datetime.now()-start_time).seconds<=5): #if the current time < start time + 2 mins    
                        status = (getElamStatus(str(ec.deb_cmd).strip(),str(ec.tri_cmd).strip()))
                #print("Status:",status)
                #print(type(status))
                
                #check if elam is triggered

                        regex = re.compile("Triggered")
                        match = regex.search(status)
                #print(match)
                        if match:
                    #print(match.group())
                            logging.info("Elam triggered")
                            logging.info("Generating report")
                            generateEreport(str(ec.deb_cmd).strip(),str(ec.tri_cmd).strip())
                            logging.info("Ereport generated")
                            out=ssh.send_command(session,"ls -laRt /var/sysmgr/tmp_logs/pretty* | head -n 1")
                            out=out.split("\n")[1]
                            #print(out)
                            b=out.index('/') 
                            global fileName
                            fileName = out[b:].split("/")
                            fileName = fileName[-1][:-1]
                            print("Elam file "+fileName+" generated and saved at /var/sysmgr/tmp_logs/ in Switch")
                            flag=1
                            break
                        else:
                            logging.info("ELAM not triggered yet")
                    if flag==0:
                        inp=raw_input("Elam not triggered yet, Do you want to continue(Y/N):").lower()
                        if inp=='y':
                            continue
                        else:
                            break
                    else:
                        break
            if flag == 1 and role =="leaf":
                inp=raw_input("Do you want to parse this report(Y/N):").lower()
                if inp == 'y':
                    out=ssh.send_command(session,"ls -laRt /var/sysmgr/tmp_logs/pretty* | head -n 1")
                    out=out.split("\n")[1]
                    #print(out)
                    b=out.index('/')
                    fileName = out[b:].split("/")
                    #print(fileName,"filename")
                    fileName = fileName[-1][:-1]
                    myTopSys = json.loads(os.popen('''icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=eq(topSystem.name,"'"$HOSTNAME"'")' 2>/dev/null''').read())
                    myAddr = myTopSys['imdata'][0]['topSystem']['attributes']['address']
                    cmd = 'sshpass -p ' + password + ' scp -q -o ServerAliveInterval=2 -o ServerAliveCountMax=1 -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o BindAddress=' + myAddr + ' -o UserKnownHostsFile=/dev/null ' + uName +"@"+ hostIp + '://var/sysmgr/tmp_logs/' + fileName + ' /data/techsupport/'
                    print("Copying ELAM File to /data/techsupport")
                    #print(cmd)
                    try:
                        pexpect.run(cmd)
                        print("ELAM File copied to the APIC")
                    except:
                        print("Error connecting to the Node")
                else:
                    print("Execution Completed!!!")
                    sys.exit(0)
            else:
		print("Execution Completed!!!")
		sys.exit(0)




    elif role =="spine":
        logging.info("Device Role:{} | Model: {}".format(role,model))
        logging.info("Getting Module details from spine")
        try:
            mod_list = getModList()
        except Exception:
            logging.error("Could not get module list from the device")
        else:
            logging.info("Getting ASIC details for the modules")
            try:
                asic_dict = getAsicDict(mod_list)
            except Exception:
                logging.error("Could not build asic dictionary")
            
        pool = Pool(9)

        # check if mod mapping exists
        halarglst = []
        for mod in asic_dict.keys():
            check = ssh.send_command(session,"ls /data/techsupport/mod-mapping{}.txt".format(mod))
            if "No such file or directory" in check:
                halarglst.append((mod,uName,password,hostIp))
                try:
                    ssh.send_command(session,"rm /data/techsupport/haloutmod{}.txt".format(mod))
                except Exception:
                    pass
        

        #getting hal outputs 
        if len(halarglst) >= 1:
            halp = pool.map_async(getHalOutputs_wrapper,halarglst)
            try:
                halResults = halp.get(0xFFFF)
            except KeyboardInterrupt:
                print ('parent received control-c. Wait 5 seconds for cleanup')
                pool.terminate()
                return
            except Exception:
                pool.terminate()
                return
            for i in halResults:
                logging.info(i)
        else:
            logging.info("All mod-mappings are present")

        logging.info("Now Ready..!! Please provide input for setting Elam")


        layer = ''
        final_dict = {}
        layer_list = []
        while layer != "exit":
            lst=["inner","outer"]
            readline.set_completer(complete)
            layer = raw_input("Capture inner or outer : ").lower()
            if layer == "inner":
                layer_list.append(layer)
                final_dict.update({"inner": {}})
                final_dict["inner"].update(get_inner())
                lst=["inner","outer","exit"]
                readline.set_completer(complete)
                layer = raw_input("Capture inner or outer packet (type \"exit\" to stop capturing input and start triggering elam): ").lower()
                if layer!="inner" and layer!="outer" and layer!="exit":
                    print("Invalid option entered")
                    sys.exit(0)
                if layer == "inner":
                    final_dict["inner"].update(get_inner())
                elif layer == "outer":
                    final_dict.update({"outer": {}})
                    final_dict["outer"].update(get_outer_vxlan())
            elif layer == "outer":
                layer_list.append(layer)
                final_dict.update({"outer": {}})
                final_dict["outer"].update(get_outer())
                lst=["outer","exit"]
                readline.set_completer(complete)
                layer = raw_input("Capture outer packet (type \"exit\" to stop selecting further filters and start triggering elam, type \"outer\" to set more elam filters):").lower()
                if layer!="outer"  and layer!="exit":
                    print("Invalid Option")
                    sys.exit(0)
                if layer == "outer":
                    final_dict["outer"].update(get_outer())
        try:
            if not final_dict["outer"]:
                del(final_dict["outer"])
            elif not final_dict["inner"]:
                del(final_dict["inner"])

        except:
            pass


        if layer_list[0] == "outer":
            insel = "6"   
        elif layer_list[0] == "inner":
            insel = "14"
    
        elamArgLst = []
        date = datetime.datetime.now().strftime("%d-%m-%YT%H:%M:%S")
        for module,asic in asic_dict.items():
            for asic_inst in getNumberOfAsic(module):
                init_dict = {"asic_type": asic,
                        "asic_inst": asic_inst,
                        "inselect": insel,
                        "outselect": "0",
                        "inner":{},
                        "outer":{},
                        }  

                a = (deep_update(init_dict,final_dict))
                ec = ElamCommand(a)
                if ec.bad_param is not None:
                    print("--failed--")
                    print(("missing info : {}".format(ec.bad_param["missing_info"])))
                    print(("unsupported param : {}".format(ec.bad_param["unsupported_param"])))
                else:
                    elamArgLst.append((module,ec.deb_cmd,ec.tri_cmd,ec.set_cmds,asic_inst,uName,password,hostIp,date))

        

        p = pool.map_async(setElam_wrapper,elamArgLst)

        try:
            results = p.get(0xFFFF)
        except KeyboardInterrupt:
            print ('parent received control-c. Wait 5 seconds for cleanup')
            pool.terminate()
            return
        except Exception:
            pool.terminate()
            return

        for i in results:
            logging.info(i)

        sys.exit(0)
        

if __name__ == "__main__":

    logging.basicConfig(format='%(levelname)s - %(asctime)s.%(msecs)03d: %(message)s',datefmt='%H:%M:%S', level=logging.DEBUG)
    node_name_ip=pexpect.run('acidiag fnvread')
    result_dict=process_diag(node_name_ip)
    #print(result_dict)
    lst=list(result_dict.keys())
    readline.set_completer(complete)

    uName=raw_input("Enter the username:")
    password=getpass.getpass("Enter the password:")
    lName=raw_input("Enter the leaf node ID/name in the format NODEID-NODENAME, please use tab for auto completion:")
    hostIp=result_dict[lName]

    logging.info("Connecting to the Device")
    ssh = Ssh(uName,password,hostIp)
    session = ssh.connect()

    main(uName,password,hostIp)

    print("Following are the available options to parse the elam")
    print("node -> node details")
    print("ii -> Incoming Interface")
    print("head -> Headers")
    print("pctag -> Class Lookup")
    print("src -> Source Lookup")
    print("dst -> Destination Lookup")
    print("con -> Contract Lookup")
    print("res -> Result section, includes Outgoing interface, Multicast Lookup")
    print("sup -> Sup Hit")
    print("all -> Runs entire lookup")
    print("exit -> exit the parsing")
    lst=['node','ii','head','pctag','src','dst','con','res','sup','all','exit']
    readline.set_completer(complete)
    inp = raw_input("Please provide the option to parse(please enter values with comma seperated to parse with more than 1 option):").lower() 
    if inp=="exit":
        sys.exit(0)
    print("ELAM FILE : "+fileName)
    inp=inp.split(',')
    with open("/data/techsupport/" + fileName) as file:
        data = file.readlines()

    er = Ereport(data)
    intf = Interface(data)
    dl  = DstL2L3Lookup(data)
    sl = SrcL2L3Lookup(data)
    header = L2L3Header(data)
    c = Contract(data)
    p = Pctag(data)
    m = Multicast(data)

    if "node" in inp or "all" in inp:
        print("----------------------------------------------------------------")
        print("Node Details:")
        print("----------------------------------------------------------------")
        try:
            nodeName = intf.nodeName()
        except ValueError as ex:
            print(ex)
        else:
            print(nodeName)

    if "ii" in inp or "all" in inp:
        try:
            if (intf.checkPacketFromCpu()) == False:
                try:
                    incIntf = intf.IncInt()
                except ValueError as ex:
                    print(ex)
                else:
                    print("\n")
                    print("----------------------------------------------------------------")
                    print("Incoming Interface: " + incIntf)
                    print("----------------------------------------------------------------")
                    try:
                        val = (intf.checkIfFabricPort())
                    except ValueError as ex:
                        print(ex)
                    else:
                        if val == "0":
                            print("Packet arrived from Front Pannel port")
                            print("\n")
                        elif val == "1":
                            print("Packet arrived from Fabric port")
                            print("\n")
            else:
                print('Incoming Interface: CPU')
                print("\n")
        except ValueError as ex:
            print(ex)
            print("\n")
    if "head" in inp or "all" in inp:
        if header.checkEncapsulation() == True:
            print("Packet is encapsulated")
            if header.checkIfArp()==True:
                try:
                    header.getOuterHeader()
                except ValueError as ex:
                    print(ex)
                try:
                    header.getInnerArpHeader()
                except ValueError as ex:
                    print(ex)
            else:
                try:
                    header.getOuterHeader()
                except ValueError as ex:
                    print(ex)
                try:
                    header.getInnerHeader()
                except ValueError as ex:
                    print(ex)

        else:
            print("Packet is NOT encapsulated.")
            if header.checkIfArp() == True:
                try:
                    header.getOuterArpHeader()
                except ValueError as ex:
                    print(ex)
            else:
                try:
                    header.getOuterHeader()
                except ValueError as ex:
                    print(ex)


    if "pctag" in inp or "all" in inp:
        print("----------------------------------------------------------------")
        print("                     Printing PCTAG Lookup                      ")
        print("----------------------------------------------------------------")
        print("\n")


        try:
            sclass = p.getSclass()
        except ValueError as ex:
            print(ex)
        try:
            dclass = p.getDclass()
        except ValueError as ex:
            print(ex)


        #if Vnid is not present check access vlan and do the lookup
        #if Vnid is present check if ths vrf vnid or BD vnid and then do the lookup
        # Sclass lookup
        print("PCTAG Lookup for Sclass: "+ sclass)
        try:
            vnid = p.getVnid()
        except ValueError as ex:
            try:
                accessVlan = er.getAccessVlan()
            except ValueError as ex:
                print(ex)
            else:
                if int(sclass) <= 15:
                    print("Reserved pcTag: {} used. Cannot perform Source PCTAG Lookup").format(sclass)
                else:
                    try:
                        vlancktep = p.getVlanCktEp(accessVlan,sclass)
                    except ValueError as ex:
                        print(ex,"checking using VRF Scope and PcTag")
                        # get source VRF, get scope from it, do lookup using pctag and scope
                        try:
                            srcVrf = sl.srcIpVrfLookup()
                        except ValueError as ex:
                            print(ex)
                        else:
                            try:
                                dn = ("uni/tn-{}/ctx-{}").format(src_vrf.split(":")[0],src_vrf.split(":")[1])
                            except Exception:
                                print("Could not create dn since VRF lookup was not done")
                            else:
                                try:
                                    vrfScope = p.getVrfScope(dn)
                                except ValueError as ex:
                                    print(ex)
                                else:
                                    try:
                                        lookup = (p.getClasslookup(sclass,vrfScope))
                                    except ValueError as ex:
                                        print(ex)
                                    else:
                                        #print("PCTAG Lookup for Sclass: "+ sclass)
                                        if not lookup:
                                            pass
                                        else:
                                            for items in lookup:
                                                print(items)

                    else:
                        dn_pattern = u'\[vxlan-.*?]'
                        dn = re.findall(dn_pattern, vlancktep)
                        try:
                            vrf_scope = dn[0][7:-1]
                            src_bd = dn[1][7:-1]
                            vlancktep = vlancktep.splitlines()
                            src_epg = vlancktep[1].split(':')[-1].strip()
                            src_app = vlancktep[1].split(':')[-2].strip()
                            src_tn = vlancktep[1].split(':')[-3].strip()
                            #print("PCTAG lookup for Sclass: " + sclass)
                            print("Tenant: " + src_tn)
                            print("App: " + src_app)
                            print("EPG: " + src_epg)
                            #print("\n")
                        except IndexError:
                            print("Could not get individual elements for DN:{}".format(dn))

        # If try p.getVnid() doesnt fail, use Vnid for the sclass lookup            
        else:
            try:
                vnid_dict = p.checkWhichVnid(vnid)
            except ValueError as ex:
                print(ex)
            else:
                if "epg_vnid" in vnid_dict:
                    print("Check Vlancktep to find Vlan belonging to same encap")
                else:
                    vrf_vnid = (vnid_dict["vrf_vnid"])
                    if int(sclass) <= 15:
                        print("Reserved pcTag: {} used. Cannot perform Lookup").format(sclass)
                    else:
                        try:
                            lookup = (p.getClasslookup(sclass,vrf_vnid))
                        except ValueError as ex:
                            print(ex)
                        else:

                            if not lookup:
                                pass
                            else:
                                for items in lookup:
                                    print(items)

        # Dclass Lookup
        print("\n")
        print("PCTAG Lookup for Dclass: "+ dclass)
        if int(dclass) <= 15:
            print("Reserved pcTag: {} used. Cannot perform Destination PCTAG Lookup").format(dclass)
        else:
            try:
                #dstVrf = dl.dstIpVrfLookup()
                srcVrf = sl.srcIpVrfLookup()
            except ValueError as ex:
                print(ex)
            else:
                try:
                    dn = ("uni/tn-{}/ctx-{}").format(srcVrf.split(":")[0],srcVrf.split(":")[1])
                except IndexError:
                    print("Since VRF lookup was not done Could not create DN using VRF")
                else:
                    try:
                        vrfScope = p.getVrfScope(dn)
                    except ValueError as ex:
                        print(ex)
                    else:
                        try:
                            lookup = (p.getClasslookup(dclass,vrfScope))
                        except ValueError as ex:
                            print(ex)
                        else:

                            if not lookup:
                                pass
                            else:
                                for items in lookup:
                                    print(items)
    if "dst" in inp or "all" in inp:
        print("\n")
        print("----------------------------------------------------------------")
        print("                  Printing Destination Lookup                   ")
        print("----------------------------------------------------------------")
        print("\n")

        try:
            dstVrf = (dl.dstIpVrfLookup())
        except ValueError as ex:
            print(ex)
        else:
            print('Destination VRF: ' + dstVrf)

        try:
            if dl.checkDstMacLookup() == False:
                print("Dst mac lookup not done")
            else:
                if dl.dstMacBdLookup() == "NA":
                    print("BD lookup NA")
                else:
                    print(dl.dstMacBdLookup())
        except ValueError as ex:
            print(ex)

        try:
            (dl.dstIpHit())
        except ValueError as ex:
            print(ex)
    
    if "src" in inp or "all" in inp:
        print("\n")
        print("----------------------------------------------------------------")
        print("                    Printing Source Lookup                      ")
        print("----------------------------------------------------------------")
        print("\n")

        try:
            srcVrf = (sl.srcIpVrfLookup())
        except ValueError as ex:
            print(ex)
        else:
            print('Source VRF: ' + srcVrf)

        try:
            if sl.checkSrcMacLookup() == False:
                print("Src mac lookup not done")
            else:
                if sl.srcMacBdLookup() == "NA":
                    print("BD lookup NA")
                else:
                    print(sl.srcMacBdLookup())
        except ValueError as ex:
            print(ex)

        try:
            (sl.srcIpHit())
        except ValueError as ex:
            print(ex)
    
    if "con" in inp or "all" in inp:
        print("\n")
        print("----------------------------------------------------------------")
        print("               Printing Contract Lookup Section                 ")
        print("----------------------------------------------------------------")
        print("\n")


        if not c.checkContractHit() == False:
            try:
                ruleId = c.ruleId()
            except ValueError as ex:
                print(ex)
            else:
                try:
                    zr = c.zoningRule(ruleId)
                except ValueError as ex:
                    print(ex)
                else:
                    print('Contract HIT:')
                    print('-------------------------------------------------------------------------------------------------------------------------------------------------')
                    print(zr)
                    print('-------------------------------------------------------------------------------------------------------------------------------------------------')
                    try:
                        filterout = c.getFilter(zr)
                    except ValueError as ex:
                        print(ex)
                    else:
                        print("\n")
                        print("Filter HIT:")
                        print(filterout)
        else:
            print("Contract is not applied!")
            print("\n")
            print("#HINT 1: In shared Services, Contract is applied on Consumer Leaf. Please Validate!")
            print("#HINT 2: In case of traffic from an L3out, Contract is applied on Compute Leaf NOT on Boder Leaf. Please Validate!")
    if "sup" in inp or "all" in inp:
        print("\n")
        print("----------------------------------------------------------------")
        print("                  Printing SUP TCAM Section                     ")
        print("----------------------------------------------------------------")
        print("\n")

        try:
            supHit = (intf.SupTcamHit())
        except ValueError as ex:
            print(ex)
        else:
            print("Sup HIT for stats index: "+ intf.stats_index)
            print("\n")
            print(supHit)
    if "res" in inp or "all" in inp:
        try:
            if m.checkDstFloodPtr() == False:
                try:
                    print("\n")
                    print("----------------------------------------------------------------")
                    print("                   Printing Result Section                      ")
                    print("----------------------------------------------------------------")
                    outIntf = intf.ovector()
                except ValueError as ex:
                    print(ex)
                else:
                    print("Outgoing Interface: " + str(outIntf))
                    print("\n")

            else:
                print("\n")
                print("Destination is a flood index")
                print("----------------------------------------------------------------")
                print("           Printing Flood/Multicast Lookup Section              ")
                print("----------------------------------------------------------------")
                print("\n")
                try:
                    ftag = m.getFtag()
                except ValueError as ex:
                    print(ex)
                else:
                    print("FTAG: " + ftag)
                    # need to be in try block ------------------88888888888------------------
                    (sl.srcMacBdLookup())
                    try:
                        srcBd = sl.srcMacBdLookupOut
                    except ValueError as ex:
                        print(ex)
                    else:
                        try:
                            gipoFromBd = m.getGipoFromBdFloodList(bd=srcBd)
                        except ValueError as ex:
                            print(ex)
                        else:
                            #print("GPIO: "+ gipoFromBd)
                            try:
                                isisMcastRoute = m.getIsisMcastRoute(gipo=gipoFromBd)
                            except ValueError as ex:
                                print(ex)
                            else:
                                print("\n")
                                print("ISIS Multicast Route info:")
                                print(isisMcastRoute)
                                try:
                                    isisFtagRoute = m.getIsisFtagRoute(ftag=ftag)
                                except ValueError as ex:
                                    print(ex)
                                else:
                                    print("\n")
                                    print("ISIS Ftag Route Info:")
                                    print(isisFtagRoute)

                                    try:
                                        intf_in_gipo = []
                                        isis_mcast_route_split = isisMcastRoute.splitlines()
                                        for item in isis_mcast_route_split:
                                            if "Ethernet" in item:
                                                intf_in_gipo.append(item.strip())
                                    except IndexError:
                                        print("Error finding interface in isisMcastRoute")

                                    else:
                                        try:
                                            intf_in_ftag = []
                                            isis_ftag_route_split = isisFtagRoute.splitlines()
                                            for item in isis_ftag_route_split:
                                                if "Root port: Ethernet" in item:
                                                    print(item)
                                                    intf_in_ftag.append(item.split(":")[1].strip())
                                        except IndexError:
                                            print("Error finding interface in isisFtagRoute")

                                        else:
                                            try:
                                                common_egress_intf = (set(intf_in_gipo)&set(intf_in_ftag))
                                                for intf in common_egress_intf:
                                                    print("\n")
                                                    print("Expected fabric interface in Software: " + str(intf))
                                            except Exception:
                                                print("Could not find Common interface in isisMcastRoute and isisFtagRoute")

                            #get GPIO from BD in the try block, if it fails below code will not run
                            print("\n")
                            print("----------------------------------------------------------------")
                            print("     Printing Flood/Multicast Hardware Verification Section     ")
                            print("----------------------------------------------------------------")
                            print("\n")
                            fabInt = []

                            try:
                                print("Gettting mcast_repl_list_handle for gipo: " + gipoFromBd)
                                mcastReplListHandleId = m.getMcastReplListHandle(gipoFromBd)
                            except TypeError:
                                print("Cannot get GIPO from BD, since BD lookup was not done")
                            except ValueError as ex:
                                print(ex)
                            else:
                                print("Getting mcast_repl_list for handle: " + mcastReplListHandleId)
                                try:
                                    mcastReplLstObj =  m.getMcastReplLstObj(mcastReplListHandleId)
                                except ValueError as ex:
                                    print(ex)
                                else:
                                    try:
                                        mcIdLst = m.getMcIdLst(mcastReplLstObj)
                                    except Exception:
                                        print("Could not get MC ids from mcastReplLstObj")
                                    else:
                                        if not len(mcIdLst) < 1:
                                            for mcId in mcIdLst:
                                                print("Getting mcast_port_fanout for MC ID: " + mcId)
                                                try:
                                                    mcastPortFanout = m.getMcastPortFanout(mcId)
                                                except ValueError as ex:
                                                    print(ex)
                                                else:
                                                    #print(mcastPortFanout)
                                                    argsList = []
                                                    mcastPortFanoutLst = mcastPortFanout.splitlines()
                                                    try:
                                                        argsList = m.getMcastIfmapArgs(mcastPortFanoutLst)
                                                    except Exception:
                                                        print("Issues getting Slice/Asic/IfIds from mcastPortFanout")
                                                    else:
                                                        intf = []
                                                        for item in argsList:
                                                            print("Getting Interface from ifmap-to-ifname table for value: " +  str(item))
                                                            print("\n")

                                                        try:
                                                            intf = m.getIfmapToIfname(argsList)
                                                        except Exception:
                                                            print("Could not get ifname for ifmap")
                                                        else:
                                                            for interface in intf:
                                                                fabInt.append(interface)

                                        else:
                                            print("Could not get MC ids from mcastReplLstObj")

                                    print("----------------------------------------------------------------")
                                    print("Fabric Interfaces programmed in Hardware are: ")
                                    print("----------------------------------------------------------------")
                                    print("\n")
                                    for item in fabInt:
                                        print item,

                                    print("\n")

                print("----------------------------------------------------------------")
                print("\n")
                try:
                    met_ptr = m.getMetPtr()
                except ValueError as ex:
                    print(ex)
                else:
                    print("MET POINTER: " + met_ptr + ". Finding local egress interfaces!")
                    try:
                        chip = er.getAsicType()
                    except ValueError as ex:
                        print(ex)
                    else:
                        print("Asic type is: " + chip)
                        try:
                            table_alias = m.get_asic_table_alias(chip=chip)
                        except Exception:
                            print("Issue finding table alias for chip: " + chip)
                        else:
                            try:
                                ovidx_list = m.get_ovindx_list(met_ptr)
                            except Exception:
                                print("Could not get OvidxLst for Met Pointer: " + met_ptr)
                            else:
                                try:
                                    for ovidx in ovidx_list:
                                        try:
                                            ifmap_list = m.get_ifmap_list_from_qsmt_ovtbl(ovidx)
                                        except Exception:
                                            print("Could not get Ifmap from qsmt ovtable for ovidx: "+ovidx)
                                        else:
                                            try:
                                                for ifmap in ifmap_list:
                                                    try:
                                                        ifmap_args_list=m.get_ifmap_args_list_from_ifmap_list(ifmap)
                                                    except Exception:
                                                        print("Could not find ifmap args from ifmap list")
                                                    else:
                                                        print("ifmap from qsmt_ovtbl is: " + str(ifmap))
                                                        intf = []
                                                        print("Getting interface from ifmap_to_ifname table")
                                                        try:
                                                            intf =  m.getIfmapToIfname(ifmap_args_list)
                                                        except Exception:
                                                            print("Could not find interface ifmap using args: " + ifmap_args_list)
                                                        else:
                                                            print("\n")
                                                            print("-------------------------------------------------------------------------")
                                                            print("Egress Flood interfaces: ")
                                                            print("-------------------------------------------------------------------------")
                                                            if not len(intf) < 0:
                                                                for interface in intf:
                                                                    #print(get_ifmap_to_ifname.ifmap_to_ifname_cmd)
                                                                    print interface,
                                                                print("\n")
                                                            else:
                                                                print("Cannot get interface from Ifmap to Ifname table")
                                            except TypeError:
                                                print("Cannot get Ifmap using QSMT Ovtable")
                                except TypeError:
                                    print("Could not get Ovidx from MetPtr")


        except ValueError as ex:
            print(ex)                                       

