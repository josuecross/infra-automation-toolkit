#!/usr/intel/bin/python3.7.4

#
# Owner: Jeff Paquette
#
# Redfish management utility
# 
# Description:
#      Queires remote management consoles of servers or chassis CMMs to collect a range
#      of values and information available via the standard redfish API including network
#      information, power, system status, serial numbers and much more.
#
#      The utility can also perform actions such as power on/off/cycle/reboot or set the
#      system to perform a one-time boot method such as PXE
#
#      see redfish_mgmt.py -h for available options

import UsrIntel.R1
import requests
import subprocess
import argparse
import json
import psutil
import os
import sys 
from getpass import getpass, getuser
from RedfishCmds import RedfishCmds
from RedfishParse import RedfishParse
from RemoteSession import RemoteSession
from multiprocessing import Process, current_process
from concurrent.futures import ThreadPoolExecutor
from argparse import RawTextHelpFormatter
import configparser

requests.packages.urllib3.disable_warnings() 

QUERY_NODES = "/usr/intel/bin/query_nodes"
MAX_JOBS = 50
SCRIPT_LOCATION = os.path.dirname(os.path.realpath(__file__))
SHORTCUTS_FILE = SCRIPT_LOCATION + '/shortcuts.conf'

def parse_args():
    '''
    Parse input options
    '''
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument('-u', '--username', metavar='<username>')
    parser.add_argument('-p', '--password', metavar='<password>')

    parser.add_argument('-s', '--show', action='append',nargs='*', help="\nShow system information:\n\n               |  hash  | |        hash[key1]        | |     hash[key1][key2]     |\n               |        | |                          | |                          |\nsyntax: --show <endpoint> \"<key1.1>|<key1.2>|<key1.3>\" \"<key2.1>|<key2.2>|<key2.3>\" ...\n\nex: --show /redfish/v1/Systems/1 \"SerialNumber|ProcessorSummary|Status\" \"Health|Count\"\n\nOutput:\n\n> Hostname = ienvscv630020\n> SerialNumber: MXQ9050203\n> ProcessorSummary::\n>     Count: 1\n> Status::\n>     Health: OK\n\nOr use shortcuts set in shortcuts.conf:\nsyntax: --show \"<shortcut>\"\n\nKnown shortcuts:\n" + shortcuts_string + "\n\n")        
    parser.add_argument('-w', '--where', action='append',nargs=1, help="Where a key/value pair matches a block in a group of blocks with the same key names.\nTo be used after a --show argument.\n\nsyntax: --where \"<field><operator>'<value>'\"\n\nOperators can be the following:\n   ==     : equal to\n   !=     : not equal to\n   =~     : like\n\nex: --show /redfish/v1/TaskService/Tasks \"Members\" --where \"Name=='<value>'\"\"\n\nMultiple fields can be matched by combining them with '&&' or '||'\n\nex: --where \"Name=='<value>'||Description=='<value>'\"\n\n")        
    parser.add_argument('-x', '--script', action='store_true', help='Print the output fields on one line for each host')
    parser.add_argument('-c', '--console', action='store_true', help='Open the remote console in firefox')
    parser.add_argument('-B', '--update_bios', metavar='<bios_file_url>', nargs=1, help='Update the BIOS')

    #For testing maintenance window creation
    parser.add_argument('--patch', action='append', nargs='*', help='Patch an endpoint')
    parser.add_argument('-z', '--maint_window', action='append', nargs='*', help='Create maintenance window')
    parser.add_argument('-y', '--maint_window_delete', action='append', nargs='*', help='Delete maintenance window')

    # Required option - either hostname or file needs to be used
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument('-n', '--hostname', metavar="", help='<hostname>')
    group1.add_argument('-f', '--hostfile', metavar="", help='File of hostnames')
    group1.add_argument('-m', '--mgmt', metavar="", help='Mgmt IP or name')
    group1.add_argument('-mf', '--mgmtfile', metavar="", help='File of mgmt IPs or names')

    # Power actions - only 1 can be used
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument('-poff', '--power_off', action='store_true', help='Power off host')
    group2.add_argument('-pon', '--power_on', action='store_true', help='Power on host')
    #group2.add_argument('--set_onetime_boot', action='append',nargs=1, help='Set one-time boot override. Allowable values: ("None","Pxe","Hdd","Cd","BiosSetup","Usb","Floppy")')
    group2.add_argument('--set_onetime_boot', nargs=2, metavar="", help='Set one-time boot override \nAllowable values: (\"None\",\"Pxe\",\"Hdd\",\"Cd\",\"BiosSetup\",\"Usb\",\"Floppy\") \nMust include a second argument for either \"Legacy\" or \"UEFI\" \n        example: --set_onetime_boot \"Pxe\" \"UEFI\"')
    group2.add_argument('--set_boot_source', metavar="", help='Set boot source override. Allowable values: ("Legacy","UEFI")')
    group2.add_argument('--reboot', action='store_true', help='Reboot host')
    group2.add_argument('--restart', action='store_true', help='Restart host')
    group2.add_argument('--reset_bmc', action='store_true', help='Reboot BMC')
    group2.add_argument('--accycle_blade', nargs=1, metavar="", help="AC cycle node in chassis") 
    group2.add_argument('--power_off_blade', nargs=1, metavar="", help="Power off node in chassis") 
    group2.add_argument('--power_on_blade', nargs=1, metavar="", help="Power on node in chassis") 
    group2.add_argument('--set_mgmt_dhcp', nargs=1, metavar="", help="Change CMM node LanMode to DHCP") 

    args = parser.parse_args()

    # If user and/or password was not given then prompt for input
    if args.username is None:
        args.username = getuser()
    if args.password is None:
        args.password = getpass()

    return args

def main():
    args = parse_args()
  
    #    make_choice()

    if args.hostfile or args.mgmtfile:
        if args.accycle_blade is not None:
            print("Cannot AC cycle blades from hostfile (yet)...")
            exit()
        if args.hostfile:
            hostfile = args.hostfile
        if args.mgmtfile:
            hostfile = args.mgmtfile
        hosts = open(hostfile, "r")
        with ThreadPoolExecutor(max_workers=MAX_JOBS) as executor:
            for i in hosts:
                hostname = i.replace('\n','')
                processJob = executor.submit(query_redfish,hostname)
        hosts.close()
    else:
        if args.hostname:
            query_redfish(args.hostname)
        if args.mgmt:
            query_redfish(args.mgmt)

def make_choice():
        yes = {'yes'}
        no = {'no','n',''}

        print("")
        print("WARNING: Your about to perform a power command the host(s)")
        print("Are you sure you want to continue?")

        choice = input().lower()
        if choice in no:
            print("Exiting....")
            exit()
        if choice in yes:
            print("continuing...")
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'")
            make_choice()

def get_machine_nodes_info(hostname):
    get_nodes_info = QUERY_NODES + " --fields model,mgmt,mode,nbpool --filter hostname=" + hostname
    nodes_exe = subprocess.Popen([get_nodes_info, '-i'], shell=True, stdout=subprocess.PIPE).communicate()[0]
    nodes_info = nodes_exe.decode().split('\n')[1]

    mgmt_ip   = nodes_info.split(' ')[1]

    return(mgmt_ip)

def get_shortcuts():
    shortcuts_list = []
    confparser = configparser.RawConfigParser()
    confparser.optionxform = str
    confparser.read(SHORTCUTS_FILE)
    for k,v in confparser.items("Shortcuts"):
        tmp = {} 
        tmp[k] = v
        shortcuts_list.append(tmp)

    shortcuts = ""
    for i in shortcuts_list:
        for k,v in i.items():
            shortcuts = shortcuts + '"' + k + '"\n'

    return(shortcuts_list, shortcuts)

def query_redfish(hostname):
    args = parse_args()

    if args.script is False:
        print("Hostname = " + hostname)

    if args.hostname or args.hostfile:
        mgmt_ip = get_machine_nodes_info(hostname)
    else:
        mgmt_ip = hostname

    blade = RedfishCmds(hostname, mgmt_ip, args.username, args.password, debug=True)

    my_process = psutil.Process( os.getpid() )
    cmdline_args_order = []
    for p in my_process.cmdline():
        if p == '-s' or p == '-w' or p == '--show' or p == '--where':
            cmdline_args_order.append(p)

    if args.show is not None:

        if args.show[0]:
            final_output = []
            count = 0
            
            if args.where:
                args_where = args.where
            else:
                args_where = []
            if args.script is not False:
                args_script = "True"
            else:
                args_script = "False"

            for a in args.show:
                args_group = a
                for s in shortcuts_list:
                    for k,v in s.items():
                        if k.lower() == a[0].lower():
                            args_group = s[k].replace('"','').split(' ')

                tmp = []
                sys_dict,status_code = blade.get_system_info_by_endpoint(hostname,args_group[0])
                if status_code == 200:
                    if isinstance(sys_dict, dict):
                        tmp = RedfishParse.parse_hash(args_group,sys_dict)
                    elif isinstance(sys_dict, list):
                        print(sys_dict)
                    else:
                        print(str(sys_dict))
                elif status_code == 500:
                    print("Endpoint couldnt be retreived - Error: " + str(status_code))
                elif status_code != 401:
                    print("Error: " + str(status_code))
                #elif status_code == 401:
                #    print("Connection refused - Error: " + str(status_code))


                if tmp:
                    section_output = RedfishParse.output_selection(tmp, args_script, args_where, count, cmdline_args_order)
                    for s in section_output:
                        final_output.append(s)
                count += 1

            if final_output:
                if args.script is not False:
                    out = hostname + " " + " ".join(final_output)
                    print(out)
                else:
                    for o in final_output:
                        print(o)  
    
        else: 
            result,status_code = blade.get_system_info_by_endpoint(hostname,'/redfish/v1')
            if status_code == 200:
                if isinstance(result, dict):
                    print(json.dumps(result, indent=4))
                elif isinstance(result, list):
                    print(result)
            elif status_code == 500:
                print("Endpoint couldnt be retreived - Error: " + str(status_code))
            elif status_code != 401:
                print("Error: " + str(status_code))


    if args.console is not False:
        print(blade.get_console_uri(hostname))

    if args.power_off is not False:
        blade.power(hostname,"ForceOff")
    elif args.power_on is not False:
        blade.power(hostname,"ForceOn")
    elif args.reboot is not False:
        print("Rebooting")
        blade.power(hostname,"ForceRestart")
    elif args.restart is not False:
        print("Restarting")
        blade.power(hostname,"GracefulRestart")
    elif args.reset_bmc is not False:
        print("Resetting BMC")
        blade.bmc_cold_reset(hostname)
    elif args.set_onetime_boot is not None:
        boot_source = str(args.set_onetime_boot[0])
        boot_mode = str(args.set_onetime_boot[1])
        blade.set_one_time_boot_mode(hostname,boot_source,boot_mode)
    elif args.set_boot_source is not None:
        boot_source = str(args.set_boot_source)
        blade.set_boot_source(hostname,boot_source)
    elif args.accycle_blade is not None:
        node_number = str(args.accycle_blade[0])
        print("Node " + str(node_number) + " AC cycled")
        blade.accycle_node_number(hostname, node_number)
    elif args.power_off_blade is not None:
        node_number = str(args.power_off_blade[0])
        print("Node " + str(node_number) + " Powered off")
        blade.power_off_blade_by_cmm(hostname, node_number)
    elif args.power_on_blade is not None:
        node_number = str(args.power_on_blade[0])
        print("Node " + str(node_number) + " Powered on")
        blade.power_on_blade_by_cmm(hostname, node_number)
    elif args.update_bios is not None:
        fw_update_file = args.update_bios[0]
        blade.simple_system_bios_update(hostname, fw_update_file)
    elif args.maint_window is not None:
        blade.maintenance_window(hostname)
    elif args.maint_window_delete is not None:
        blade.maintenance_window_delete(hostname)
    elif args.set_mgmt_dhcp is not None:
        node_number = str(args.set_mgmt_dhcp[0])
        blade.change_mgmt_network(hostname, node_number)

shortcuts_list, shortcuts_string = get_shortcuts()
main()
