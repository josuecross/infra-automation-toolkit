import UsrIntel.R1
import requests
import subprocess
import json
from RemoteSession import RemoteSession


# TODO add in 401 if session expired
class RedfishCmds:
    def __init__(self, host, mgmt, user, pw, debug):
        self.host = host
        self.mgmt = mgmt
        self.user = user
        self.pw = pw
        self.debug = debug
        self.rmt_session = RemoteSession(self.host, self.mgmt, self.user, self.pw, endpoints["create_session"], self.debug)      # Create a remote session


    def power(self,hostname,resettype):
        try:
            url = f'{self.rmt_session.base_url}{endpoints["power"]}'
            header = {'content-type': 'application/json'}
            payload = json.dumps({"ResetType":resettype})         # ForceOff, ForceOn, ForceRestart, GracefulRestart
            response = self.rmt_session.session.post(url, headers=header, data=payload, timeout=5, verify=False)
            status = response.status_code                         # TODO - use status code
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))


    def bmc_cold_reset(self,hostname):
        try:
            url = f'{self.rmt_session.base_url}{endpoints["bmc_cold_reset"]}'
            header = {'content-type': 'application/json'}
            payload = json.dumps({"ResetType":"ForceRestart"})
            response = self.rmt_session.session.post(url, headers=header, data=payload, timeout=5, verify=False)
            status = response.status_code                         # TODO - use status code
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))

    def accycle_node_number(self,hostname,nodenumber):
        try:
            url = f'{self.rmt_session.base_url}/Chassis/1/Blade/{nodenumber}/Node/1/Status'
            payload = json.dumps({"PowerControl":"ACCycle"})
            response = self.rmt_session.session.patch(url, data=payload, timeout=5, verify=False)
            status = response.status_code                         # TODO - use status code
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))

    def change_mgmt_network(self,hostname,nodenumber):
        try:
            url = f'{self.rmt_session.base_url}/Chassis/1/Blade/{nodenumber}/Node/1/Network'
            payload = json.dumps({"IPv4Addresses": [{"LanMode":"DHCP"}]})
            #payload = json.dumps([{"IPv4Addresses": [{"LanMode":"DHCP"}]])
            response = self.rmt_session.session.patch(url, data=payload, timeout=5, verify=False)
            status = response.status_code                         # TODO - use status code
            #print(str(status))
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))

    def power_off_blade_by_cmm(self,hostname,nodenumber):
        try:
            url = f'{self.rmt_session.base_url}/Chassis/1/Blade/{nodenumber}/Node/1/Status'
            payload = json.dumps({"PowerControl":"PowerOff"})
            response = self.rmt_session.session.patch(url, data=payload, timeout=5, verify=False)
            status = response.status_code                         # TODO - use status code
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))

    def power_on_blade_by_cmm(self,hostname,nodenumber):
        try:
            url = f'{self.rmt_session.base_url}/Chassis/1/Blade/{nodenumber}/Node/1/Status'
            payload = json.dumps({"PowerControl":"PowerOn"})
            response = self.rmt_session.session.patch(url, data=payload, timeout=5, verify=False)
            status = response.status_code                         # TODO - use status code
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))

    def set_one_time_boot_mode(self,hostname,boot_source,boot_mode):
        try:
            url = f'{self.rmt_session.base_url}/Systems/1'
            header = {'content-type': 'application/json'}
            payload = json.dumps({"Boot":{
                                        "BootSourceOverrideEnabled":"Once",
                                        #"BootSourceOverrideMode":"Dual",
                                        #"BootSourceOverrideMode":"Legacy",
                                        "BootSourceOverrideMode":boot_mode,
                                        "BootSourceOverrideTarget":boot_source
                                        }
                                    })
            response = self.rmt_session.session.patch(url, headers=header, data=payload, timeout=5, verify=False)
            status = response.status_code                         # TODO - use status code
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))

    def set_boot_source(self,hostname,boot_source):
        try:
            url = f'{self.rmt_session.base_url}/Systems/1'
            header = {'content-type': 'application/json'}
            payload = json.dumps({"Boot":{
                                        "BootSourceOverrideEnabled":"Continuous",
                                        "BootSourceOverrideMode":boot_source,
                                        "BootSourceOverrideTarget":"Hdd"
                                        }
                                    })
            response = self.rmt_session.session.patch(url, headers=header, data=payload, timeout=5, verify=False)
            self.rmt_session.close_session()
            status = response.status_code                         # TODO - use status code
        except Exception as err:
            print(hostname + ": " + str(err))

# TODO - parse response
    def get_system_info(self,hostname,endpoint):
        try:
            url = f'{self.rmt_session.base_url}{endpoints[endpoint]}'
            response = self.rmt_session.session.get(url, timeout=5, verify=False)
            response_json = json.loads(response.text)
            status = response.status_code 
            self.rmt_session.close_session()
            return response_json
        except Exception as err:
            print(hostname + ": " + str(err))


    def get_system_info_by_endpoint(self,hostname,endpoint):
        try:
            endpoint = endpoint.replace('/redfish/v1','')
            url = f'{self.rmt_session.base_url}{endpoint}'
            response = self.rmt_session.session.get(url, timeout=5, verify=False)
            response_json = json.loads(response.text)
            status = response.status_code
            self.rmt_session.close_session()
            return(response_json,status)
        except Exception as err:
            return(err,500)


    def get_console_uri(self,hostname):
        try:
             url = f'{self.rmt_session.base_url}{endpoints["console"]}'
             response = self.rmt_session.session.get(url, timeout=5, verify=False)
             status = response.status_code
             self.rmt_session.close_session()
             if status == 200:                          #TODO need else statement
                return response.URI
                
        except Exception as err:
            print(hostname + ": " + str(err))


# TODO - not working
    def system_bios_update(self,hostname):
        try:
            url = f'{self.rmt_session.base_url}{endpoints["bios_update_mode"]}'
            header = {'content-type': 'application/json'}
            set_mode_response = self.rmt_session.session.post(url, headers=header, timeout=5, verify=False)
            set_mode_status = set_mode_response.status_code

            if set_mode_status == 200:
                url = f'{self.rmt_session.base_url}{endpoints["bios_upload_fw"]}'
                header = {'content-type': 'multipart/form-data'}
                upload_fw_response = self.rmt_session.session.post(url, headers=header, timeout=5, verify=False)        # TODO need to add bios file
                upload_fw_status = upload_fw_response.status_code

                if upload_fw_status == 200:
                    url = f'{self.rmt_session.base_url}{endpoints["bios_start_update"]}'
                    payload = json.dumps({"PreserveME":"true", "PreserveNVRAM":"true", "PreserveSMBIOS":"true"})
                    start_update_response = self.rmt_session.session.post(url, headers=header, data=payload, timeout=5, verify=False)
                    start_update_status = start_update_response.status_code
            self.rmt_session.close_session()

        except Exception as err:
            print(hostname + ": " + str(err))

    def simple_system_bios_update(self,hostname,fw_update_file):
            #payload example:   {"ImageURI": "http://10.90.122.195/ProLiant-DL360-Gen10/BIOS_Version/2020.03.09/U32_2.32_03_09_2020.signed.flash"}
        try:  
            url = f'{self.rmt_session.base_url}{endpoints["simple_bios_update"]}'
            header = {'content-type': 'application/json'}
            payload = json.dumps({"ImageURI": fw_update_file})
            set_mode_response = self.rmt_session.session.post(url, headers=header, data=payload, timeout=120, verify=False)
            set_mode_status = set_mode_response.status_code
            #print(set_mode_response.content)
            #print(set_mode_status)
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))

    def maintenance_window(self,hostname):
        try:
            url = f'{self.rmt_session.base_url}{endpoints["maintenance_window"]}'
            header = {'content-type': 'application/json'}
            payload = json.dumps({
                "Description": "Test maintenance window",
                "Name" : "Test maintenance window name",
                "StartAfter": "2022-08-03T00:00:00Z",
                "Expire": "2022-08-03T01:00:00Z"
            })
            response = self.rmt_session.session.post(url, headers=header, data=payload, timeout=5, verify=False)
            status = response.status_code
            content = response.content
            print(str(content))
            print(str(status))
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))

    def maintenance_window_delete(self,hostname):
        try:
            url = f'{self.rmt_session.base_url}{endpoints["maintenance_window_delete"]}'
            response = self.rmt_session.session.post(url, timeout=5, verify=False)
            status = response.status_code
            content = response.content
            print(str(content))
            print(str(status))
            self.rmt_session.close_session()
        except Exception as err:
            print(hostname + ": " + str(err))


endpoints = {
    'create_session'        : '/SessionService/Sessions/',
    'create_user'           : '/AccountService/Accounts/',
    'bmc_update_mode'       : '/UpdateService/SmcFirmwareInventory/BMC/Actions/SmcFirmwareInventory.EnterUpdateMode',
    'bmc_upload_fw'         : '/UpdateService/SmcFirmwareInventory/BMC/Actions/SmcFirmwareInventory.Upload',
    'bmc_cold_reset'        : '/Managers/1/Actions/Manager.Reset',
    'bmc_start_update'      : '/UpdateService/SmcFirmwareInventory/BMC/Actions/SmcFirmwareInventory.Update',                      # payload: {"PreserveCfg":"true", "PreserveSdr":"true", "PreserveSsl":"true"}
    'bios_update_mode'      : '/UpdateService/SmcFirmwareInventory/BIOS/Actions/SmcFirmwareInventory.EnterUpdateMode',
    'bios_upload_fw'        : '/UpdateService/SmcFirmwareInventory/BIOS/Actions/SmcFirmwareInventory.Upload',
    'bios_start_update'     : '/UpdateService/SmcFirmwareInventory/BIOS/Actions/SmcFirmwareInventory.Update',                     # payload: {"PreserveME":"true", "PreserveNVRAM":"true", "PreserveSMBIOS":"true"}
    'simple_bios_update'     : '/UpdateService/Actions/UpdateService.SimpleUpdate',                                       # payload: {"PreserveME":"true", "PreserveNVRAM":"true", "PreserveSMBIOS":"true"}
    'system_info'           : '/Systems/1',
    'manager_info'         : '/Managers/1',
    'power'                 : '/Systems/1/Actions/ComputerSystem.Reset',                                                       # payload: {"ResetType: ["On", "ForceOff", "GracefulShutdown", "GracefulRestart", "ForceRestart", Nmi", "ForceOn"]"}
    'console'               : '/Managers/1/IKVM',
    'bmc_ethernet'          : '/Managers/1/EthernetInterfaces/1',
    'maintenance_window'    : '/UpdateService/MaintenanceWindows',
    'maintenance_window_delete'    : '/UpdateService/Actions/Oem/Hpe/HpeiLOUpdateServiceExt.DeleteMaintenanceWindows'
}
