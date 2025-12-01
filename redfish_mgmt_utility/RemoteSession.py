import UsrIntel.R1
import requests
import subprocess
import json

class RemoteSession:
    def __init__(self, host, mgmt, user, pw, endpoint, debug, timeout=5,):
        self.session_location = None
        self.token = None
        self.session = None
        self.endpoint = endpoint

        if mgmt is not None:
            self.base_url = f'https://{mgmt}/redfish/v1'
        else:
            self.base_url = f'https://{host}/redfish/v1'           # TODO - need to get fqhn
       
        self.create_session(host, user, pw, debug)


    def create_session(self, host, user, pw, debug):
        try:
            credentials = json.dumps({'UserName': user, 'Password': pw})
            url = f'{self.base_url}{self.endpoint}'
            header = {'content-type': 'application/json'}
            self.session = requests.Session()
            response = self.session.post(url, headers=header, data=credentials, timeout=5, verify=False)
            status = response.status_code
            if status == 201:
                self.token = response.headers['x-auth-token']
                self.session_location = response.headers['location']
                self.session.headers.update({'x-auth-token': self.token})                    # Save token in session header
            elif status == 404:
                if debug:
                    print(f'{host}: Maximum sessions reached. Status code:{status}')
            else:
                if debug:
                    print(f'{host}: Unable to create Redfish session. Check credentials. Status code:{status}')
        except Exception as err:
            error = host + ": " + str(err)
            if debug:
                print(error)

    def close_session(self, debug=False):
        if self.session_location:
            try:
                if self.session_location.startswith('/redfish/v1'):
                    full_url = f'{self.base_url.split("/redfish/v1")[0]}{self.session_location}'
                else:
                    full_url = f'{self.base_url}{self.session_location}'

                if debug:
                    print(f"Attempting to close session at: {full_url}")
                response = self.session.delete(full_url, timeout=5, verify=False)
                if response.status_code == 200:
                    if debug:
                        print("Session closed successfully.")
                else:
                    if debug:
                        print(f"Failed to close session. Status code: {response.status_code}")
            except Exception as err:
                if debug:
                    print(f"Error closing session: {err}")
        else:
            if debug:
                print("No session location found. Session might not have been created.")

