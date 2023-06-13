import requests
import json
import logging
from dataclasses import dataclass
import json
import csv


date_strftime_format = "%d-%b-%y %H:%M:%S"
message_format = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(format= message_format,level=logging.INFO, filename='ipa.log', filemode='a')


@dataclass
class User:
    first_name: str
    last_name: str
    login: str
    password: str
    email: str
    group: str


class Ipa(object):
    def __init__(self, host_name: str, ssl_verify=False) -> None:
        self.host_name = host_name
        self.ssl_verify = ssl_verify
        self.session = requests.Session()

    def create_ipa_session(self, login: str, passwd: str):
        ipa_login_url = f'https://{self.host_name}/ipa/session/login_password'
        headers = {'referer': ipa_login_url,
                'Content-Type':'application/x-www-form-urlencoded',
                'Accept': 'text/plain'
        }
        user_data = {
            'user': login,
            'password': passwd
        }
        resp = self.session.post(ipa_login_url, data=user_data, headers=headers)
        logging.info(f'Ipa sesion created by {login}')
        return resp
    
    def __make_request_to_idm(self, req_data: dict):
        session_url = f'https://{self.host_name}/ipa/session/json'
        headers = {'referer': f'https://{self.host_name}/ipa/',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
        }
        data = json.dumps(req_data)
        request = self.session.post(session_url,
                                    data=data, headers=headers, verify=self.ssl_verify)
        response = request.json()
        logging.info(f' request to {session_url}, params: {str(data)}, response: {str(response)}')
        return response
    
    def create_user(self, user: User):
        request_data = {'method': 'user_add',
                'params': [[user.login,],{'givenname': user.first_name,
                                          'sn': user.last_name,
                                          'userpassword': user.password,
                                          'version': '2.245',
                                            },
                            ],
                }
        result = self.__make_request_to_idm(request_data)
        if result.get('error'):
            logging.error(f'User not created {user.login} - {result}')
        else:
            logging.info(f'User {user.login} created')
        return result

    def add_user_to_group(self, user: User):
        request_data = {'method': 'batch',
                      'params': [[{'method': 'group_add_member',
                                    'params': [
                                                [user.group,],{'user': user.login,},
                                              ],
                                  },
                                 ],
                                {'version': '2.245',},
                                ],
                    }
        result = self.__make_request_to_idm(req_data=request_data)
        if result.get('error'):
            logging.error(f'User {user.login} cant be added to {user.group}')
        else:
            logging.info(f'User {user.login} added to {user.group}')
        return result
    
    def change_OTP(self, user: User):
        #first_login
        user_session = requests.Session()
        ipa_login_url = f'https://{self.host_name}/ipa/session/login_password'
        headers = {'referer': ipa_login_url,
                'Content-Type':'application/x-www-form-urlencoded',
                'Accept': 'text/plain'
        }
        user_login_data = {
            'user': user.login,
            'password': user.password
        }
        change_pass_data = {
            'user': user.login,
            'old_password': user.password,
            'new_password': user.password,
        }
        with user_session as session:
            resp = session.post(ipa_login_url, data=user_login_data, headers=headers, verify=self.ssl_verify)
            if resp.status_code != '204':
                if 'error' in resp.text:
                    logging.error(f'cant login with data {user.login} - {resp.text}')
            #changing otp
            result = session.post(f'https://{self.host_name}/ipa/session/change_password', data=change_pass_data, verify=self.ssl_verify)
            if result.status_code != '204':
                if 'error' in result.text:
                    logging.error(f'Cant change OTP to user {user.login} - {result.text}')
                else:
                    logging.info(f'OTP change for {user.login}')
            return result
        
    def edit_user_title(self, user: User, title: str):
        json_data = {'method': 'user_mod',
                    'params': [[user.login,],
                                {'all': True,
                                'rights': True,
                                'title': title,
                                'version': '2.245',
                                },],
                    }
        result = self.__make_request_to_idm(json_data)
        logging.info(f'To user {user.login} add title {title}')
        return result
    
        


if __name__ == '__main__':
    devim_ipa = Ipa('idm-2.devim.team')
    devim_ipa.create_ipa_session('daniil.boyko', 'PowerWolf115229')
    with open('vpn_employees1.csv', 'r', newline='') as f:
        reader = csv.reader(f)
        next(reader)
        for line in reader:
            if line[1] == "коллекторы2":
                user = User(line[3], line[4], line[6], line[5], f'123@devim.team' ,line[7])
                devim_ipa.create_user(user)
                devim_ipa.add_user_to_group(user)
                devim_ipa.change_OTP(user)
                devim_ipa.edit_user_title(user=user, title='DZP')


