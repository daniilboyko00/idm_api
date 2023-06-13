import requests
import json
import logging
import getpass
import string
import random

requests.packages.urllib3.disable_warnings()

class ipa(object):

    def __init__(self, server, sslverify=False):
        self.server = server
        self.sslverify = sslverify
        self.log = logging.getLogger(__name__)
        self.session = requests.Session()

    def login(self, user, password):
        rv = None
        ipaurl = 'https://{0}/ipa/session/login_password'.format(self.server)
        header = {'referer': ipaurl, 'Content-Type':
                  'application/x-www-form-urlencoded', 'Accept': 'text/plain'}
        login = {'user': user, 'password': password}
        rv = self.session.post(ipaurl, headers=header, data=login,
                               verify=self.sslverify)
        return rv

    def makeReq(self, pdict):
        results = None
        ipaurl = 'https://{0}/ipa'.format(self.server)
        session_url = '{0}/session/json'.format(ipaurl)
        header = {'referer': ipaurl, 'Content-Type': 'application/json',
                  'Accept': 'application/json'}

        data = {'id': 0, 'method': pdict['method'], 'params':
                [pdict['item'], pdict['params']]}

        self.log.debug('Making {0} request to {1}'.format(pdict['method'],
                        session_url))

        request = self.session.post(
                session_url, headers=header,
                data=json.dumps(data),
                verify=self.sslverify
        )
        results = request.json()

        return results

    def user_show(self, user):
        m = {'item': [user], 'method': 'user_show', 'params':
            {'all': True, 'raw': False, 'version': "2.235"}}
        results = self.makeReq(m)

        return results

    def user_add(self, user, opts):
        opts['all'] = False
        m = {'method': 'user_add', 'item': [user], 'params': opts}
        results = self.makeReq(m)

        return results

    def passwd(self, principal, password):
        item = [principal, password]
        m = {'method': 'passwd', 'item': item, 'params': {'version': "2.235"}}
        results = self.makeReq(m)
        return results

    def group_add_member(self, group, user):
        m = {
            'item': [group],
            'method': 'group_add_member',
            'params': {
                'user': user,
                'all': True,
                'raw': True,
            }
        }
        results = self.makeReq(m)
        return results

    def group_find(self, group=None, sizelimit=40000):
        m = {'method': 'group_find', 'item': [group], 'params': {'all': True, 'sizelimit': sizelimit}}
        results = self.makeReq(m)

        return results


def userinfo(reply):
    uid = reply['result']['result']['uid']
    mail = reply['result']['result']['mail']
    groups = reply['result']['result']['memberof_group'] + reply['result']['result']['memberofindirect_group']
    blocked = reply['result']['result']['nsaccountlock']
    return ('UID ', uid, 'Mail ', mail,'Groups ', groups,'Is blocked ', blocked)

def newuser(user):
    givenname=input('Имя ')
    sn = input('Фамилия ')
    cn = givenname + sn
    !!!! userpassword = pwgen(16)
    mail = input('Введите почту ')
    opts = {'sn': sn, 'cn': cn, 'givenname': givenname, 'mail': mail, 'userpassword': userpassword }
    devimipa.user_add(user, opts)
    print('User created, password ', userpassword)

def addusertogroup(grouplist, user):
    for i in grouplist:
        devimipa.group_add_member(i, user)
    #print(userinfo(devimipa.user_show(user)))


def listgroups(reply):
    groups = []
    dic = reply['result']['result']
    for i in dic:
        group = i['cn']
        groups.append(group)
    return groups


devimipa = ipa('idm-2.devim.team')
devimipa.login('daniil.boyko', 'PowerWolf115229')
#devimipa.login(input('Введите логин '), getpass.getpass('Введите пароль '))
#user = input('Введите пользователя которого хотите посмотреть ')
#reply = devimipa.user_show(user)
#print(userinfo(reply))
#newuser(input('Введите логин нового пользователя '))

#devimipa = ipa('idm-1.devim.local')
#print('Введите ваш креды для доступа в idm')
#devimipa.login(input('Введите логин '), getpass.getpass('Введите пароль '))
print('Выберите действие :')
select = int(input('1 - Информация о пользователе. 2 - добавление пользователя. 3 - добавление пользователя в группу. 4 - поиск групп. '))
if select == 1:
    user = input('Введите имя пользователя которого хотите посмотреть ')
    print(userinfo(devimipa.user_show(user)))
if select == 2:
    newuser(input('Введите логин нового пользователя '))
if select == 3:
    print('Список доступных групп:')
    print(listgroups(devimipa.group_find()))
    user = input('Введите пользователя ')
    groupstr = input('Введите название групп через запятую ')
    #cn = input('Введите группу ')
    grouplist = groupstr.split(",")
    #devimipa.group_add_member(cn, user)
    for i in grouplist:
        devimipa.group_add_member(i, user)

if select == 4:
    print(listgroups(devimipa.group_find()))



{"method":"batch","params":[[{"method":"user_show","params":[["adelina.mikhailova"],{"no_members":true}]},{"method":"user_show","params":[["admin"],{"no_members":true}]},{"method":"user_show","params":[["aleksandr.fomichev"],{"no_members":true}]},{"method":"user_show","params":[["aleksandr.kovalev"],{"no_members":true}]},{"method":"user_show","params":[["aleksandr.ratchin"],{"no_members":true}]},{"method":"user_show","params":[["aleksandr.shtilgoiz"],{"no_members":true}]},{"method":"user_show","params":[["aleksandr.zarovnyi"],{"no_members":true}]},{"method":"user_show","params":[["aleksandra.drogan"],{"no_members":true}]},{"method":"user_show","params":[["aleksandra.vysotskaya"],{"no_members":true}]},{"method":"user_show","params":[["aleksei.solonkov"],{"no_members":true}]},{"method":"user_show","params":[["alexander.andreev"],{"no_members":true}]},{"method":"user_show","params":[["alexander.nikitin"],{"no_members":true}]},{"method":"user_show","params":[["alexander.panov"],{"no_members":true}]},{"method":"user_show","params":[["alexander.shtilgoiz"],{"no_members":true}]},{"method":"user_show","params":[["alexander.yarukhin"],{"no_members":true}]},{"method":"user_show","params":[["alexey.kondratiev"],{"no_members":true}]},{"method":"user_show","params":[["allure1"],{"no_members":true}]},{"method":"user_show","params":[["allure2"],{"no_members":true}]},{"method":"user_show","params":[["amashkileison"],{"no_members":true}]},{"method":"user_show","params":[["anatoliy.egorov"],{"no_members":true}]}],{"version":"2.245"}]}