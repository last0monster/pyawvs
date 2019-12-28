# -*- coding: utf-8 -*-
"""
@Project  ：pyawvs -> pyawvs
@Author   ：last0monster
@mail     : last0monster@gmail.com
@blog     : https://last.monster/
@Date     ：2019/12/26 14:02
"""

import requests
import json
from pprint import pprint
from requests.adapters import HTTPAdapter
from copy import deepcopy


class AWVS:
    action = {
        'dashboard_info': {
            'method': 'get',
            'path': '/info'
        },
        'dashboard_stats': {
            'method': 'get',
            'path': '/me/stats'
        },
        'dashboard_trends': {
            'method': 'get',
            'path': '/me/trends'
        },
        'notifications': {
            'method': 'get',
            'path': '/notifications'
        },
        'notifications_count': {
            'method': 'get',
            'path': '/notifications/count'
        },
        'targets_info': {
            'method': 'get',
            'path': '/targets'
        },
        'targets_add': {
            'method': 'post',
            'path': '/targets'
        },
        'targets_delete': {
            'method': 'delete',
            'path': '/targets'
        },
        'targets_update': {
            'method': 'patch',
            'path': '/targets'
        },
        'target_groups_info': {
            'method': 'get',
            'path': '/target_groups'
        },
        'target_groups_add': {
            'method': 'post',
            'path': '/target_groups'
        },
        'target_groups_delete': {
            'method': 'delete',
            'path': '/target_groups'
        },
        'target_groups_update': {
            'method': 'patch',
            'path': '/target_groups'
        }
    }

    def __init__(self, url, key, timeout=1, proxy=None, retry=2):
        self.api = url.rstrip('/') + '/api/v1'
        self.key = key
        self.timeout = timeout
        self.targets_add_failed = set()
        self.session = requests.Session()
        self.session.mount('https://', HTTPAdapter(max_retries=retry))
        self.session.verify = False
        self.session.headers = {
            "X-Auth": key,
            "Content-type": "application/json; charset=utf8"
        }
        if proxy is not None:
            self.session.proxies = {'https': proxy}
        requests.packages.urllib3.disable_warnings()
        self.check_awvs()

    def check_awvs(self):
        if self.do().status_code == 401:
            print('api key error!')
            exit()

    def do(self, data=None, method='get', path='/me'):
        url = self.api + path
        try:
            if method == 'get':
                return self.session.get(url, timeout=self.timeout)
            elif method == 'post':
                return self.session.post(url, data=data, timeout=self.timeout)
            elif method == 'delete':
                return self.session.delete(url, timeout=self.timeout)
            elif method == 'patch':
                return self.session.patch(url, data=data, timeout=self.timeout)
            else:
                pass
        except requests.exceptions.RequestException as e:
            print('connecting awvs server error!')
            print(e)
            exit()

    def dashboard_info(self):
        tmp = self.do(**self.action['dashboard_info'])
        return tmp.json() if tmp.status_code == 200 else None

    def dashboard_stats(self):
        tmp = self.do(**self.action['dashboard_stats'])
        return tmp.json() if tmp.status_code == 200 else None

    def dashboard_trends(self):
        tmp = self.do(**self.action['dashboard_trends'])
        return tmp.json() if tmp.status_code == 200 else None

    def notifications(self):
        tmp = self.do(**self.action['notifications'])
        return tmp.json() if tmp.status_code == 200 else None

    def notifications_count(self):
        tmp = self.do(**self.action['notifications_count'])
        return tmp.json() if tmp.status_code == 200 else None

    def targets_info(self, target_id=None):
        if target_id is None:
            tmp = self.do(**self.action['targets_info'])
            return tmp.json() if tmp.status_code == 200 else None
        else:
            action = deepcopy(self.action['targets_info'])
            action['path'] = action['path'] + '/' + target_id
            tmp = self.do(**action)
            return tmp.json() if tmp.status_code == 200 else None

    def targets_add(self, address, description='targets_pyawvs', criticality=10):
        data = {"address": address, "description": description, "criticality": criticality}
        data = json.dumps(data)
        tmp = self.do(data=data, **self.action['targets_add'])
        if tmp.status_code == 201:
            return tmp.json()
        else:
            self.targets_add_failed.add((address, description, criticality))
            return None

    def targets_delete(self, target_id):
        action = deepcopy(self.action['targets_delete'])
        action['path'] = action['path'] + '/' + target_id
        tmp = self.do(**action)
        return True if tmp.status_code == 200 else None

    def targets_update(self, target_id, description='targets_pyawvs', criticality=10):
        data = {"criticality": criticality, "description": description}
        data = json.dumps(data)
        action = deepcopy(self.action['targets_update'])
        action['path'] = action['path'] + '/' + target_id
        tmp = self.do(data=data, **action)
        if tmp.status_code == 204:
            return True
        else:
            return None

    def target_groups_info(self, group_id=None):
        if group_id is None:
            tmp = self.do(**self.action['target_groups_info'])
            return tmp.json() if tmp.status_code == 200 else None
        else:
            action = deepcopy(self.action['target_groups_info'])
            action['path'] = action['path'] + '/' + group_id
            tmp = self.do(**action)
            return tmp.json() if tmp.status_code == 200 else None

    def target_groups_add(self, name, description='target_groups_pyawvs'):
        data = {"name": name, "description": description}
        data = json.dumps(data)
        tmp = self.do(data=data, **self.action['target_groups_add'])
        if tmp.status_code == 201 and 'group_id' in tmp.json().keys():
            return tmp.json()
        else:
            return None

    def target_groups_delete(self, group_id):
        action = deepcopy(self.action['target_groups_delete'])
        action['path'] = action['path'] + '/' + group_id
        tmp = self.do(**action)
        return True if tmp.status_code == 204 else None

    def target_groups_update(self, group_id, name, description='target_groups_pyawvs'):
        data = {"name": name, "description": description}
        data = json.dumps(data)
        action = deepcopy(self.action['target_groups_update'])
        action['path'] = action['path'] + '/' + group_id
        tmp = self.do(data=data, **action)
        if tmp.status_code == 204:
            return True
        else:
            return None


if __name__ == '__main__':
    a = AWVS('https://192.168.168.30/', '1986ad8c0a5b3df4d7028d5f3c06e936ce2bba9e0ba0d4f3b96904044488bfcdc'
             , proxy='127.0.0.1:8080')
    # pprint(a.dashboard_info())
    # pprint(a.dashboard_stats())
    # pprint(a.dashboard_trends())
    # pprint(a.targets_info())
    # pprint(a.targets_info('511c79b2-a577-4932-91ca-fc35857ef8ee'))
    # pprint(a.targets_add('https://teset.com/', 'sdfsdf', 20))
    # pprint(a.targets_update('511c79b2-a577-4932-91ca-fc35857ef8ee', 'aaaa', 10))
    # pprint(a.targets_delete('511c79b2-a577-4932-91ca-fc35857ef8ee'))
    # pprint(a.target_groups_info())
    # pprint(a.target_groups_info('da33a529-721e-4cbe-81aa-2c373adb725f'))
    # pprint(a.target_groups_add('fagaf'))
    # pprint(a.target_groups_update('7b62a808a3b9454581742b9286419a04', 'fate', 'fate'))
    # pprint(a.target_groups_delete('7b62a808a3b9454581742b9286419a04'))

    pprint(a.targets_info())