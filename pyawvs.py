# -*- coding: utf-8 -*-
"""
@Project  ：pyawvs -> pyawvs
@Author   ：last0monster
@mail     : last0monster@gmail.com
@blog     : https://last.monster/
@Date     ：2019/12/26 14:02
"""
import datetime
import time
import requests
import json
import os
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
        'targets_set_proxy': {
            'method': 'patch',
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
        },
        'scans_info': {
            'method': 'get',
            'path': '/scans'
        },
        'scans_delete': {
            'method': 'delete',
            'path': '/scans'
        },
        'scans_stop': {
            'method': 'post',
            'path': '/scans'
        },
        'scans_pause': {
            'method': 'post',
            'path': '/scans'
        },
        'scans_resume': {
            'method': 'post',
            'path': '/scans'
        },
        'scans_add': {
            'method': 'post',
            'path': '/scans'
        },
        'scanning_profiles': {
            'method': 'get',
            'path': '/scanning_profiles'
        },
        'report_templates': {
            'method': 'get',
            'path': '/report_templates'
        },
        'reports_info': {
            'method': 'get',
            'path': '/reports'
        }
    }

    def __init__(self, url, key, timeout=4, proxy=None, retry=2):
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
        self.scan_types = self.get_scan_types()
        self.report_templates = self.get_report_templates()

    def check_awvs(self):
        if self.do().status_code == 401:
            print('api key error!')
            exit()

    def get_scan_types(self):
        tmp = self.do(**self.action['scanning_profiles'])
        if tmp.status_code == 200:
            profiles = tmp.json()['scanning_profiles']
            scan_types = {}
            for i in profiles:
                scan_types[i['name'].replace(' ', '')] = i['profile_id']
            return scan_types
        else:
            return None

    def get_report_templates(self):
        tmp = self.do(**self.action['report_templates'])
        if tmp.status_code == 200:
            templates = tmp.json()['templates']
            report_templates = {}
            for i in templates:
                report_templates[i['name'].replace(' ', '')] = i['template_id']
            return report_templates
        else:
            return None

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

    def targets_set_proxy(self, target_id, address, port, enabled=True, protocol='http', username=None, password=None):
        data = {'proxy': {
            'enabled': enabled,
            'address': address,
            'protocol': protocol,
            'port': port,
            'username': username,
            'password': password
        }}
        if username is None and password is None:
            del data['proxy']['username']
            del data['proxy']['password']
        data = json.dumps(data)
        action = deepcopy(self.action['targets_set_proxy'])
        action['path'] = action['path'] + '/' + target_id + '/configuration'
        tmp = self.do(data=data, **action)
        if tmp.status_code == 204:
            return True
        else:
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

    def scans_info(self, scan_id=None):
        if scan_id is None:
            tmp = self.do(**self.action['scans_info'])
            return tmp.json() if tmp.status_code == 200 else None
        else:
            action = deepcopy(self.action['scans_info'])
            action['path'] = action['path'] + '/' + scan_id
            tmp = self.do(**action)
            return tmp.json() if tmp.status_code == 200 else None

    def scans_delete(self, scan_id):
        action = deepcopy(self.action['scans_delete'])
        action['path'] = action['path'] + '/' + scan_id
        tmp = self.do(**action)
        return True if tmp.status_code == 204 else None

    def scans_stop(self, scan_id):
        data = '{}'
        action = deepcopy(self.action['scans_stop'])
        action['path'] = action['path'] + '/' + scan_id + '/abort'
        tmp = self.do(data=data, **action)
        return True if tmp.status_code == 204 else None

    def scans_pause(self, scan_id):
        data = '{}'
        action = deepcopy(self.action['scans_pause'])
        action['path'] = action['path'] + '/' + scan_id + '/pause'
        tmp = self.do(data=data, **action)
        return True if tmp.status_code == 204 else None

    def scans_resume(self, scan_id):
        data = '{}'
        action = deepcopy(self.action['scans_resume'])
        action['path'] = action['path'] + '/' + scan_id + '/resume'
        tmp = self.do(data=data, **action)
        return True if tmp.status_code == 204 else None

    def scans_add(self, target_id, scan_type='FullScan', report_template='AffectedItems', scan_after=None,
                  profile_id=None, report_template_id=None,
                  start_date=None, recurrence=None, ui_session_id=None):
        if report_template_id is None:
            report_template_id = self.report_templates[report_template]
        if profile_id is None:
            profile_id = self.scan_types[scan_type]
        if scan_after is not None:
            start_date = (datetime.datetime.now() + datetime.timedelta(minutes=scan_after)).strftime(
                '%Y%m%dT%H%M%S%z') + time.strftime('%z')
        if start_date is None and recurrence is None:
            data = {'target_id': target_id, 'profile_id': profile_id, 'report_template_id': report_template_id,
                    'schedule': {'disable': False, 'start_date': start_date, 'time_sensitive': False},
                    'ui_session_id': ui_session_id}
        if start_date is not None and recurrence is None:
            data = {'target_id': target_id, 'profile_id': profile_id, 'report_template_id': report_template_id,
                    'schedule': {'disable': False, 'start_date': start_date, 'time_sensitive': True},
                    'ui_session_id': ui_session_id}
        if start_date is None and recurrence is not None:
            data = {'target_id': target_id, 'profile_id': profile_id, 'report_template_id': report_template_id,
                    'schedule': {'disable': False, 'recurrence': recurrence, 'time_sensitive': True},
                    'ui_session_id': ui_session_id}
        if data['report_template_id'] is None:
            del data['report_template_id']
        if data['ui_session_id'] is None:
            del data['ui_session_id']
        tmp = self.do(data=json.dumps(data), **self.action['scans_add'])
        return tmp.json() if tmp.status_code == 201 else None

    def reports_info(self, report_id=None):
        if report_id is None:
            tmp = self.do(**self.action['reports_info'])
            return tmp.json() if tmp.status_code == 200 else None
        else:
            action = deepcopy(self.action['reports_info'])
            action['path'] = action['path'] + '/' + report_id
            tmp = self.do(**action)
            return tmp.json() if tmp.status_code == 200 else None

    def reports_download(self, fmt='.html', path='./reports'):
        if not os.path.isdir(path):
            os.mkdir(path)
        reports = [i for i in self.reports_info()['reports'] if i['status'] == 'completed']
        if len(reports) > 0:
            for i in reports:
                name = i['generation_date'][0:9] + '_' + i['source']['list_type'] + '_' \
                       + i['source']['description'].split(';')[0].replace(':', '-').replace('/', '-') + '_' \
                       + i['template_name'].replace(' ', '-')
                if fmt == '.html':
                    download_url = i['download'][0][7:]
                    file_name = name + fmt
                if fmt == '.pdf':
                    download_url = i['download'][1][7:]
                    file_name = name + fmt
                path_file_name = path + '/' + file_name
                if not os.path.isfile(path_file_name):
                    res = self.do(path=download_url)
                    with open(path_file_name, 'wb') as f:
                        f.write(res.content)


if __name__ == '__main__':
    import argparse
    from pprint import pprint
    parser = argparse.ArgumentParser(description='pyawvs')
    parser.add_argument('-c', '--config', default=None, type=str, help='-c config.json | awvs config file')
    parser.add_argument('-i', '--info', default=False, action='store_true', help='-i | awvs information')
    parser.add_argument('-r', '--reports', default=False, action='store_true', help='-r | download reports')

    parser.add_argument('--awvs-api', default=None, type=str, help='--awvs-api https://127.0.0.1/ | awvs web url')
    parser.add_argument('--awvs-key', default=None, type=str, help='--awvs-key 1986ad8c0 | awvs api key')
    parser.add_argument('--awvs-proxy', default=None, type=str, help='--awvs-proxy 127.0.0.1:8080 | pyawvs proxy')
    parser.add_argument('--time-out', default=None, type=int, help='--time-out 5 | awvs time-out')
    parser.add_argument('--retry', default=None, type=int, help='--retry 3 | awvs time-out retry count')

    parser.add_argument('-t', '--target', default=None, type=str, help='-t t.txt or -t url | target file or single url')
    parser.add_argument('--target-proxy', default=None, type=str,
                        help='--target-proxy 127.0.0.1:8080 | target proxy')
    parser.add_argument('--target-proxy-auth', default=None, type=str,
                        help='--target-proxy admin:123456 | target proxy auth')

    parser.add_argument('-a', '--add', default=False, action='store_true', help='-a | add target')
    parser.add_argument('-d', '--delete', default=False, action='store_true', help='-d | delete target')
    parser.add_argument('--delete-all-targets', default=False, action='store_true',
                        help='--delete-all-targets | delete all targets')
    parser.add_argument('-s', '--scan', default=False, action='store_true', help='-s | add scan')
    parser.add_argument('--scan-after', default=None, type=int, help='--scan-after 5 | scan after some minutes')
    parser.add_argument('--scan-type', default=None, type=str, help='--scan-type FullScan | view scan types by -i')
    parser.add_argument('--scan-report', default=None, type=str,
                        help='--scan-report AffectedItems | view report templates by -i')

    args = parser.parse_args()
    args = vars(args)
    if args['config'] is not None:
        with open(args['config']) as f:
            config = json.load(f)
        for k, v in args.items():
            if k in config.keys() and v is None:
                args[k] = config[k]
    if args['awvs_api'] is None or args['awvs_key'] is None:
        print('Parameters must have awvs_api and awvs_key')
        exit()
    if args['scan_after'] is None:
        args['scan_after'] = 5
    if args['time_out'] is None:
        args['time_out'] = 5
    if args['retry'] is None:
        args['retry'] = 3
    if args['scan_type'] is None:
        args['scan_type'] = 'FullScan'
    if args['scan_report'] is None:
        args['scan_report'] = 'AffectedItems'


    awvs = AWVS(args['awvs_api'], args['awvs_key'], proxy=args['awvs_proxy'],
                timeout=args['time_out'], retry=args['retry'])
    if args['info']:
        print('\nAWVS information:')
        pprint(awvs.dashboard_info())
        print('\nscan types information:')
        pprint(awvs.scan_types)
        print('\nreport templates information:')
        pprint(awvs.report_templates)
    if args['reports']:
        awvs.reports_download()

    if args['delete_all_targets']:
        awvs_targets = awvs.targets_info()['targets']
        if len(awvs_targets) > 0:
            for i in awvs_targets:
                awvs.targets_delete(i['target_id'])
    if args['target'] is not None:
        targets = []
        target_ids = []
        if os.path.isfile(args['target']):
            des = os.path.basename(args['target'])
            with open(args['target']) as f:
                for i in f.readlines():
                    target = i.rstrip('\n').rstrip('/')
                    if target != '':
                        targets.append(target)
        else:
            des = args['target']
            targets.append(args['target'])
        if args['add']:
            if args['target_proxy'] is not None:
                target_proxy = args['target_proxy'].split(':')
            if args['target_proxy_auth'] is not None:
                target_proxy_auth = args['target_proxy_auth'].split(':')
            for target in targets:
                target_id = awvs.targets_add(target, des)['target_id']
                target_ids.append(target_id)
                if args['target_proxy'] is not None:
                    if args['target_proxy_auth'] is None:
                        awvs.targets_set_proxy(target_id, *target_proxy)
                    else:
                        awvs.targets_set_proxy(target_id, *target_proxy,
                                               username=target_proxy_auth[0], password=target_proxy_auth[1])
            if args['scan']:
                for i in target_ids:
                    awvs.scans_add(i, scan_type=args['scan_type'], report_template=args['scan_report'],
                                   scan_after=args['scan_after'])
        if args['delete']:
            awvs_targets = awvs.targets_info()['targets']
            awvs_targets_delete = []
            if len(awvs_targets) > 0:
                for i in awvs_targets:
                    if i['description'] == des:
                        awvs_targets_delete.append(i)
            if len(awvs_targets_delete) > 0:
                for i in awvs_targets_delete:
                    for j in targets:
                        if j == i['address']:
                            awvs.targets_delete(i['target_id'])
        if args['scan'] and not args['add']:
            if args['scan_after'] is None:
                args['scan_after'] = 5
            if args['scan_type'] is None:
                args['scan_type'] = 'FullScan'
            if args['scan_report'] is None:
                args['scan_report'] = 'AffectedItems'
            awvs_targets = awvs.targets_info()['targets']
            awvs_targets_scan = []
            for i in awvs_targets:
                if i['description'] == des:
                    awvs_targets_scan.append(i)
            for i in awvs_targets_scan:
                awvs.scans_add(i['target_id'], scan_type=args['scan_type'], report_template=args['scan_report'],
                               scan_after=args['scan_after'])



    # test case
    # a = AWVS('https://192.168.168.30/', '1986ad8c0a5b3df4d7028d5f3c06e936ce2bba9e0ba0d4f3b96904044488bfcdc'
    #      , proxy='127.0.0.1:8080')
    # from pprint import pprint
    # pprint(a.dashboard_info())
    # pprint(a.dashboard_stats())
    # pprint(a.dashboard_trends())
    # pprint(a.targets_info())
    # pprint(a.targets_info('511c79b2-a577-4932-91ca-fc35857ef8ee'))
    # pprint(a.targets_add('https://teset.com/', 'sdfsdf', 20))
    # pprint(a.targets_update('511c79b2-a577-4932-91ca-fc35857ef8ee', 'aaaa', 10))
    # pprint(a.targets_delete('511c79b2-a577-4932-91ca-fc35857ef8ee'))
    # pprint(a.targets_set_proxy(target_id='7e46320b-cd9b-4430-92be-371c7c14145f', address='127.0.0.1', port=8080))
    # pprint(a.target_groups_info())
    # pprint(a.target_groups_info('da33a529-721e-4cbe-81aa-2c373adb725f'))
    # pprint(a.target_groups_add('fagaf'))
    # pprint(a.target_groups_update('7b62a808a3b9454581742b9286419a04', 'fate', 'fate'))
    # pprint(a.target_groups_delete('7b62a808a3b9454581742b9286419a04'))
    # pprint(a.scans_info())
    # pprint(a.scans_info('89a7bf32-4fc3-4295-8537-ddb79d8e3328'))
    # pprint(a.scans_delete('3aabae8b-4d1d-469c-9d17-7085e078af39'))
    # pprint(a.scans_pause('a6160b23-d4af-465d-82ec-fa6e4b655127'))
    # pprint(a.scans_resume('a6160b23-d4af-465d-82ec-fa6e4b655127'))
    # pprint(a.scans_stop('a6160b23-d4af-465d-82ec-fa6e4b655127'))
    # pprint(a.scan_types)
    # pprint(a.report_templates)
    # pprint(a.scans_add(target_id=12))
    # pprint(a.scans_add('241d099a-089f-48d0-b943-d424fd41ee11', scan_after=4))
    # pprint(a.reports_info())
    # pprint(a.reports_info('8e91c238-dbaa-41d3-b533-542778a0ccff'))
    # a.reports_download()
