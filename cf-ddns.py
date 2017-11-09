#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Based on code from https://github.com/AmirAzodi/cloudflare_ddns
#

import argparse
import json
import os

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
    from urllib.request import Request
    from urllib.error import URLError
    from urllib.error import HTTPError
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen
    from urllib2 import Request
    from urllib2 import HTTPError
    from urllib2 import URLError

CF_BASE_URL = 'https://api.cloudflare.com/client/v4/zones/'
IPV4_CHECKER = 'http://ipv4.icanhazip.com/'
IPV6_CHECKER = 'http://ipv6.icanhazip.com/'
CONFIG_FILE_NAME = 'cf-ddns.conf'
SCRIPT_DIR = os.path.dirname(__file__)


class CloudFlareUpdater(object):
    messages = []
    config = None
    content_header = None
    public_ipv4 = None
    public_ipv6 = None

    def update_cloudflare(self, force=False):
        self._load_config()
        self._get_public_ips()
        return self._process_domains(force=force)

    def dump_log(self):
        for msg in self.messages:
            print('* %s' % msg)

    def _log(self, msg):
        self.messages.append(msg)

    def _load_config(self):
        with open(os.path.join(SCRIPT_DIR, CONFIG_FILE_NAME), 'r') as config_file:
            try:
                self.config = json.loads(config_file.read())
            except ValueError as ex:
                raise RuntimeError('problem with the config file', ex)

        if self.config and (not self.config['user']['email'] or not self.config['user']['api_key']):
            raise RuntimeError('missing CloudFlare auth credentials')

        self.content_header = {
            'X-Auth-Email': self.config['user']['email'],
            'X-Auth-Key': self.config['user']['api_key'],
            'Content-type': 'application/json'
        }

        for idx, domain in enumerate(self.config['domains'], start=1):
            # check to make sure domain name is specified
            if not domain['name']:
                raise RuntimeError('missing "name" for domain at slot %d' % idx)

            for host_idx, host in enumerate(domain['hosts'], start=1):
                if not host['name']:
                    raise RuntimeError('missing "name" for host %d in domain %s' % (host_idx, domain['name']))

                for host_type in host['types']:
                    if host_type not in ('A', 'AAAA'):
                        raise RuntimeError('wrong or missing dns record type "%s" for host %s in %s' % (host_type,
                                                                                                        host['name'],
                                                                                                        domain['name']))

    def _get_public_ips(self):
        try:
            self.public_ipv4 = urlopen(Request(IPV4_CHECKER)).read().rstrip().decode('utf-8')
            self._log('IPv4: %s' % self.public_ipv4)
        except URLError:
            self._log('no public IPv4 address detected')

        try:
            self.public_ipv6 = urlopen(Request(IPV6_CHECKER)).read().rstrip().decode('utf-8')
            self._log('IPv6: %s' % self.public_ipv6)
        except URLError:
            self._log('no public IPv6 address detected')

        if not (self.public_ipv4 or self.public_ipv6):
            raise RuntimeError('Failed to get any public IP addresses')

    def _process_domains(self, force=False):
        for domain in self.config['domains']:
            # get domain zone id from CloudFlare if missing
            if not domain['id']:
                self._get_domain_id(domain)
                assert domain['id']

            success = True
            do_update_config = False

            # get domain zone id from CloudFlare if missing
            for host in domain['hosts']:
                fqdn = '%s.%s' % (host['name'], domain['name'])

                # get host id from CloudFlare if missing
                if not host['id']:
                    self._log('host id for "{0}" is missing. attempting to get it from cloudflare...'.format(fqdn))

                    # TODO only need to do this once per domain, not per host
                    rec_id_req = Request('{}{}/dns_records/'.format(CF_BASE_URL, domain['id']),
                                         headers=self.content_header)

                    rec_id_resp = urlopen(rec_id_req).read().decode('utf-8')
                    parsed_host_ids = json.loads(rec_id_resp)

                    for h in parsed_host_ids['result']:
                        if fqdn == h['name']:
                            host['id'] = h['id']
                            self._log('host id for "{0}" is {1}'.format(fqdn, host['id']))

                # iterate over the record types
                for t in host['types']:
                    # select which IP to use based on dns record type (e.g. A or AAAA)
                    if t == 'A':
                        if self.public_ipv4:
                            public_ip = self.public_ipv4
                            ip_version = 'ipv4'
                        else:
                            self._log('cannot set A record because no IPv4 is available')
                            continue
                    elif t == 'AAAA':
                        if self.public_ipv6:
                            public_ip = self.public_ipv6
                            ip_version = 'ipv6'
                        else:
                            self._log('cannot set AAAA record because no IPv6 is available')
                            continue

                    # update ip address if it has changed since last update
                    if force or host[ip_version] != public_ip:
                        status = self._update_ip(domain, fqdn, host, ip_version, public_ip, t)
                        do_update_config |= status
                        success &= status

            if do_update_config:
                self._update_config()
            else:
                self._log('nothing to update')

            return success

    def _update_ip(self, domain, fqdn, host, ip_version, public_ip, host_type):
        try:
            data = json.dumps({
                'id': host['id'],
                'type': host_type,
                'name': host['name'],
                'content': public_ip
            })

            url_path = '{}{}{}{}'.format(CF_BASE_URL, domain['id'], '/dns_records/', host['id'])

            update_request = Request(url_path, data=data.encode('utf-8'), headers=self.content_header)
            update_request.get_method = lambda: 'PUT'

            update_res = urlopen(update_request).read().decode('utf-8')
            update_res_obj = json.loads(update_res)

            if update_res_obj['success']:
                host[ip_version] = public_ip
                self._log('update successful (type: {0}, fqdn: {1}, ip: {2})'.format(host_type, fqdn, public_ip))
                return True
            else:
                self._log('update failed (type: {}, fqdn: {}, ip: {}): {}'.format(
                    host_type, fqdn, public_ip, update_res))
                return False

        except (Exception, HTTPError) as ex:
            self._log('update failed (type: {}, fqdn: {}, ip: {}): {}'.format(host_type, fqdn, public_ip, ex))
            return False

    def _get_domain_id(self, domain):
        try:
            self._log(
                'zone id for "{0}" is missing. attempting to '
                'get it from cloudflare...'.format(domain['name']))
            zone_id_req = Request(CF_BASE_URL, headers=self.content_header)
            zone_id_resp = urlopen(zone_id_req)
            for d in json.loads(zone_id_resp.read().decode('utf-8'))['result']:
                if domain['name'] == d['name']:
                    domain['id'] = d['id']
                    self._log('zone id for "{0}" is'
                             ' {1}'.format(domain['name'], domain['id']))
        except HTTPError as e:
            self._log('could not get zone id for: {0}'.format(domain['name']))
            self._log('possible causes: wrong domain and/or auth credentials')
            # continue

    def _update_config(self):
        # if any records were updated, update the config file accordingly
        with open(CONFIG_FILE_NAME, 'w') as config_file:
            json.dump(self.config, config_file, indent=1, sort_keys=True)
        self._log('configuration updated')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--force", help="force setting of IP addresses",
                        action="store_true")
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    args = parser.parse_args()

    updater = CloudFlareUpdater()
    success = updater.update_cloudflare(force=args.force)

    if args.verbose or not success:
        updater.dump_log()
