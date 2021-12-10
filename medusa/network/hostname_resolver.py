# -*- coding: utf-8 -*-
# Copyright 2020- Datastax, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import socket
import logging
import dns.resolver
import dns.reversename
import re
import sys

class HostnameResolver():
    def __init__(self, resolve_addresses=True):
        self.resolve_addresses = resolve_addresses
        logging.debug

    def resolve_fqdn(self, ip_address=''):
        if str(self.resolve_addresses) == "False":
            logging.debug("Not resolving {} as requested".format(ip_address))
            return ip_address

        fqdn = socket.getfqdn(ip_address) # Set as default if no match in dns PTR lookup

        if self.resolve_addresses: # try:
            # Try to figure out the naming schema from current hostname
            curHostname = socket.gethostname()
            idx = curHostname.rfind("-") # on K8S pods usually get suffixed by a number (StatefulSet) or id (Deployment)
            if idx > 0:
                pattern = '^(' + curHostname[:idx] + '-[0-9a-z]+(?:\..*)?)'
                p = re.compile(pattern)
                qname = dns.reversename.from_address(ip_address)
                answer = dns.resolver.resolve(qname, 'PTR')
                if (len(answer) > 0):
                    for rr in answer:
                        rr_str = str(rr)[:-1]; # chop off dot at the of the PTR record
                        logging.debug("Got ptr record {} for ip {}".format(rr_str, ip_address))
                        m = p.match(rr_str)
                        if m != None and len(m.groups()) > 0:
                            fqdn = m.group(1);
                            logging.debug("Setting fqdn to {}".format(fqdn))
                            break
        #except:
        #    logging.error("Unexpected error: {}".format(sys.exc_info()[0]))
        #else:
        #    fqdn = socket.getfqdn(ip_address) # Fallback if necessary

        logging.debug("Resolved {} to {}".format(ip_address, fqdn))
        return fqdn

