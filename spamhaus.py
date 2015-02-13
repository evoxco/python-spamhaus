"""
This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2014 Evox Computing Ltd
"""

import dns.resolver
import dns.reversename

zen_return_codes = {'127.0.1.2': 'Spam domain',
                     '127.0.1.4': 'Phishing domain',
                     '127.0.1.5': 'Malware domain',
                     '127.0.1.6': 'Botnet C&C domain',
                     '127.0.1.102': 'Abused legit spam',
                     '127.0.1.103': 'Abused spammed redirector domain',
                     '127.0.1.104': 'Abused legit phish',
                     '127.0.1.105': 'Abused legit malware',
                     '127.0.1.106': 'Abused legit botnet C&C',
                     '127.0.1.255': 'IP queries prohibited!',
                     '127.0.0.2': 'Static UBE sources, verified spam services',
                     '127.0.0.3': 'Static UBE sources, verified spam services',
                     '127.0.0.4': 'Illegal 3rd party exploits, including'
                                  ' proxies, worms and trojan exploits',
                     '127.0.0.5': 'Illegal 3rd party exploits, including'
                                  ' proxies, worms and trojan exploits',
                     '127.0.0.6': 'Illegal 3rd party exploits, including'
                                  ' proxies, worms and trojan exploits',
                     '127.0.0.7': 'Illegal 3rd party exploits, including'
                                  ' proxies, worms and trojan exploits',
                     '127.0.0.10': 'IP ranges which should not be delivering'
                                   ' unauthenticated SMTP email',
                     '127.0.0.11': 'IP ranges which should not be delivering'
                                   ' unauthenticated SMTP email'

                    }


class SpamhausChecker:

    sp_response = {'status': '0',
                   'response_code': ''}

    def __init__(self):
        pass

    def reset_response(self):
        self.sp_response = {'status': '0',
                   'response_code': ''}


    def check_status(self, ip_address):
        self.reset_response()
        sp_resolver = dns.resolver.Resolver()

        try:

            _r_name = dns.reversename.from_address(ip_address)
            _r_name = str(_r_name).replace("in-addr.arpa.", "zen.spamhaus.org.")
            answers = sp_resolver.query(_r_name)

            for rdata in answers:
                #print 'Host %s' %rdata.address
                self.sp_response = {'status': '1',
                                    'response_code': zen_return_codes[rdata.address]}
        except Exception,e:
            pass

        return self.sp_response

if __name__ == "__main__":

    sh = SpamhausChecker()
    response = sh.check_status("58.119.19.2")
