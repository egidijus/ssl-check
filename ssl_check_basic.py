#!/usr/bin/env python

import socket
import ssl
from datetime import datetime

#
# linux local ca
#for cert in $(ls /etc/ssl/certs/); do openssl x509 -in /etc/ssl/certs/$cert -noout --issuer --issuer_hash --hash --serial; done > ~/.virtualenvs/ssl-check/linux-local-ca-issuers.txt
# bad issuers
#   "Symantec",
#   "GeoTrust",
#   "thawte",
#   "RapidSSL",
#   "VeriSign",
#   "Equifax",
# before 2017 december 1

domain_list_path = 'domains.txt'
cert_output_path = 'cert_ouput.txt'
cert_status_file = open(cert_output_path, 'w')
bad_issuers = ("Symantec", "GeoTrust", "thawte", "RapidSSL", "VeriSign",
               "Equifax")
now_date = datetime.now()
one_day = 86400
timeout_seconds = 2
days_until_expired = 100

context = ssl.create_default_context()


def datify_date(the_date):
    # the_date = the_date.replace(tzinfo, "None")
    # strftime Return a string representing the date and time, controlled by an explicit format string
    # strptime Return a datetime corresponding to date_string
    """
    This takes in the wierdo date like 'Dec 01 00:00:00 2018 GMT' and churns out a datetime compatible date
    we only chew first 20 charactes, because i do not want to faff with timezones
    """
    return datetime.strptime(the_date[:20], '%b %d %H:%M:%S %Y')


def flatten(elem, leaves=None):
    """
    This accepts any nested lists and sublists, and expands it, so we have a flat structure, and we do not need to faff with optional nested lists.
    """
    leaves = []
    if isinstance(elem, tuple):
        for member in elem:
            leaves.extend(flatten(member))
    else:
        leaves.append(elem)
    return leaves


def check_expiration_date(ssl_expiration_date):
    """
    accepts expiration date, returns days left until expiration.
    """
    if type(ssl_expiration_date) is datetime:
        time_left = ssl_expiration_date - now_date
        return time_left.total_seconds() / one_day
    else:
        print(ssl_expiration_date + " type, is not datetime")
    return time_left.total_seconds() / one_day


def check_cert(domain):
    try:
        with socket.create_connection((domain, 443),
                                      timeout=timeout_seconds) as sock:
            with context.wrap_socket(
                    sock, server_hostname=domain) as connection:
                result = connection.getpeercert()
                issuer = ' '.join(
                    str(e) for e in flatten(result['issuer'][0:3]))
                valid_until = flatten(result['notAfter'])[0]
                result_dictionary = {
                    "domain": domain,
                    "issuer": issuer,
                    "valid_until": valid_until
                }
                valid_until = datify_date(result_dictionary['valid_until'])
                bad_list = []
                if check_expiration_date(valid_until) < days_until_expired:
                    """
                    if expiration days left less than value, put it in the list of dictionaries
                    """
                    reasons = {
                        "domain":
                        domain,
                        "valid_until":
                        valid_until.strftime("%Y-%m-%d"),
                        "reason":
                        "{} {} {}".format(
                            "less than", int(
                                check_expiration_date(valid_until)),
                            "days left")
                    }
                    cert_status_file.write(str(reasons) + '\n')
                    cert_status_file.flush()
                if any(bad in issuer for bad in bad_issuers):
                    reasons = {
                        "domain": domain,
                        "valid_until": valid_until.strftime("%Y-%m-%d"),
                        "reason": "issuer"
                    }
                    cert_status_file.write(str(reasons) + '\n')
                    cert_status_file.flush()
                print(reasons)
    except Exception as e:
        fail = {"domain": domain, "valid_until": "none", "reason": e}
        print(fail)
        cert_status_file.write(str(fail) + '\n')
        return


def main():
    domain_list = []
    with open(domain_list_path, 'r') as file:
        domains = file.readlines()
        for domain in domains:
            domain_list.append(domain.strip('\n'))
    for domain in domain_list:
        if domain:
            """
            simple check if a line in domains list is empty or not.
            """
            check_cert(domain)
    cert_status_file.close()


if __name__ == '__main__':
    main()
