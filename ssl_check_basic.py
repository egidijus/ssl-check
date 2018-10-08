#!/usr/bin/env python


import socket
import ssl
from datetime import datetime

#
# linux local ca
#for cert in $(ls /etc/ssl/certs/); do openssl x509 -in /etc/ssl/certs/$cert -noout --issuer --issuer_hash --hash --serial; done > ~/.virtualenvs/ssl-check/linux-local-ca-issuers.txt
# bad issuers
# 	"Symantec",
# 	"GeoTrust",
# 	"thawte",
# 	"RapidSSL",
# 	"VeriSign",
# 	"Equifax",
# before 2017 december 1

url_list_path = 'urls.txt'
cert_output_path = 'cert_ouput.txt'
cert_status_file = open(cert_output_path, 'w')
bad_issuers = ("Symantec", "GeoTrust", "thawte", "RapidSSL", "VeriSign", "Equifax")
# bad_list = {}
now_date = datetime.now()
day = 86400

context = ssl.create_default_context()
def datify_date(the_date):
    # the_date = the_date.replace(tzinfo, "None")
    # strftime Return a string representing the date and time, controlled by an explicit format string
    # strptime Return a datetime corresponding to date_string
    """
    this takes in the wierdo date like 'Dec 01 00:00:00 2018 GMT' and churns out a datetime compatible date
    we only chew first 20 charactes, because i do not want to faff with timezones
    """
    return datetime.strptime(the_date[:20], '%b %d %H:%M:%S %Y')


def check_symantec_date(ssl_date_today):
    return

def flatten(elem, leaves=None):
    leaves =  []
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
        return time_left.total_seconds() / day
    else:
        print (ssl_expiration_date + " type, is not datetime")
    return time_left.total_seconds() / day



def check_cert(url):
    try:
        with socket.create_connection((url, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=url) as connection:
                result = connection.getpeercert()
                issuer = ' '.join(str(e) for e in flatten(result['issuer'][0:3]))
                valid_from = flatten(result['notBefore'])[0]
                valid_until = flatten(result['notAfter'])[0]
                result_dictionary = {
                    "host": url,
                    "issuer": issuer,
                    "valid_from": valid_from,
                    "valid_until": valid_until
                }
                valid_from = datify_date(
                    result_dictionary['valid_from'])
                valid_until = datify_date(
                    result_dictionary['valid_until'])
                # print(valid_from)
                # print(issuer)
                # print(check_expiration_date(valid_until))

                reasons = []

                if check_expiration_date(valid_until) < 300:
                    """
                    if expiration days left less than value, put it in the list of dictionaries
                    """
                    reasons.append( {
                        "host":
                        url,
                        "issuer":
                        issuer,
                        "valid_from":
                        valid_from.strftime("%Y-%m-%d"),
                        "valid_until":
                        valid_until.strftime("%Y-%m-%d"),
                        "reason":
                        "{} {} {}".format(
                            "less than", int(
                                check_expiration_date(valid_until)),
                            "days left")
                    })
                    # cert_status_file.write(str(bad_list) + '\n')
                if any(bad in issuer for bad in bad_issuers):
                    reasons.append({
                        "host":
                        url,
                        "issuer":
                        issuer,
                        "valid_from":
                        valid_from.strftime("%Y-%m-%d"),
                        "valid_until":
                        valid_until.strftime("%Y-%m-%d"),
                        "reason":"issuer"
                    })
                    # cert_status_file.write(str(bad_list) + '\n')
                print(reasons)
                if reasons:
                    cert_status_file.write(str(reasons) + '\n')
                    cert_status_file.flush()

    except Exception as e:
        fail = {
            "host": url,
            "issuer": "none",
            "valid_from": "none",
            "valid_until": "none",
            "reason": e
        }
        # ['FAIL', url, ' failed with ', e]
        # print(fail)
        cert_status_file.write(str(fail) + '\n')
        return


def main():
    url_list = []
    with open(url_list_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            url_list.append(line.strip('\n'))
    for url in url_list:
        check_cert(url)
    cert_status_file.close()

if __name__ == '__main__':
    main()