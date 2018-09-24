#!/usr/bin/env python


import socket
import ssl

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

# url_list_path = 'short_url.txt'
url_list_path = 'urls_u.txt'
cert_output_path = 'cert_ouput.txt'
cert_status_file = open(cert_output_path, 'w')


context = ssl.create_default_context()

def flatten(elem, leaves=None):
    leaves =  []
    if isinstance(elem, tuple):
        for member in elem:
            leaves.extend(flatten(member))
    else:
        leaves.append(elem)
    return leaves

def check_cert(url):
    try:
        with socket.create_connection((url, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=url) as connection:
                result = connection.getpeercert()
                basic_result =  (result['issuer'][
                    0:3], result['notBefore'], result['notAfter'])
                compiled_result = ['MAYBE'] + [url] + flatten(basic_result)
                print(flatten(basic_result))
            cert_status_file.write(str(compiled_result) + '\n')
    except Exception as e:
        fail = ['FAIL', url, ' failed with ', e]
        print(fail)
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