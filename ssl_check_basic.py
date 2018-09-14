#!/usr/bin/env python

import subprocess, sys
from subprocess import Popen
import datetime

# url = 'yahoo.com:443'
url_list_path = 'urls.txt'
cert_output_path = 'cert_ouput.txt'
cert_status_file = open(cert_output_path, 'w')




def check_cert(url):
    try:
        p1 = subprocess.Popen(['openssl', 's_client',  '-showcerts', '-connect', url],
                  stdout=subprocess.PIPE,
                  bufsize=1,
                  universal_newlines=True)
        stdout, _ = p1.communicate(input="\n")
        p1.stdout.close()
        p2 = subprocess.Popen([
            'openssl', 'x509', '-noout', '-issuer', '-issuer_hash', '-subject'
        ],
                   stdin=subprocess.PIPE,
                   stdout=subprocess.PIPE,
                   universal_newlines=True)
        stdout, _ = p2.communicate(input=stdout, timeout=2)
        cert_status_file.write(str(stdout) + '\n')
        cert_status_file.close()
        print(stdout.splitlines())

    except Exception as e:
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        cert_status_file.close()

def main():
    url_list = []
    with open(url_list_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            url_list.append(line.strip('\n'))
    for url in url_list:
      check_cert(url)

if __name__ == '__main__':
    main()