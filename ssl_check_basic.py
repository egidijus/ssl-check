#!/usr/bin/env python

import subprocess, sys
import datetime

url = 'yahoo.com:443'

def check_cert():
    raw_openssl_out = subprocess.run(
        ['openssl', 's_client',  '-showcerts', '-connect', url, '-state'],
        capture_output=True)
    print(raw_openssl_out.stdout)

    parsing_openssl = subprocess.Popen([
        'openssl', 'x509', '-noout', '-issuer', '-issuer_hash', '-subject'],
                                        stdin=raw_openssl_out.stdout,
                                        stdout=subprocess.PIPE)
    try:
        outs, err = parsing_openssl.communicate(timeout=2)
    except Exception as e:
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)

def main():
    check_cert()

if __name__ == '__main__':
    main()