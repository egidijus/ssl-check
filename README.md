# ssl-check is a pure python3 way of testing ssl/https certificates
You should not need to install anything.
You only need to add your list of domains to the file urls.txt
The script will produce a file `cert_ouput.txt` with a list of certificates that have failed and the reason why they have failed.

## Requirements
* python3 for ssl-check
* for `aws_get_domains.py`, python3, pprint, boto3, you can install via requirements.txt

## Example ouput
CSVs !!!
```
domain,valid_until,reason,checked_on
www.google.co.uk,2018-12-18,less than 63 days left,2018-10-15
www.google.fr,2018-12-18,less than 63 days left,2018-10-15
www.t.co,2018-12-20,less than 65 days left,2018-10-15
www.tmall.com,2018-11-22,less than 37 days left,2018-10-15
www.google.com.br,2018-12-18,less than 63 days left,2018-10-15
www.google.it,2018-12-18,less than 63 days left,2018-10-15
www.google.ru,2018-12-18,less than 63 days left,2018-10-15
www.google.es,2018-12-18,less than 63 days left,2018-10-15
www.gmw.cn,none,"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'www.gmw.cn'. (_ssl.c:1045)",2018-10-15
www.tumblr.com,2018-11-06,less than 21 days left,2018-10-15
www.blogspot.com,2018-12-18,less than 63 days left,2018-10-15
www.imgur.com,2019-01-09,less than 85 days left,2018-10-15
```


## Failure tests/conditions
This is designed to firstly test for bad issuers, which will be untrusted by various operating systems and browsers.
"Bad issuers"
* "Symantec",
* "GeoTrust",
* "thawte",
* "RapidSSL",
* "VeriSign",
* "Equifax",

Secondly I am testing for expiration date, if there are less than `x` days remaining, add the domain to the list of "bad" domains.

https://knowledge.digicert.com/alerts/ALERT2530.html

## Tips
* Try running `aws_get_domains.py` to produce a list of domains in your aws route53.
* Update the `default` in `boto3.setup_default_session(profile_name='default')` to your aws profile in `~/.aws/credentials`



## Reasons explanation

```
[Errno -2] Name or service not known = no server behind the domain, we should check and maybe delete the record. could be internal only. could be whitelist/blacklist security group.
[Errno 0] Error = maybe probably no server behind the domain, we should check and maybe delete the record. could be internal only. could be whitelist/blacklist security group.
[Errno 101] Network is unreachable = maybe probably no server behind the domain, we should check and maybe delete the record. could be internal only. could be whitelist/blacklist security group.
[Errno 111] Connection refused = maybe probably no server behind the domain, we should check and maybe delete the record. could be internal only. could be whitelist/blacklist security group.
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'test.google.com'. (_ssl.c:1045) = your certificate is NOT VALID, change it !
[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1045) = your certificate is NOT VALID, change it !
issuer = the issuer is one of the "bad" issuers ("Symantec", "GeoTrust", "thawte", "RapidSSL", "VeriSign", "Equifax").
less than 83 days left = your certificate is VALID, but it will stop working after 83 days.
timed out = maybe probably no server behind the domain, we should check and maybe delete the record. could be internal only. could be whitelist/blacklist security group.
```
