# ssl-check is a pure python3 way of testing ssl/https certificates
You should not need to install anything.
You only need to add your list of domains to the file urls.txt
The script will produce a file `cert_ouput.txt` with a list of certificates that have failed and the reason why they have failed.

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
