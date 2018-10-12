#!/usr/bin/env python

import boto3
import pprint

boto3.setup_default_session(profile_name='default')
"""
this profile should be a [block] in ~/.aws/credentials
"""

domain_list = []
output_path = 'domains.txt'
write_things = open(output_path, 'w')

client = boto3.client('route53')


def prettyfy(things):
    """
    prettyfy any dict/list thing
    """
    pp = pprint.PrettyPrinter(indent=4)
    return pp.pprint(things)


def check_record_types(record_type):
    """
    check if record type is interesting.
    """
    return record_type in ('A', 'CNAME', 'AAAA')


def list_domains(zone_id):
    """
    accept zone id and return list of domains
    """
    result = client.list_resource_record_sets(HostedZoneId=zone_id)
    records = result['ResourceRecordSets']
    for element in records:
        if check_record_types(element['Type']):
            domain = element['Name'].strip('.')
            write_things.write(str(domain) + '\n')
            write_things.flush()
            domain_list.append(domain)


def list_zones():
    """
    get all zones and Ids for the account
    """
    result = client.list_hosted_zones()
    zones = []
    for zone in result['HostedZones']:
        zone_data = {"Domain": zone['Name'], "Id": zone['Id']}
        list_domains(zone['Id'])


def main():
    list_zones()
    print(domain_list)
    write_things.close()


main()
