#!/usr/bin/env python
# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""
pip install iocextract
pip install re
pip install stix

This program parse the single STIX package into different IOC in array.
Change the on9strings if more on9 things happen to the content

default filename:fsisac.txt

Work in stix-1.1

"""
# python-stixls
from stix.core import STIXPackage
import re
import iocextract

on9strings = {'[.]':'.', 'hxxp':'http', '[@]':'@'}
iocs = {'domain':[], 'ip':[], 'email':[], 'hash':[], 'url':[], 'hash':[], 'yara':[]}
FILENAME = './fsiac.txt'


def main():

    # Parse input file
    stix_package = STIXPackage.from_xml(FILENAME)

    # Convert STIXPackage to a Python 
    stix_dict = stix_package.to_dict()

    #Extract description from the indicator (suitable for indicator only)
    description = stix_dict["indicators"][0]["description"]
    # Convert the first STIXPackage dictionary into another STIXPackage via
    # the from_dict() method.
  
    # Pattern for domain / email and IP addresses
    raw_iocs = re.findall(r'[a-zA-Z0-9-\.]*\[\.?\@?\][a-zA-Z0-9-\.\[\.\@\]]*[-a-zA-Z0-9@:%_\+.~#?&//=]*', description)

    print(len(raw_iocs))


    for i in range(len(raw_iocs)):
        # Replace the on9 strings
        for on9string in on9strings:
            raw_iocs[i] = raw_iocs[i].replace(on9string, on9strings[on9string])
        # Import those IOCs into the array.
        if re.match(r'.*[@]+', raw_iocs[i]):
            iocs['email'].append(raw_iocs[i])
        elif re.match(r'.*[//].*', raw_iocs[i]):
            iocs['url'].append(raw_iocs[i])
        elif re.match(r'.*[a-zA-Z]', raw_iocs[i]):
            iocs['domain'].append(raw_iocs[i])


    #Extract hashes by their plugin
    for hash_extracted in iocextract.extract_hashes(description):
        iocs['hash'].append(hash_extracted)
    #Extract Yara rule
    for yara_extracted in iocextract.extract_yara_rules(description):
        iocs['yara'].append(yara_extracted)
    #Extract IP
    for ip_extracted in iocextract.extract_ips(description, refang=True):
        iocs['ip'].append(ip_extracted)
    

    for key in iocs:
        for item in iocs[key]:
            print(key + ":" + item)


if __name__ == '__main__':
    main()