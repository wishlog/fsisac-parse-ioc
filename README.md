# stix-to-ioc
Python script to parse IOC from FS-ISAC (STIX) feed

The iocextract script from InQuest does works well on extracting hashes and IPs.
However, email with [@] doesn't work. Also it were not able to extract domains.

This is a wrapper of https://github.com/InQuest/python-iocextract
