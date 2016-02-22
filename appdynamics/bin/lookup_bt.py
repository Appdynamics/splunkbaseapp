#!/usr/bin/env python

# Copyright (C) 2012 AppDynamics, All Rights Reserved.  Version 3.5
from ConfigParser import ConfigParser
import json
import httplib2
import logging
import logging.handlers
import os
import sys
import csv
import sys


def lookup(url, username, password, logger):
    try:
        myhttp = httplib2.Http(disable_ssl_certificate_validation=True)
        myhttp.add_credentials(username, password)
        logger.debug('Requesting entities from url: %s' % url)
        response, content = myhttp.request(url, 'GET')
        logger.debug('Response: %s' % content)
        parsed = json.loads(content)
        for entity in parsed:
            logger.debug('Returning: %s' % entity['name'])
            return entity['name']
    except:
        return ''

def main():
    if len(sys.argv) != 4:
        print "Usage: python lookup.py [applicationId field] [BTId field] [BTName field]"
        sys.exit(1)

    # Setup logging
    logger = logging.getLogger('appdynamics_metrics')
    logger.propagate = False  # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fileHandler = logging.handlers.RotatingFileHandler(
        os.environ['SPLUNK_HOME'] + '/var/log/splunk/appdynamics_metrics.log', maxBytes=25000000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    applicationId = sys.argv[1]
    BT_Id = sys.argv[2]
    BT_Name = sys.argv[3]

    # read config
    conf = ConfigParser()
    conf.read([os.environ['SPLUNK_HOME'] + '/etc/apps/appdynamics/default/lookup.conf'])
    items = dict(conf.items('Controller'))

    username = items['username']
    password = items['password']

    infile = sys.stdin
    outfile = sys.stdout

    r = csv.DictReader(infile)
    header = r.fieldnames

    w = csv.DictWriter(outfile, fieldnames=r.fieldnames)
    w.writeheader()

    for result in r:
        if result[applicationId] and result[BT_Id] and result[BT_Name]:
            # both fields were provided, just pass it along
            logger.info('both fields were provided, just pass it along')
            w.writerow(result)

        elif result[applicationId] and result[BT_Id]:
            # only ids were provided, add name
            url = items['url']
            url += 'controller/rest/applications/'
            url += result[applicationId]
            url += '/business-transactions/'
            url += result[BT_Id]
            url += '?output=JSON'
            result[BT_Name] = lookup(url, username, password, logger)
            if result[BT_Name]:
                w.writerow(result)

main()



