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


def lookup(id, url, username, password, logger):
    try:
        myhttp = httplib2.Http(disable_ssl_certificate_validation=True)
        myhttp.add_credentials(username, password)
        url += '?output=JSON'
        logger.debug('Requesting entities from url: %s' % url)
        response, content = myhttp.request(url, 'GET')
        logger.debug('Response: %s' % content)
        parsed = json.loads(content)
        for entity in parsed:
            if (id==str(entity['id'])):
                return entity['name']
    except:
        return ''

def main():
    if len(sys.argv) != 3:
        print "Usage: python lookup.py [applicationId field] [applicationName field]"
        sys.exit(1)

    # Setup logging
    logger = logging.getLogger('lookup_app')
    logger.propagate = False  # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    log_dir = os.environ['SPLUNK_HOME'] + '/var/log/splunk/appdynamics'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    fileHandler = logging.handlers.RotatingFileHandler(log_dir + '/lookup_app.log', maxBytes=25000000, backupCount=5)
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    applicationId = sys.argv[1]
    applicationName = sys.argv[2]


    # read config
    conf = ConfigParser()
    conf.read([os.environ['SPLUNK_HOME'] + '/etc/apps/appdynamics/local/lookup.conf'])
    items = dict(conf.items('Controller'))
    url = items['url']
    url += 'controller/rest/applications'
    
    #Getting the password 
    sessionKey = auth_utils.getSessionKey(sys.stdin.readline())
    username,password = auth_utils.getCredentials(sessionKey)

    infile = sys.stdin
    outfile = sys.stdout

    r = csv.DictReader(infile)
    header = r.fieldnames

    w = csv.DictWriter(outfile, fieldnames=r.fieldnames)
    w.writeheader()

    for result in r:
        if result[applicationId] and result[applicationName]:
            # both fields were provided, just pass it along
            logger.info('both fields were provided, just pass it along')
            w.writerow(result)

        elif result[applicationId]:
            # only id was provided, add name

            result[applicationName] = lookup(result[applicationId], url, username, password, logger)
            if result[applicationName]:
                w.writerow(result)

main()



