# Copyright (C) 2012 AppDynamics, All Rights Reserved.  Version 3.5
from ConfigParser import ConfigParser
import json
import httplib2
import threading
import logging
import logging.handlers
import os
import sys
import time
import datetime
import splunk.entity as entity
import splunk,re


class Metric(threading.Thread):
	def __init__(self, name, url, interval, username, password):
		self._interval = interval
		self._name = name
		self._url = url
		self._username = username
		self._password = password
		self._stopping = False
		self._event = threading.Event()

		threading.Thread.__init__(self)

	def run(self):
		while not self._event.is_set():
			try:
				myhttp = httplib2.Http(disable_ssl_certificate_validation=True)
				myhttp.add_credentials(self._username, self._password)
				url = self._url + '&output=JSON'
				logger.debug('Requesting metric from url: %s' % url)
				response, content = myhttp.request(url, 'GET')
				logger.debug('Response: %s' % content)
				parsed = json.loads(content)

				for metric in parsed:
					logger.debug('Processing metric [%s]' % metric['metricPath'])
					if not metric['metricValues']:
						logger.debug('No metrics available for [%s], defaulting to 0' % metric['metricPath'])
						output = datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S.%f") + " "
						output += 'name="%s" ' % self._name
						output += 'frequency=%s ' % metric['frequency']
						output += 'metricPath="%s" ' % metric['metricPath']
						output += 'value=0 '
						output += 'current=0 '
						output += 'min=0 '
						output += 'max=0 '

						out = globals()['out']
						out.debug(output)
					else:
						logger.debug('Metrics are available for [%s]' % metric['metricPath'])
						for metricValue in metric['metricValues']:
							output = datetime.datetime.fromtimestamp(metricValue['startTimeInMillis']/1000).strftime("%Y-%m-%d %H:%M:%S.%f") + " "
							output += 'name="%s" ' % self._name
							output += 'frequency=%s ' % metric['frequency']
							output += 'metricPath="%s" ' % metric['metricPath']
							output += 'value=%s ' % metricValue['value']
							output += 'current=%s ' % metricValue['current']
							output += 'min=%s ' % metricValue['min']
							output += 'max=%s ' % metricValue['max']

							out = globals()['out']
							out.debug(output)
			except Exception, e:
				import traceback

				stack = traceback.format_exc()
				logger.error("Exception received attempting to retrieve metric '%s': %s" % (self._name, e))
				logger.error("Stack trace for metric '%s': %s" % (self._name, stack))

			self._event.wait(self._interval)

	def stop(self):
		self._event.set()


# Copied from http://danielkaes.wordpress.com/2009/06/04/how-to-catch-kill-events-with-python/
def set_exit_handler(func):
	if os.name == "nt":
		try:
			import win32api

			win32api.SetConsoleCtrlHandler(func, True)
		except ImportError:
			version = ".".join(map(str, sys.version_info[:2]))
			raise Exception("pywin32 not installed for Python " + version)
	else:
		import signal

		signal.signal(signal.SIGTERM, func)
		signal.signal(signal.SIGINT, func)


def handle_exit(sig=None, func=None):
	print '\n\nCaught kill, exiting...'
	for metric in metrics:
		metric.stop()
	sys.exit(0)



def getMetrics():
	conf = ConfigParser()
	conf.read([os.environ['SPLUNK_HOME'] + '/etc/apps/appdynamics/default/metrics.conf'])
	#Getting the password 
	sessionKey = getSessionKey()
	username,password = getCredentials(sessionKey)
	#logger.info("Username and password are %s,%s" % (username,password))
	sections = conf.sections()

	metrics = []
	logger.info("Starting all the threads to fetch the metrics.")
	for section in sections:
		try:
			name = section
			items = dict(conf.items(section))
			url = items['url']
	
			if 'interval' not in items:
				interval = float(60)
			else:
				interval = float(items['interval'])

			metrics.append(Metric(name, url, interval, username, password))
		except Exception, e:
			logger.error("Parsing error reading metric '%s'.  Error: %s" % (section, e))

	return metrics

def getSessionKey():
	# read session key sent from splunkd
	sk = sys.stdin.readline().strip()
	sessionKey = re.sub(r'sessionKey=', "", sk)

	if len(sessionKey) == 0:
		logger.error("Did not receive a session key from splunkd. Please enable passAuth in inputs.conf for this  script\n")
		sys.exit(2)
	return sessionKey
       

def getCredentials(sessionKey):
	myapp = 'appdynamics'
	try:
      # list all credentials
		entities = entity.getEntities(['admin', 'passwords'], namespace=myapp, owner='nobody', sessionKey=sessionKey) 
	except Exception, e:
		raise Exception("Could not get %s credentials from splunk. Error: %s"% (myapp, str(e)))

	#logger.info("Entities %s" % entities)	
   
	for i, c in entities.items(): 
		if c['eai:acl']['app'] == myapp:
			return c['username'], c['clear_password']

	raise Exception("No credentials have been found")

if __name__ == '__main__':
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
	logger.info('AppDynamics Metrics Grabber started')

	out = logging.getLogger('appdynamics_out')
	formatter = logging.Formatter('%(message)s')
	handler = logging.handlers.RotatingFileHandler(
		filename=os.environ['SPLUNK_HOME'] + '/etc/apps/appdynamics/output/metrics.log', maxBytes=25000000,
		backupCount=5)
	handler.setFormatter(formatter)
	out.addHandler(handler)
	out.setLevel(logging.DEBUG)

	metrics = getMetrics()
	for metric in metrics:
		metric.start()

	set_exit_handler(handle_exit)
	while True:
		try:
			time.sleep(1)
		except KeyboardInterrupt:
			handle_exit()
