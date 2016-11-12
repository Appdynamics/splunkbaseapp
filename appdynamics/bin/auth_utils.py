import os
import sys
import splunk.entity as entity
import splunk,re

def getSessionKey(sessionKey):
	# read session key sent from splunkd
	sk = sessionKey.strip()
	sessionKey = re.sub(r'sessionKey=', "", sk)

	if len(sessionKey) == 0:
		logger.error("Did not receive a session key from splunkd. Please enable passAuth in inputs.conf for this  script\n")
		sys.exit(2)
	return sessionKey
       

def getCredentials(sessionKey,myapp='appdynamics'):
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