
How To Use the AppDynamics App in Splunk

##What is AppDynamics?

[AppDynamics](http://www.appdynamics.com) is an application performance monitoring solution that helps you:
*Identify problems such as slow and stalled user requests and errors in a production environment.
*Troubleshoot and isolate the root cause of such problems by: 
*Mining performance data from AppDynamics and viewing it in Splunk using the AppDynamics Controller REST API. 
*Pushing notifications on policy violations and events from AppDynamics to Splunk so that a Splunk user can use those to launch deep dives in AppDynamics. See Getting Notifications From and Launching AppDynamics in Splunk.


##Installation

These instructions assume that you are familiar with using both AppDynamics and Splunk. 

Links within this file go to AppDynamics 4.2 documentation. If you are running an earlier version, use the Search feature to find the associated topics.

####Prerequisites


- You have installed AppDynamics version 4.0 or newer. If you do not already have a license, you can sign up for a [trial license]( https://portal.appdynamics.com/account/signup/signupForm/). You can choose either a SaaS solution or an On-Premise installation.
- You have installed Splunk version 6.x or newer.
- You have installed the AppDynamics App for Splunk from Splunkbase. 
- You have access to the following AppDynamics Controller information, which is required to set up the integration: 
   - hostname/IP address
   - port number
   - account name
   - user name
   - password
   
    If you use a SaaS account, AppDynamics provides you with the required information.
- You have access to the [AppDynamics documentation](https://docs.appdynamics.com/display/PRO42/AppDynamics+Essentials). When you trial or buy the product, AppDynamics provides access credentials to you.
- $SPLUNK_HOME is set to the directory where Splunk is installed.

####Steps
1.  Install the appdynamics app from splunkbase and before restarting perform steps 2 and 3.
2.  Locate and edit the files: $SPLUNK_HOME/etc/apps/appdynamics/default/metrics.conf and $SPLUNK_HOME/etc/apps/appdynamics/default/events.conf
3.  In the metrics.conf file, add one section for each individual metric you want to mine from AppDynamics. You need the following:
    -   AppDynamics metric name, to name the section in the metrics.conf file, and for use as as unique identifier in Splunk
    -   REST URL of the metric from the AppDynamics Metric Browser, see the [AppDynamics REST documentation](https://docs.appdynamics.com/display/PRO42/Using+the+Controller+APIs)  (login required).
    -   polling interval - how frequently, in seconds, Splunk will run the script to get this metric

    For example, if you want to mine a metric called AverageResponseTime for the ViewCart.sendItems business transaction, the entry would be similar to this:
    
        [ViewCart.sendItems_AverageResponseTime]  
        url = http://<controller-host>:<port>/controller/rest/applications/Acme%20Online%20Book%20Store/metric-data?metricpath=Business%20Transaction%20Performance%7CBusiness%20Transactions%7CECommerce%7CViewCart.sendItems%7CAverage%20Response%20Time%20(ms)&time-range-type=BEFORE_NOW&duration-in-mins=15  
        interval = 60  
        
        
4.  In the events.conf file, add one section for each individual event type you want to mine from AppDynamics. You need the following:
    -   AppDynamics event type, to name the section in the events.conf file, specify the event query for the REST URL, and for use as as unique identifier in Splunk
    -   AppDynamics event severity, to specify the event query for the REST URL
    -   REST URL of the event type from the AppDynamics Metric Browser, see the [AppDynamics REST documentation](https://docs.appdynamics.com/display/PRO42/Alert+and+Respond+API#AlertandRespondAPI-RetrieveEventData)  (login required).
    -   polling interval - how frequently, in seconds, Splunk will run the script to get this metric

    For example, if you want to mine events caused by application changes, the entry would look similar to this:

        [Server.application_Changes]  
        url = http://<controller-host>:<port>/controller/rest/applications/Acme%20Online%20Book%20Store/events?time-range-type=BEFORE_NOW&duration-in-mins=15&event-types=APP_SERVER_RESTART,APPLICATION_CONFIG_CHANGE,APPLICATION_DEPLOYMENT&severities=INFO,WARN,ERROR  
        interval = 60  

5.  Restart splunk.
6.  You will be prompted to setup the AppDynamics App. Please click on setup and configure the AppDynamics credentials. Using this view, splunk will store AppDynamics credentials in encrypted mode.


##Splunk Indexes
For metrics, an index called "appdynamics" is created. 
For events, an index called "appdynamics_events" is created. 

##Metrics

1.  Launch the AppDynamics App in Splunk.
2.  Enter index=appdynamics in the Search field of the AppDynamics App in Splunk.  

![AppDMetricsOnSplunk.png](100353)

##Events

1.  Launch the AppDynamics App in Splunk.
2.  Enter index=appdynamics_events in the Search field of the AppDynamics App in Splunk.  

![AppDEventsOnSplunk.PNG](120359)




####Cross App linking to AppDynamics

1.  Add the following field extraction section to your $SPLUNK_HOME/etc/apps/search/default/props.conf file:
    
		[source::http-simple]  
		EXTRACT-AppD = url="http[s]*://(?<nurl>[^"|]+)"
    	
2.  Add the following workflow action to your $SPLUNK_HOME/etc/apps/search/default/workflow_actions.conf file:
    
		[LaunchAppD]  
		display_location = both  
		fields = url  
		label = Launch in AppDynamics  
		link.method = get  
		link.target = blank  
		link.uri = http://$!nurl$  
		type = link

##Dependencies

The appdynamics splunkbase app depend on the open source library httplib2.    
    
####Custom Notifications in Splunk from AppDynamics

![AppDNotificationsOnSplunk.png](100352)

##Launching AppDynamics from Splunk

On an event in the Splunk Search App, click the blue pulldown and choose Launch in AppDynamics. See the screenshot above.


##Contributing

Always feel free to fork and contribute any changes directly via [GitHub](https://github.com/Appdynamics/splunkbaseapp)

##Community

Find out more in the [AppSphere](https://www.appdynamics.com/community/exchange/) community.

##Support

For any questions or feature request, please contact [AppDynamics Center of Excellence](mailto:help@appdynamics.com).

