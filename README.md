# WORDPRESS UPDATES AND VULNERABILITIES #

Script to be executed in command line that checks for core, plugin or themes updates and vulnerabilities.

## Description ##
Loads wp environment and uses environment vars to set settings.

Vulnerabilities are check agains https://wpvulndb.com/ and Change log.

This script forces the checks, does not depend on the wp_cron.

To properly functions user the following env vars:

    XTOKEN -  An md5 encripted string of the wp prefix to verify that we can safetly run this script.

        Example:
            export XTOKEN=`echo -n "wp_prefix_" | openssl md5 | sed 's/^. //'`

    XCHANNELS - a valid json string that holds the slack channels to send notifications.
        info channel(s) -  will be user to send any information.
        fire channel(s) -  will be user to send any vulnerability.

        Example:
               export XCHANNELS='{"info":["notification-channel"],"fire":["emergency-channel"]}'

    XNOTIFY_USERS ( Optional ) - A valid json string that will hold slack user id's slack of
       users that need to be notified.

        Example:
           export XNOTIFY='{"info":["userid1","userid2"],"fire":["userid1"]}'

    XSLACK ( Optional ) - Webhook URL. Only uses one webhook to send to different channels.

        Example:
             export XSLACK_ENDPOINT='https://hooks.slack.com/services/XXXXX/XXXXXXX'

    XJIRA ( Optional )- Jira: jenkins Build id, project, labels and url.

            Example:
                export XJIRA='{"project":"XXX","labels":["XXX"],"url":"https://XXX.atlassian.net/rest/api/latest/issue","progress_transition_id":"21"}'


## Installation ##

Download program in the root of wp core of the site.

Example of how to run script in command line:

  export XTOKEN=`echo -n "wp_prefix_" | openssl md5 | sed 's/^. //'`

  export XCHANNELS='{"info":["notification-channel"],"fire":["emergency-channel"]}'

  export XNOTIFY_USERS='{"info":["userid1","userid2"],"fire":["userid1"]}'

  export XSLACK='https://hooks.slack.com/services/XXXXX/XXXXXXX'

  export XJIRA='{"project":"XXX","labels":["XXX"],"server":"http://myjira.com","progress_transition_id":"4","user":"XXX","pwd":"XXX","assignee":"admin"}


  php xno-updates-vulnerabilities.php


## Screenshots ##


## Changelog ##

### 1.0 ###
 Initial revision as part of Xeno Media projects.
