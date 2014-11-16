#!/usr/bin/env python

import sys
import re
from rt2jira import jira, config, pp, logger, JIRAError, syslog, resolve

rt2jira_regex = re.compile('From: rt2jira\n')
action_regex = re.compile('Action: (.*)\n')
tid_regex = re.compile('Ticket ID: (.*?)(\r|)\n')

# Get the set of tickets that have been inactive for a set amount of time.
jira_results = jira.search_issues('project = ' + config.get('jira', 'project') + ' AND component = "' + config.get('jira', 'component') + '" AND status in ("Open") AND createdDate <= startOfDay(-' + config.get('jira', 'auto_resolve_after_days') + 'd) ORDER BY created ASC', maxResults=False)

try:
    for jira_issue in jira_results:
        logger.info('Processing Ticket (' + jira_issue.key + ')')
        syslog.syslog(syslog.LOG_INFO, 'Processing Ticket (' + jira_issue.key + ')')

        # Next, obtain all current comments on the JIRA ticket. 
        jira_comments = jira.comments(jira_issue)

        ticket_acted_upon = False
        for existing_comment in jira_comments:
            action_match = action_regex.search(existing_comment.body)
            tid_match = tid_regex.search(existing_comment.body)

            ticket_id = None
            if tid_match and (len(tid_match.groups()) >= 1):
                ticket_id = tid_match.group(1)

            if jira_issue.fields.assignee:
                ticket_acted_upon = True
                break

            elif (not rt2jira_regex.search(existing_comment.body)) and action_match and (len(action_match.groups()) >= 1) and ('Correspondence added' in action_match.group(1) or 'Status changed' in action_match.group(1) or 'Taken by' in action_match.group(1) or (jira_issue.fields.customfield_16300 != ticket_id and 'Ticket created by' in action_match.group(1))):
                logger.info('Ticket (' + jira_issue.key + ') was acted upon')
                syslog.syslog(syslog.LOG_INFO, 'Ticket (' + jira_issue.key + ') was acted upon')
                ticket_acted_upon = True
                break

        if ticket_acted_upon:
            resolve(jira_issue, config.get('jira', 'resolve_resolution_name'), 'Auto resolving ticket after ' + config.get('jira', 'auto_resolve_after_days') + ' days, as it appears to be acted upon.  Please reopen if this ticket is still active.')
        else:
            resolve(jira_issue, 'Task Dropped', 'Task dropped due to inactivity after ' + config.get('jira', 'auto_resolve_after_days') + ' days.  Please reopen if further action is still required.')

except JIRAError as e:
    logger.error('JIRA processing error occurred.')
    syslog.syslog(syslog.LOG_ERR, 'JIRA processing error occurred.')
    logger.error(e)
    syslog.syslog(syslog.LOG_ERR, e)
    sys.exit(1)
except:
    logger.error('Unknown processing error occurred.')
    syslog.syslog(syslog.LOG_ERR, 'Unknown processing error occurred.')
    sys.exit(1)

