#!/usr/bin/env python

import sys
import re
from urllib import quote_plus
from rt2jira import jira, resource, config, pp, logger, JIRAError, syslog, config_get_dict, RTResourceError

def reply_to_rt_requestors(rt_resource, rt_ticket_id, rt_requestors, rt_message):
    """
    Given an RT ticket ID, a list of RT requestors, and a response message,
    send a private email to the requestors with the provided message.
    The message will be recorded in RT, but will not be sent to any other 
    watchers of the queue.

    :param rt_resource: the RTResource object to use
    :param rt_ticket_id: the ticket ID as it appears in RT
    :param rt_requestors: the list of original RT ticket requestors to email
    :param rt_message: the message to reply back to them about
    """
    params = {
        'content': {
            'Action': 'comment',
            'Text': rt_message,
            'Cc': rt_requestors,
            'Bcc': '',
        },
    }
    response = rt_resource.post(path='ticket/' + rt_ticket_id + '/comment', payload=params,)
    return response

def format_search_results(jira_results):
    """
    Given a list of JIRA results, output a printable lists of these results
    in an acceptable form for email notifications.
    
    :param jira_results: the list of JIRA tickets to format
    """
    output = ""
    for result in jira_results:
        template = '[%(issue_key)s] - %(issue_summary)s - [%(issue_status)s]\n%(jira_url_prefix)s/browse/%(issue_key)s\n'
        entry = template % {"jira_url_prefix": config.get('jira', 'jira_url_prefix'), "issue_key": result.key, "issue_summary": result.fields.summary, "issue_status": result.fields.status}
        output = output + '\n' + entry

    return output

# Requestor regex format.
from_regex = re.compile('From: (.*?\@FireEye\.com)(\r|)\n')

# KB Notified regex format.
kb_notified_regex = re.compile('KB Notified: (.*?\@FireEye\.com)(?:\r|)(?:\n|)')

# Get the set of tickets that require an auto reply.
jira_results = jira.search_issues('project = ' + config.get('jira', 'project') + ' AND component = "' + config.get('jira', 'component') + '" AND labels in ("' + config.get('jira', 'new_issue_label') + '", "' + config.get('jira', 'new_comment_label') + '") ORDER BY created ASC', maxResults=False)

try:
    for jira_issue in jira_results:
        logger.info('Processing JIRA Ticket (' + jira_issue.key + ')')
        syslog.syslog(syslog.LOG_INFO, 'Processing JIRA Ticket (' + jira_issue.key + ')')

        # Get the original RT ticket ID.
        ticket_id = None
        fields_dict = config_get_dict(config, 'jira', 'create_fields')
        if fields_dict != {}:
            for k,v in fields_dict.iteritems():
                try:
                    if 'ticket_id' in v:
                        ticket_id = eval('jira_issue.fields.' + k)
                except:
                    continue

        if not ticket_id:
            logger.warn('Unable to find equivalent RT ticket ID in JIRA: ' + jira_issue.key)
            syslog.syslog(syslog.LOG_WARNING, 'Unable to find equivalent RT ticket ID in JIRA: ' + jira_issue.key)
            continue

        logger.info('RT Ticket ID (' + ticket_id + ') - ' + jira_issue.fields.summary)
        syslog.syslog(syslog.LOG_INFO, 'RT Ticket ID (' + ticket_id + ') - ' + jira_issue.fields.summary)

        # Next, obtain all current comments on the JIRA ticket. 
        jira_comments = jira.comments(jira_issue)
        # Search for any external comments on the ticket.
        requestors = set()
        notified = set()
        for existing_comment in jira_comments:
            from_match = from_regex.search(existing_comment.body)
            notified_match = kb_notified_regex.findall(existing_comment.body)

            if from_match and (len(from_match.groups()) >= 1):
                requestors.add(from_match.group(1))

            if notified_match and (len(notified_match) >= 1):
                map(notified.add, notified_match)

        # Collect the set of people who have already been notified.
        requestors = map(str, list(requestors))
        notified = map(str, list(notified))
        if len(notified) > 0:
            notified_addresses = ', '.join(list(notified))
            logger.debug('Already notified (' + notified_addresses + ') for JIRA ticket (' + jira_issue.key + ')')
            syslog.syslog(syslog.LOG_DEBUG, 'Already notified (' + notified_addresses + ') for JIRA ticket (' + jira_issue.key + ')')

        # Filter the set of already notified people out of the set of people who still need to be notified.
        requestors = set(requestors) - set(notified)

        # Look for related tickets.
        sanitized_summary = re.sub('[^0-9A-Za-z\.\- ]', ' ', jira_issue.fields.summary)
        sanitized_summary = ' '.join([item.strip() for item in sanitized_summary.split(' ') if len(item) > 3])
        sanitized_summary = re.sub('--', '', sanitized_summary)
        sanitized_summary = re.sub(' -', ' ', sanitized_summary)
    
        related_jira_query = None
        related_jira_results = None
        if sanitized_summary:
            logger.debug('JQL Search Terms: ' + sanitized_summary)
            syslog.syslog(syslog.LOG_DEBUG, 'JQL Search Terms: ' + sanitized_summary)
   
            # Check if JIRA ticket already exists.
            related_jira_query = 'key != ' + jira_issue.key + ' AND project = ' + config.get('jira', 'project') + ' AND component = "' + config.get('jira', 'component') + '" AND summary ~ "' + sanitized_summary + '" ORDER BY updated DESC'
            related_jira_results = jira.search_issues('level IS EMPTY AND ' + related_jira_query, maxResults=config.getint('jira', 'auto_reply_max_results'))
        else:
            # If the sanitized summary is empty, then search specifically for the Ticket ID reference in the JIRA ticket description.
            description = 'Ticket ID: ' + ticket_id

            # If the ticket_summary was completely empty, then create an artificial one.
            if not ticket_summary:
                ticket_summary = description
    
            logger.debug('JQL Search Terms: ' + description)
            syslog.syslog(syslog.LOG_DEBUG, 'JQL Search Terms: ' + description)
    
            # Check if JIRA ticket already exists.
            related_jira_query = 'key != ' + jira_issue.key + ' AND project = ' + config.get('jira', 'project') + ' AND component = "' + config.get('jira', 'component') + '" AND description ~ "' + description + '" ORDER BY updated DESC'
            related_jira_results = jira.search_issues('level IS EMPTY AND ' + related_jira_query, maxResults=config.getint('jira', 'auto_reply_max_results'))

        # Recent search results.
        recent_jira_query = 'key != ' + jira_issue.key + ' AND project = ' + config.get('jira', 'project') + ' AND component = "' + config.get('jira', 'component') + '" ORDER BY created DESC'
        recent_jira_results = jira.search_issues('level IS EMPTY AND ' + recent_jira_query, maxResults=config.getint('jira', 'auto_reply_max_results'))

        # Construct message to send to the requestors.
        template_issue = jira.issue(config.get('jira', 'auto_reply_template_ticket'))
        if not template_issue:
            logger.error('Unable to find template issue specified: ' + config.get('jira', 'auto_reply_template_ticket'))
            syslog.syslog(syslog.LOG_ERR, 'Unable to find template issue specified: ' + config.get('jira', 'auto_reply_template_ticket'))
            sys.exit(1)

        reply_message = template_issue.fields.description % {"jira_url_prefix": config.get('jira', 'jira_url_prefix'), "issue_key": jira_issue.key, "issue_summary": jira_issue.fields.summary, "related_results": format_search_results(related_jira_results), "recent_results": format_search_results(recent_jira_results), "related_query": quote_plus(related_jira_query), "recent_query": quote_plus(recent_jira_query)}

        if len(requestors) > 0:
            cc_addresses = ', '.join(list(requestors))
            logger.debug('Sending auto-reply to (' + cc_addresses + ') for JIRA ticket (' + jira_issue.key + ')')
            syslog.syslog(syslog.LOG_DEBUG, 'Sending auto-reply to (' + cc_addresses + ') for JIRA ticket (' + jira_issue.key + ')')
            reply_to_rt_requestors(resource, ticket_id, cc_addresses, reply_message)

            kb_tracking_prefix = lambda x: 'KB Notified: ' + x
            kb_tracking_comment = '\n'.join(map(kb_tracking_prefix, requestors))
            logger.info('Adding new comment to (' + jira_issue.key + ') to track existing notifiers (' + cc_addresses + ')')
            syslog.syslog(syslog.LOG_INFO, 'Adding new comment to (' + jira_issue.key + ') to track existing notifiers (' + cc_addresses + ')')
            new_comment = jira.add_comment(jira_issue, kb_tracking_comment)

        # Remove the labels from processed tickets.
        logger.info('Removing auto-reply label(s) in JIRA ticket (' + jira_issue.key + ')')
        syslog.syslog(syslog.LOG_INFO, 'Removing auto-reply label(s) in JIRA ticket (' + jira_issue.key + ')')

        try:
            jira_issue.fields.labels.remove(config.get('jira', 'new_issue_label'))
            jira_issue.fields.labels.remove(config.get('jira', 'new_comment_label'))
        except:
            pass

        jira_issue.update(fields={"labels": jira_issue.fields.labels})

except RTResourceError as e:
    logger.error('RT processing error occurred.')
    syslog.syslog(syslog.LOG_ERR, 'RT processing error occurred.')
    logger.error(e.response.status_int)
    syslog.syslog(syslog.LOG_ERR, e.response.status_int)
    logger.error(e.response.status)
    syslog.syslog(syslog.LOG_ERR, e.response.status)
    logger.error(e.response.parsed)
    syslog.syslog(syslog.LOG_ERR, e.response.parsed)
    sys.exit(1)
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

