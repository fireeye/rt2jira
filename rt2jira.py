#!/usr/bin/env python

from __future__ import print_function
from itertools import izip
from rtkit.resource import RTResource
from rtkit.authenticators import CookieAuthenticator
from rtkit.errors import RTResourceError
from rtkit import set_logging
from jira.client import JIRA
from jira.exceptions import JIRAError
from titlecase import titlecase
import time
import os
import pprint
import re
import sys
import logging
import ConfigParser
import syslog

# Initialize RT library logging
set_logging('error')
rt_logger = logging.getLogger('rtkit')

# Initialize app-level logging
logger = logging.getLogger('rt2jira')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(asctime)s %(name)s[%(process)s]: [%(levelname)s] - %(message)s', "%b %m %H:%M:%S"))
logger.addHandler(ch)

# Initialize factories
pp = pprint.PrettyPrinter(indent=4)

# Define helper functions
def rt_format_ticket_time(t):
    """
    Given a time struct representing the RT ticket's creation timestamp, this
    returns a formatted, printable version of this timestamp.

    :param t: the time struct of the RT ticket's creation timestamp 
    """
    return time.strftime("%a %b %d %H:%M:%S %Y", t)

def rt_parse_ticket_time(t):
    """
    Given a string representing the RT ticket's creation timestamp, this
    returns a parsed time struct version of this timestamp.

    :param t: the string of the RT ticket's creation timestamp 
    """
    return time.strptime(t, "%a %b %d %H:%M:%S %Y")

def rt_format_comment_time(t):
    """
    Given a time struct representing the RT ticket's comment timestamp, this
    returns a formatted, printable version of this timestamp.

    :param t: the time struct of the RT ticket's comment timestamp 
    """
    return time.strftime("%a %b %d %H:%M:%S %Y UTC", t)

def rt_parse_comment_time(t):
    """
    Given a string representing the RT ticket's comment timestamp, this
    returns a parsed time struct version of this timestamp.

    :param t: the string of the RT ticket's comment timestamp 
    """
    return time.strptime(t, "%Y-%m-%d %H:%M:%S")

def package(r):
    """
    Given an array of tuples, this function returns a dict of mapped
    key/value pairs.

    :param r: the array of tuples to process
    """
    keys, vals = zip(*r)
    k = iter(keys)
    v = iter(vals)
    d = dict(izip(k,v))
    return d

def config_get_dict(config, section, option):
    """
    Given a configuration section and option, fetch and parse the data
    as if it were a dict.  Return the resultant data as a dict.

    :param config: the parsed configuration object
    :param section: the section to extract
    :param option: the option to parse
    """
    fields_raw = config.get(section, option)
    ret_fields = {}
    if fields_raw:
        regex_iter = re.finditer('\("([a-zA-Z0-9_]*)", "([a-zA-Z0-9_\.\ ]*)"\)', fields_raw)
        fields = [(c.group(1), c.group(2)) for c in regex_iter]
        ret_fields = package(fields)
 
    return ret_fields

def find_id_range(jira_issue):
    """
    Given an existing JIRA ticket, search the ticket and extract out
    all corresponding RT ticket IDs referenced in the description and
    comments of the JIRA ticket.  Then, return an array indicating
    the smallest and largest IDs found in this ticket.

    :param jira_issue: the JIRA issue to search
    """
    ret = None
    regex = re.compile('Ticket ID: (.*)\n')
    match = regex.search(jira_issue.fields.description)

    if match and len(match.groups()) >= 1:
        id_list = set([ int(match.group(1).strip()) ])
        jira_comments = jira.comments(jira_issue)
        for comment in jira_comments:
            match = regex.search(comment.body)
            if match and len(match.groups()) >= 1:
                id_list.add(int(match.group(1).strip()))

        id_list = list(id_list)
        id_list.sort()
        ret = [ id_list[0], id_list[-1] ]

    return ret

def resolve(jira_issue, resolution_name, resolve_comment):
    """
    Given a JIRA ticket, mark the ticket as resolved.

    :param jira_issue: the specified JIRA ticket
    :param resolution_name: the specified type of resolution for this ticket
    """
    state_name = config.get('jira', 'resolve_transition_name')
    state_id = None
    resolution_id = None

    for transition in jira.transitions(jira_issue):
        if state_name in transition['name']:
            state_id = transition['id']
            break

    for resolution in jira.resolutions():
        if resolution_name in resolution.name:
            resolution_id = resolution.id
            break

    if state_id and resolution_id:
        fields_dict = config_get_dict(config, 'jira', 'resolve_fields')
        fields_dict['resolution'] = { 'id': resolution_id }
        logger.info('Resolving ticket (' + jira_issue.key + ')')
        syslog.syslog(syslog.LOG_INFO, 'Resolving ticket (' + jira_issue.key + ')')
        jira.transition_issue(jira_issue, state_id, fields=fields_dict, comment=resolve_comment)

def reopen(jira_issue):
    """
    Given a JIRA ticket, mark the ticket as reopened.

    :param jira_issue: the specified JIRA ticket
    """
    state_name = config.get('jira', 'reopen_transition_name')
    state_id = None

    for transition in jira.transitions(jira_issue):
        if state_name in transition['name']:
            state_id = transition['id']
            break

    jira.transition_issue(jira_issue, state_id, comment=config.get('jira', 'reopen_comment'))

def find_user(rt_username, algo_type, project_keys):
    """
    Given an RT username, returns the corresponding JIRA username that best
    matches this user.  None is returned, otherwise.

    Two different algorithms are provided:

    0 - straight search in JIRA using the specified RT username
    1 - search in JIRA where RT usernames are <first_initial><last_name>
        and JIRA usernames are <first_name>.<last_name>

    :param rt_username: the RT username to use as initial search criteria
    :param algo_type: the algorithm type specified (0 or 1)
    :param project_keys: comma-separated list of project keys to check for issue assignment permissions
    """
    users = None
    if algo_type == 1:
        users = jira.search_assignable_users_for_projects(rt_username[1:], project_keys)
    else:
        users = jira.search_assignable_users_for_projects(rt_username, project_keys)

    regex = None
    if algo_type == 1:
        regex = re.compile('^' + rt_username[0] + '.*\.' + rt_username[1:] + '$', re.IGNORECASE)
    else:
        regex = re.compile('^' + rt_username + '$', re.IGNORECASE)

    ret_user = None
    for user in users:
        match = regex.search(user.name)
        if match:
            ret_user = user
            break

    return ret_user

# Read global configuration settings
config_file = 'config.ini'
config = ConfigParser.RawConfigParser(allow_no_value=True)
try:
    config.read([config_file])
except:
    logger.error("Can't parse " + config_file)
    syslog.syslog(syslog.LOG_ERR, "Can't parse " + config_file)
    sys.exit(1)

# Sanity check
try:
    if not config.getboolean('sanity', 'reviewed'):
        logger.error('Please review and change the ' + config_file + ' settings before running this script.')
        syslog.syslog(syslog.LOG_ERR, 'Please review and change the ' + config_file + ' settings before running this script.')
        sys.exit(1)
except:
    sys.exit(1)

# Check for debug setting.
try:
    if not config.getboolean('sanity', 'debug'):
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
except:
    pass

# Initialize or restore RT state settings
stored_last_updated_activity = time.gmtime(0)
try:
    stored_last_updated_activity = rt_parse_ticket_time(config.get('rt', 'last_fetched_timestamp'))
except:
    logger.warn('Unable to parse feed timestamp - Defaulting to: ' + rt_format_ticket_time(stored_last_updated_activity) + ' UTC')
    syslog.syslog(syslog.LOG_WARNING, 'Unable to parse feed timestamp - Defaulting to: ' + rt_format_ticket_time(stored_last_updated_activity) + ' UTC')

# Initialize web services
# Source RT Feed
resource = None
feed = None
try:
    resource = RTResource(config.get('rt', 'api_url_prefix'), config.get('rt', 'username'), config.get('rt', 'password'), CookieAuthenticator)
    feed = resource.get(path=config.get('rt', 'api_search_suffix'))
except RTResourceError as e:
    logger.error('Cannot connect to RT server')
    syslog.syslog(syslog.LOG_ERR, 'Cannot connect to RT server')
    logger.error(e.response.status_int)
    syslog.syslog(syslog.LOG_ERR, e.response.status_int)
    logger.error(e.response.status)
    syslog.syslog(syslog.LOG_ERR, e.response.status)
    logger.error(e.response.parsed)
    syslog.syslog(syslog.LOG_ERR, e.response.parsed)
    sys.exit(1)
except:
    logger.error('Cannot connect to RT server')
    syslog.syslog(syslog.LOG_ERR, 'Cannot connect to RT server')
    sys.exit(1)

# Destination JIRA Service
jira = None
try:
    jira = JIRA(options={'server': config.get('jira', 'api_url_prefix'), 'verify': config.getboolean('jira', 'verify')}, basic_auth=(config.get('jira', 'username'), config.get('jira', 'password')))
except JIRAError as e:
    logger.error("Unable to connect to JIRA server.")
    syslog.syslog(syslog.LOG_ERR, "Unable to connect to JIRA server.")
    logger.error(e.response.parsed)
    syslog.syslog(syslog.LOG_ERR, e.response.parsed)
    sys.exit(1)
except:
    logger.error("Unable to connect to JIRA server.")
    syslog.syslog(syslog.LOG_ERR, "Unable to connect to JIRA server.")
    sys.exit(1)

if __name__ == '__main__':

    # Process the most recent activity currently stored.
    logger.info('Starting - Feed Last Updated: ' + rt_format_ticket_time(stored_last_updated_activity) + ' UTC')
    syslog.syslog(syslog.LOG_NOTICE, 'Starting - Feed Last Updated: ' + rt_format_ticket_time(stored_last_updated_activity) + ' UTC')
    last_updated_activity = stored_last_updated_activity

    try:
        # For each ticket found in the source feed
        for e in feed.parsed:
            t = package(e)
            ticket_id = re.sub('ticket\/', '', t['id'])
            ticket_requester = re.sub('\@.*', '', t['Requestors'])
            ticket_requester_name = titlecase(re.sub('[0-9]', '', re.sub('\.', ' ', ticket_requester)))
            ticket_date = rt_parse_ticket_time(t['Created']) 
            ticket_last_updated = rt_parse_ticket_time(t['LastUpdated']) 
    
            # Scrub ticket title to remove 're:' and 'fw:' prefixes
            scrubbed_title = re.sub('^(?i)(re|fw|fwd):( |)', '', t['Subject'])
            #ticket_summary = ticket_requester_name + ': ' + scrubbed_title
            ticket_summary = scrubbed_title
            logger.info('Processing Ticket ID (' + ticket_id + ') - ' + ticket_summary)
            syslog.syslog(syslog.LOG_INFO, 'Processing Ticket ID (' + ticket_id + ') - ' + ticket_summary)
    
            # If stored timestamp is more recent than the comment, then skip processing the comment.
            if stored_last_updated_activity >= ticket_last_updated:
                logger.debug('RT ticket older than stored timestamp, skipping')
                syslog.syslog(syslog.LOG_DEBUG, 'RT ticket older than stored timestamp, skipping')
                continue

            sanitized_summary = re.sub('[^0-9A-Za-z\.\- ]', ' ', ticket_summary)
            sanitized_summary = ' '.join([item.strip() for item in sanitized_summary.split(' ') if len(item) > 3])
            sanitized_summary = re.sub('--', '', sanitized_summary)
            sanitized_summary = re.sub(' -', ' ', sanitized_summary)
    
            jira_results = None
            if sanitized_summary:
                logger.debug('JQL Search Terms: ' + sanitized_summary)
                syslog.syslog(syslog.LOG_DEBUG, 'JQL Search Terms: ' + sanitized_summary)
    
                # Check if JIRA ticket already exists.
                jira_results = jira.search_issues('project = ' + config.get('jira', 'project') + ' AND component = "' + config.get('jira', 'component') + '" AND summary ~ "' + sanitized_summary + '" ORDER BY created ASC')
            else:
                # If the sanitized summary is empty, then search specifically for the Ticket ID reference in the JIRA ticket description.
                description = 'Ticket ID: ' + ticket_id
    
                logger.debug('JQL Search Terms: ' + sanitized_summary)
                syslog.syslog(syslog.LOG_DEBUG, 'JQL Search Terms: ' + sanitized_summary)
    
                # Check if JIRA ticket already exists.
                jira_results = jira.search_issues('project = ' + config.get('jira', 'project') + ' AND component = "' + config.get('jira', 'component') + '" AND description ~ "' + description + '" ORDER BY created ASC')
    
            # Check if at least one matching JIRA ticket exists.
            jira_issue = None
            if jira_results:
                # Iterate through the resuling JIRA ticket search results
                # Find the first JIRA ticket where the ticket IDs listed in the ticket are within +/- 10 of the RT ticket ID
                for result in jira_results:
                    id_range = find_id_range(result)
                    original_id = int(ticket_id)
                    id_correlation_range = config.getint('rt', 'ticket_id_correlation_range')
                    if (((id_range[0] - id_correlation_range) <= original_id) and (original_id <= (id_range[-1] + id_correlation_range))):
                        jira_issue = result
                        break

                if jira_issue:
                    logger.info('Found existing JIRA ticket (' + jira_issue.key + ')')
                    syslog.syslog(syslog.LOG_INFO, 'Found existing JIRA ticket (' + jira_issue.key + ')')
    
            if not jira_issue:
                # If there's no match, then create a new JIRA ticket.
                ticket_description = 'Ticket ID: ' + ticket_id + '\n' + config.get('rt', 'url_ticket_display_prefix') + ticket_id + '\nTitle: ' + scrubbed_title + '\nRequester: ' + ticket_requester_name  + '\nCreated Date: ' + rt_format_ticket_time(ticket_date)
                jira_issue = jira.create_issue(project={'key':config.get('jira', 'project')}, summary=ticket_summary, description=ticket_description, issuetype={'name':'Bug'}, components=[{'name':config.get('jira', 'component')}])
                logger.info('Creating new JIRA ticket (' + jira_issue.key + ')')
                syslog.syslog(syslog.LOG_INFO, 'Creating new JIRA ticket (' + jira_issue.key + ')')
    
                user = find_user(ticket_requester, config.getint('jira', 'find_user_algo_type_description'), config.get('jira', 'find_user_projects'))
                if user:
                    # Make the ticket requester the reporter of the JIRA ticket.
                    logger.debug('Making (' + user.name + ') the reporter of (' + jira_issue.key + ')')
                    syslog.syslog(syslog.LOG_DEBUG, 'Making (' + user.name + ') the reporter of (' + jira_issue.key + ')')
                    jira_issue.update(fields={'reporter':{'name': user.name}})
    
                    # Auto-add ticket requester as watcher to the JIRA ticket.
                    logger.debug('Adding (' + user.name + ') as a watcher to (' + jira_issue.key + ')')
                    syslog.syslog(syslog.LOG_DEBUG, 'Adding (' + user.name + ') as a watcher to (' + jira_issue.key + ')')
                    jira.add_watcher(jira_issue, user.name)
                else:
                    logger.warn('Unable to find equivalent RT requester in JIRA: ' + ticket_requester)
                    syslog.syslog(syslog.LOG_WARNING, 'Unable to find equivalent RT requester in JIRA: ' + ticket_requester)
    
            # Next, obtain all current comments on the JIRA ticket. 
            jira_comments = jira.comments(jira_issue)
    
            # Finally, loop through all non-system comments currently associated to the RT ticket.
            rt_response = resource.get(path='ticket/'+ticket_id+'/history?format=l')
            for r in rt_response.parsed:
                c = package(r)
                comment_date = rt_parse_comment_time(c['Created']) 
    
                # Skip system comments.
                if c['Creator'] == 'RT_System':
                    continue
    
                # If stored timestamp is more recent than the comment, then skip processing the comment.
                if stored_last_updated_activity >= comment_date:
                    logger.debug('RT comment older than stored timestamp, skipping')
                    syslog.syslog(syslog.LOG_DEBUG, 'RT comment older than stored timestamp, skipping')
                    continue
                elif comment_date > last_updated_activity:
                    # If the comment timestamp is more recent than the current timestamp of most recent activity,
                    # then update the current timestamp of most recent activity.
                    last_updated_activity = comment_date
    
                # Check to see if the comment already exists in the JIRA ticket.
                comment_creator = re.sub('\@.*', '', c['Creator'])
                comment_uuid = 'Date: ' + rt_format_comment_time(comment_date) + '\nFrom: ' + comment_creator
    
                comment_exists = False
                for existing_comment in jira_comments:
                    logger.debug('Searching (' + jira_issue.key + ') comment (' + existing_comment.id + ')')
                    syslog.syslog(syslog.LOG_DEBUG, 'Searching (' + jira_issue.key + ') comment (' + existing_comment.id + ')')
                    if comment_uuid in existing_comment.body:
                        comment_exists = True
                        logger.debug('RT comment already exists, skipping')
                        syslog.syslog(syslog.LOG_DEBUG, 'RT comment already exists, skipping')
                        break
    
                if not comment_exists:
                    logger.info('Adding new comment to (' + jira_issue.key + ') from (' + comment_creator + ') on (' + rt_format_comment_time(comment_date) + ')')
                    syslog.syslog(syslog.LOG_INFO, 'Adding new comment to (' + jira_issue.key + ') from (' + comment_creator + ') on (' + rt_format_comment_time(comment_date) + ')')
                    comment_body = 'Date: ' + rt_format_comment_time(comment_date) + '\nFrom: ' + c['Creator'] + '\nTicket ID: ' + ticket_id + '\nAction: ' + c['Description'] + '\n\n' + c['Content']
                    # JIRA can't store comments more than 32,000 chars in length
                    truncated_comment = (comment_body[:31997] + '...') if len(comment_body) > 32000 else comment_body
                    new_comment = jira.add_comment(jira_issue, truncated_comment)
    
                    user = find_user(comment_creator, config.getint('jira', 'find_user_algo_type_comment'), config.get('jira', 'find_user_projects'))
                    if user:
                        # Auto-add ticket commenter as watcher to the JIRA ticket.
                        logger.debug('Adding (' + user.name + ') as a watcher to (' + jira_issue.key + ')')
                        syslog.syslog(syslog.LOG_DEBUG, 'Adding (' + user.name + ') as a watcher to (' + jira_issue.key + ')')
                        jira.add_watcher(jira_issue, user.name)
                    else:
                        logger.debug('Unable to find equivalent RT commenter in JIRA: ' + comment_creator)
                        syslog.syslog(syslog.LOG_DEBUG, 'Unable to find equivalent RT commenter in JIRA: ' + comment_creator)
    
                    # Assign ticket, if RT ticket was taken.
                    if 'Taken by' in c['Description']:
                        ticket_owner = re.sub('Taken by ', '', c['Description'])
                        user = find_user(ticket_owner, config.getint('jira', 'find_user_algo_type_comment'), config.get('jira', 'find_user_projects'))
                        if user:
                            logger.debug('Making (' + user.name + ') the assignee of (' + jira_issue.key + ')')
                            syslog.syslog(syslog.LOG_DEBUG, 'Making (' + user.name + ') the assignee of (' + jira_issue.key + ')')
                            jira_issue.update(fields={'assignee':{'name': user.name}})
                        else:
                            logger.warn('Unable to find equivalent RT owner in JIRA: ' + ticket_owner)
                            syslog.syslog(syslog.LOG_WARNING, 'Unable to find equivalent RT owner in JIRA: ' + ticket_owner)
    
                    if 'Given to' in c['Description']:
                        ticket_owner = re.sub('Given to (\w+) by.*', '\\1', c['Description'])
                        user = find_user(ticket_owner, config.getint('jira', 'find_user_algo_type_comment'), config.get('jira', 'find_user_projects'))
                        if user:
                            logger.debug('Making (' + user.name + ') the assignee of (' + jira_issue.key + ')')
                            syslog.syslog(syslog.LOG_DEBUG, 'Making (' + user.name + ') the assignee of (' + jira_issue.key + ')')
                            jira_issue.update(fields={'assignee':{'name': user.name}})
                        else:
                            logger.warn('Unable to find equivalent RT owner in JIRA: ' + ticket_owner)
                            syslog.syslog(syslog.LOG_WARNING, 'Unable to find equivalent RT owner in JIRA: ' + ticket_owner)
    
                    # Resolve the ticket if it was resolved in RT.
                    if 'resolved' in c['Description']:
                        resolve(jira_issue, config.get('jira', 'resolve_resolution_name'), config.get('jira', 'resolve_comment'))
    
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
    
    # Update the RT feed timestamp
    try:
        config.set('rt', 'last_fetched_timestamp', rt_format_ticket_time(last_updated_activity))
        with open(config_file, 'wb') as config_output:
            config.write(config_output)
    
        logger.info('Done - Feed Last Updated: ' + config.get('rt', 'last_fetched_timestamp')  + ' UTC')
        syslog.syslog(syslog.LOG_NOTICE, 'Done - Feed Last Updated: ' + config.get('rt', 'last_fetched_timestamp')  + ' UTC')
    except:
        pass
