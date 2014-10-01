# rt2jira.py #
Converts RT tickets to JIRA tickets

## Author ##

Darien Kindlund (darien.kindlund@fireeye.com)

## Description ##

This Python script automatically convert RT tickets to JIRA tickets, where the uniqueness of the RT ticket is based on the (requestor identity, subject) of the RT ticket, which will then get assigned a unique JIRA ticket.  This script will also synchronize new comments on existing RT tickets and represent them as new JIRA comments.  **However**, this script is a 1-way sync.  It will **not** take new JIRA comments/tickets and represent that activity in new/existing RT tickets.

## Prerequisites ##

    pip install six
    pip install jira
    pip install python-rtkit
    pip install titlecase

## Quick Start ##

1. Get all prerequisite libraries installed.

2. Download and extract the rt2jira package.

3. Edit and review the `config.ini` file.

4. Run: `python rt2jira.py`

5. Rerun the script as often as you want the RT queue and the JIRA tickets synchronized

## config.ini Notes ##

The following are comments on some of the INI settings.

**NOTE**: Please review all settings in the config.ini file **before** running the script.

### [rt] ###
* `api_url_prefix`: This is the URL for the RT REST API.  Traditionally, it should look something like:
    `https://rt.server.com/REST/1.0/`

* `api_search_suffix`: Search query to feed into the REST API to pull relevant tickets down to be ported as JIRA tickets.

    For example, if this value is set to something like:
    `search/ticket?query=Queue+%3D+%27RT-Queue-Name%27+AND+LastUpdated+%3E+%27-5+days%27&orderby=LastUpdated&format=l`

    Then, the script will be making a REST API query that looks something like this:
    `https://rt.server.com/REST/1.0/search/ticket?query=Queue+%3D+%27RT-Queue-Name%27+AND+LastUpdated+%3E+%27-5+days%27&orderby=LastUpdated&format=l`

    Where the RT Queue name in this instance is **RT-Queue-Name** and this query polls all RT tickets that were updated in the past **5** days.

* `url_ticket_display_prefix`: The URL prefix to display RT tickets, given a Ticket ID.

    For example if this value is set to something like:
    `https://rt.server.com/Ticket/Display.html?id=`

    Then, if the script processes a Ticket ID (42), it will append that number to the end of the URL when creating the corresponding JIRA ticket, like:
    `https://rt.server.com/Ticket/Display.html?id=42`

* `last_fetched_timestamp`: If running the script for the first time, leave this value blank.  If you want to have the script re-process older RT tickets, you can clear out this value and increase the **5** day value in the search query URI listed in `api_search_suffix`.

### [jira] ###

* `api_url_prefix`: This is the URL of JIRA web interface.

* `project`: When a new JIRA ticket is created by the script, it will be added to the specified project.

* `component`: When a new JIRA ticket is created by the script, it will be added with the specified component.

### [sanity] ###

* `reviewed`: You have to change this setting from **False** to **True** once all other INI settings are defined.

## TODO ##

* ~~Syslog support~~
* Create links between related JIRA tickets
* Advance state tracking (meaning, when an RT ticket is resolved, then the correpsonding JIRA ticket should be resolved)
* Auto-add relevant watchers to the JIRA tickets
* Any attached files to RT tickets should also be attached to the JIRA ticket
* When a JIRA ticket is created, figure out some way to reply to the RT thread, indicating that a ticket has been created with the corresponding URL
