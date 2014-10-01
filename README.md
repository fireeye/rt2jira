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

3. Edit and review the config.ini file.

4. Run: ``python rt2jira.py``

## config.ini Notes ##

**NOTE**: Please review all settings in the config.ini file **before** running the script.

### [rt] ###
1. `api_url_prefix`: This is the URL for the RT REST API.  Traditionally, it should look something like `https://rt.server.com/REST/1.0/`

2. `api_search_suffix`: Search query to feed into the REST API to pull relevant tickets down to be ported as JIRA tickets.

    For example, if this value is set to something like:
    `search/ticket?query=Queue+%3D+%27RT-Queue-Name%27+AND+LastUpdated+%3E+%27-5+days%27&orderby=LastUpdated&format=l`

    Then, the script will be making a REST API query that looks something like this:
    `https://rt.server.com/REST/1.0/search/ticket?query=Queue+%3D+%27RT-Queue-Name%27+AND+LastUpdated+%3E+%27-5+days%27&orderby=LastUpdated&format=l`

    Where the RT Queue name in this instance is **RT-Queue-Name** and this query polls all RT tickets that were updated in the past **5** days.

3. `url_ticket_display_prefix`: The URL prefix to display RT tickets, given a Ticket ID.

For example if this value is set to something like:
`https://rt.server.com/rt/Ticket/Display.html?id=`

Then, if the script processes a Ticket ID (42), it will append that number to the end of the URL when creating the corresponding JIRA ticket, like:
`https://rt.server.com/rt/Ticket/Display.html?id=42`

4. `last_fetched_timestamp`: If running the script for the first time, leave this value blank.  If you want to have the script re-process older RT tickets, you can clear out this value and increase the **5** day value in the search query URI listed in #2.

