# rt2jira.py #
Converts RT tickets to JIRA tickets

## Author ##

Darien Kindlund (darien.kindlund@fireeye.com)

## Description ##

This Python script automatically convert RT tickets to JIRA tickets, where the uniqueness of the RT ticket is based on the (requestor identity, subject) of the RT ticket, which will then get assigned a unique JIRA ticket.  This script will also synchronize new comments on existing RT tickets and represent them as new JIRA comments.  *However*, this script is a 1-way sync.  It will *not* take new JIRA comments/tickets and represent that activity in new/existing RT tickets.

## Prerequisites ##

    pip install six
    pip install jira
    pip install python-rtkit
    pip install titlecase

## Quick Start ##

0. Get all prerequisite libraries installed.

1. Download the rt2jira package.

2. Edit and review the config.ini file.

3. Run: ``python rt2jira.py``

## config.ini Settings ##


