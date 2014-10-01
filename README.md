# rt2jira.py #
Converts RT tickets to JIRA tickets

## Author ##

Darien Kindlund (darien.kindlund@fireeye.com)

## Description ##

This Python script automatically convert RT tickets to JIRA tickets, where the uniqueness of the RT ticket is based on the (requestor identity, subject) of the RT ticket, which will then get assigned a unique JIRA ticket.

## Prerequisities ##

    pip install six
    pip install jira
    pip install python-rtkit
    pip install titlecase

