#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#
import os
import smtplib
import idb.log as log

import ConfigParser

# Initialize logging
_logger = log.get_logger("lib.alerts", relative_name=True)

# The configuration file for DB_MONITOR service
IDB_DIR_ETC = '/opt/idb/conf'
ALERTS_CONF = 'alerts.conf'

def send_email(smtp_server, smtp_port, sender, receivers, subject, message, password):
    message = ("""From: %s 
To: %s
Subject: %s

%s
""") % (sender, receivers, subject, message)
     
    receivers_list = receivers.split(',')
    try:
        _logger.debug("Sending email to %s via: server:%s, port:%s" % 
            (receivers_list, smtp_server, smtp_port))
        #print "Sending email via: server:%s, port:%s" % (smtp_server,
        #     smtp_port)
        smtpObj = smtplib.SMTP(smtp_server, int(smtp_port))
        smtpObj.ehlo()
        if smtpObj.has_extn("starttls"):
            smtpObj.starttls()
            smtpObj.login(sender, password)
        smtpObj.sendmail(sender, receivers_list, message)
        smtpObj.close()
        _logger.info("Successfully sent email")
    except smtplib.SMTPException, ex:
        _logger.error("Error: unable to send email: %s" % (ex))


def get_smtp_config(config_file=ALERTS_CONF):
    # Read the configuration file
    config = getconfig_parser(config_file)
    if not config.has_section('smtp'):
        _logger.error("No smpt options specified in the config file %s" %
             (config_file))
        raise ConfigParser.NoSectionError

    smtp_server = config.get('smtp', 'smtp_server')
    smtp_port = config.get('smtp', 'smtp_port')
    sender = config.get('smtp', 'sender')
    receivers = config.get('smtp', 'receivers')
    message = config.get('smtp', 'message')
    subject = config.get('smtp', 'subject')
    password = config.get('smtp', 'password')
    return (smtp_server, smtp_port, sender, receivers, subject, message, password)


def getconfig_parser(config_file, options={ }):
    """Get a config parser for the given configuration file
    """
    if not os.path.isabs(config_file):
        config_file = IDB_DIR_ETC + '/' + config_file

    if not os.path.exists(config_file):
        raise Exception('File not found: %s' % config_file)

    # NOTE: Use SafeConfigParser instead of ConfigParser to support
    # escaping of format strings e.g. % as %%
    config = ConfigParser.SafeConfigParser(options)
    config.read(config_file)
    return config

if __name__ == "__main__":
    # Read the configuration file
    (smtp_server, smtp_port, sender, receivers, subject, message, password) = \
        get_smtp_config()
    send_email(smtp_server, smtp_port, sender, receivers, subject, message, password)
