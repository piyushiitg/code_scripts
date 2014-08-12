#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#
import json

import idb.log as log
import idb.util as util

# Initialize logging
_logger = log.get_logger("lib.events", relative_name=True)

# The configuration file for USER_CREDS_MONITOR service
LB_DB_FILE = "/system/lb.sqlite"
MAX_RETRY = 10

class Event(object):
    """Event class which will help to send to iDB.
    """

    def send_event(self, message, event_type, priority = '1'):
        """This method will be used to send the events
            :param message: message to be send in the event_type.
            :param event_type: Event type eg 11.
            :param priority: Priority of the event to be send.

        """
        args_dict = dict(apikey = util.get_apikey(db_name = LB_DB_FILE),
                            message = message,
                            type = event_type,
                            priority = priority)

        response = util.execute_api(method='POST', url='/events', data=args_dict)
        _logger.info("Response of sending event %s" % response)
        return response


    def del_event(self, message_type, eventid):
        """This method will be used to del the events
                :param event_type: Event type eg 11.

            """
        try:
            args_dict = dict(apikey = util.get_apikey(db_name = LB_DB_FILE))
            response = util.execute_api(method='DELETE', url='/events/reset/%s' % eventid, data=args_dict)
            if isinstance(response, dict) and response.get('success'):
                response = util.execute_api(method='DELETE', url='/events/reset/%s' % eventid, data=args_dict)
                _logger.info("Response of deleting event %s" % response)
                return True, response
        
            _logger.info("Error in  deleting event %s" % response)
            return False, response
        except Exception, ex:
            return False , ex



