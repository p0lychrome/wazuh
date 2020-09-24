#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.

import os
import sys
import socket
import logging
import struct
import json
import re


LICENSE = """
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License (version 2) as 
published by the Free Software Foundation. For more details, go to 
https://www.gnu.org/licenses/gpl.html """


class WazuhDeamonProtocol:
    def __init__(self, version="1", origin_module="wazuh-logtest", module_name="wazuh-logtest"):
        self.protocol = dict()
        self.protocol['version'] = 1
        self.protocol['origin'] = dict()
        self.protocol['origin']['name'] = origin_module
        self.protocol['origin']['module'] = module_name

    def wrap(self, command, parameters):
        msg=self.protocol
        msg['command']=command
        msg['parameters']=parameters
        return json.dumps(msg)

    def unwrap(self,msg):
        return json.loads(msg)['data']

class WazuhSocket:
    def __init__(self, file):
        self.file = file
    def send(self, msg):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(self.file)
        self.socket.send(struct.pack("<I", len(msg)) + msg.encode())
        size = struct.unpack("<I", self.socket.recv(4, socket.MSG_WAITALL))[0]
        recv_msg = self.socket.recv(size, socket.MSG_WAITALL)
        self.socket.close()
        return recv_msg

class WazuhLogtest:
    def __init__(self, location = "master->/var/log/syslog", log_format = "syslog"):
        self.protocol = WazuhDeamonProtocol()
        self.socket = WazuhSocket('/var/ossec/queue/ossec/logtest')
        self.fixed_fields = dict()
        self.fixed_fields['location']= location
        self.fixed_fields['log_format']= log_format

    def process_log(self, log, token=None):
        data = self.fixed_fields
        if token:
            data['token']=token
        data['event']=log
        request =  self.protocol.wrap('log_processing',data)
        recv_packet = self.socket.send(request)
        reply = self.protocol.unwrap(recv_packet)
        return reply

    def new_session(self):
        reply = self.process_log("test value")
        return reply['token']

if __name__ == "__main__":

    logtest = WazuhLogtest()
    FORMAT = '%(asctime)-15s %(module)s %(message)s'
    logging.basicConfig(format=FORMAT, level="INFO")
    logging.info('Starting...')
    logging.info('Type one log per line')
    session_token = logtest.new_session()
    while True:
        event = input()
        output = logtest.process_log(event,session_token)
        print(json.dumps(output,indent=2))










