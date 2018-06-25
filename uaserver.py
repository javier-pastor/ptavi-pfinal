#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Programa User Agent Server (+ XML Handler + SIP Handler) que abre sesion SIP."""

import socketserver
import socket
import sys
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import hashlib
import os
import time


class XmlHandler(ContentHandler):

    def __init__(self):
        self.tags = {}

    def startElement(self, name, attrs):
        exist_atts = ['username', 'passwd', 'ip', 'puerto', 'path']
        exist_tags = ['account', 'uaserver', 'regproxy', 'rtpaudio',
                     'log', 'audio']
        for tag in exist_tags:
            if name == tag:
                atts_dic = {}
                for att in exist_atts:
                    if str(attrs.get(str(att))) != 'None':
                        atts_dic[str(att)] = attrs.get(str(att), "")
                self.tags[str(name)] = atts_dic

    def get_tags(self):
        return self.tags


def reg(line_to_write, config_data):
    """Event logging method."""
    with open(config_data['log']['path'], 'a') as log_file:
        hour = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
        line_to_write = hour + ' ' + line_to_write + '\r\n'
        log_file.write(line_to_write)
        log_file.close()

class SIPServerHandler(socketserver.DatagramRequestHandler):

    rtp_data = []

    def handle(self):
        literal = self.rfile.read().decode('utf-8')
        line = literal.split()
        ip = self.client_address[0]
        port = self.client_address[1]
        info = 'Received from ' + ip + ':' + \
                str(port) + ': ' + literal.replace('\r\n', ' ')
        reg(info, config_data)
        print('>>Recibido:\n' + literal)
        if line[0] == 'INVITE':
            self.rtp_data.append(line[6][2:])
            self.rtp_data.append(line[7])  # Guardamos la info de RTP
            self.rtp_data.append(line[11])  # para el envío
            templateSIP = ('SIP/2.0 100 Trying\r\n\r\n'
                           'SIP/2.0 180 Ring\r\n\r\n'
                           'SIP/2.0 200 OK\r\n\r\n')
            templateSDP = "Content-Type: application/sdp\r\n\r\n" + \
                "v=0\r\n" + "o=" + str(config_data['account']['username']) + \
                " " + str(config_data['uaserver']['ip']) + \
                "\r\ns=LaMesa\r\n" + "t=0\r\nm=audio " + \
                str(config_data['rtpaudio']['puerto']) + " RTP\r\n\r\n"
            self.wfile.write(bytes(templateSIP + templateSDP, 'utf-8'))
            info = templateSIP + templateSDP
            info = 'Sent to ' + ip + ':' + \
                str(port) + ': ' + info.replace('\r\n', ' ')
            reg(info,config_data)
        elif line[0] == 'ACK':
            info = 'Received from ' + ip + ':' + \
                    str(port) + ': ' + literal.replace('\r\n', ' ')
            reg(info,config_data)
            # FALTA POR HACER EL ENVIO RTP

            info = 'Sent to ' + self.rtp_data[1] + ':' + \
                self.rtp_data[2] + ': ' + \
                config_data['audio']['path'] + ' (audio file)'
            reg(info,config_data)

            # FALTA POR HACER EL ENVIO RTP
            self.rtp_data = []
        elif line[0] == 'BYE':
            sent_msg = 'SIP/2.0 200 OK\r\n\r\n'
            self.wfile.write(bytes(sent_msg, 'utf-8'))
            info = 'Sent to ' + ip + ':' + str(port) + ': ' + sent_msg
            reg(info, config_data)
        elif line[0] not in ['INVITE', 'ACK', 'BYE']:
            sent_msg = 'SIP/2.0 405 Method Not Allowed\r\n\r\n'
            self.wfile.write(bytes(sent_msg, 'utf-8'))
            info = 'Sent to ' + ip + ':' + str(port) + ': ' + sent_msg
            reg(info, config_data)
        else:
            sent_msg = 'SIP/2.0 400 Bad Request\r\n\r\n'
            self.wfile.write(bytes(sent_msg, 'utf-8'))
            info = 'Sent to ' + ip + ':' + str(port) + ': ' + sent_msg
            reg(info, config_data)

if __name__ == "__main__":

    try:
        CONFIG = sys.argv[1]
    except (IndexError, ValueError):
        sys.exit("Usage: python3 uaserver.py config")

    parser = make_parser()
    cHandler = XmlHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    config_data = cHandler.get_tags()
    #print("config_data es esto\n")
    #print(config_data)
    port = int(config_data['uaserver']['puerto'])
    serv = socketserver.UDPServer(('', port), SIPServerHandler)
    reg('Starting User Agent Server', config_data)
    print("Listening...\n")
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("\n...SERVER CLOSED")
        reg('Finishing.', config_data)
