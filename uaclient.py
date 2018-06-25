#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Programa User Agent Client que abre un socket a un servidor."""

import socket
import sys
from uaserver import XmlHandler
from xml.sax import make_parser
from uaserver import reg
import hashlib
import os
import time


if __name__ == "__main__":

    try:
        CONFIG = sys.argv[1]
        METHOD = sys.argv[2].upper()
        OPTION = sys.argv[3]
    except:
        sys.exit("Usage: python3 uaclient.py config method option")

    parser = make_parser()
    cHandler = XmlHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    config_data = cHandler.get_tags()

    # ----- CREATING AND BIND THE SOCKET TO IP AND PORT OF SERVER ------
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = config_data['regproxy']['ip']
    port = config_data['regproxy']['puerto']
    try:
        my_socket.connect((ip, int(port))) # We open the socket
        if METHOD == 'REGISTER':
            # ------------    SENDING     ------------
            line = METHOD + ' sip:' + config_data['account']['username'] + \
                ':' + config_data['uaserver']['puerto'] + \
                ' SIP/2.0\r\nExpires: ' + OPTION

            my_socket.send(bytes(line, 'utf-8') + b'\r\n\r\n')
            # ------------ WRITING IN LOG ------------
            info = 'Sent to ' + ip + ':' + port + ': ' + \
                        line.replace('\r\n', ' ')
            reg(info, config_data)
            # ------------   RECIEVING    ------------
            received = my_socket.recv(1024).decode('utf-8')
            info = 'Received from ' + ip + ':' + port + ': ' + \
                        received.replace('\r\n', ' ')
            reg(info, config_data)

            if received.split()[1] == '401':
                nonce = received.split('"')[1]
                # ---- AUTHORIZATION AND GETTING THE HASH ----
                psswd = config_data['account']['passwd']
                response = hashlib.sha1()
                response.update(bytes(psswd, 'utf-8'))
                response.update(bytes(nonce, 'utf-8'))
                response = response.hexdigest()
                authorization = 'Authorization: Digest response="' + response
                line += '\r\n' + authorization
                my_socket.send(bytes(line, 'utf-8') + b'"\r\n\r\n')
                # ------------ WRITING IN LOG ------------
                info = 'Sent to ' + ip + ':' + port + ': ' + \
                        received.replace('\r\n', ' ')
                reg(info, config_data)
                received = my_socket.recv(1024).decode('utf-8')
                # ------------ WRITING IN LOG ------------
                info = 'Received from ' + ip + ':' + port + ': ' + \
                        received.replace('\r\n', ' ')
                reg(info, config_data)
                print('\nRECEIVING:\n' + received)
        elif METHOD == 'INVITE':
            templateSDP = "Content-Type: application/sdp\r\n\r\n" + "v=0\r\n" \
                        + "o=" + str(config_data['account']['username']) + \
                        " " + str(config_data['uaserver']['ip']) + \
                        "\r\ns=LaMesa\r\n" + "t=0\r\nm=audio " + \
                        str(config_data['rtpaudio']['puerto']) + " RTP\r\n\r\n"
            line = METHOD + ' sip:' + OPTION + ' SIP/2.0\r\n' + templateSDP
            print('\nSENT:\n' + line)
            my_socket.send(bytes(line, 'utf-8'))
            # ------------ WRITING IN LOG ------------
            info = 'Sent to ' + ip + ':' + port + ': ' + \
                    line.replace('\r\n', ' ')
            reg(info, config_data)

            received = my_socket.recv(1024).decode('utf-8')
            # ------------ WRITING IN LOG ------------
            info = 'Received from ' + ip + ':' + port + ': ' + \
                    received.replace('\r\n', ' ')
            reg(info, config_data)
            print('\nRECEIVED:\n' + received)
            if '200' in received:
                line = 'ACK sip:' + OPTION + ' SIP/2.0\r\n'
                my_socket.send(bytes(line, 'utf-8'))
                # ------------ WRITING IN LOG ------------
                info = 'Sent to ' + ip + ':' + port + ': ' + \
                        line.replace('\r\n', ' ')
                reg(info, config_data)
                rtp_ip = received.split()[13]
                rtp_port = received.split()[17]
                cmd = 'cvlc rtp://@' + config_data['uaserver']['ip'] + \
                      ':' + config_data['rtpaudio']['puerto']
                os.system(cmd)

                info = 'Sent to ' + rtp_ip + ':' + rtp_port + ': ' + \
                        config_data['audio']['path'] + ' (audio file)'
                reg(info, config_data)

                os.system("./mp32rtp -i " + rtp_ip + " -p " +
                          rtp_port + " < " + config_data['audio']['path'])

        elif METHOD == 'BYE':
            line = 'BYE sip:' + OPTION + ' SIP/2.0\r\n'
            # ------------    SENDING     ------------
            my_socket.send(bytes(line, 'utf-8'))
            print("\nSENT:\n" + line)
            # ------------ WRITING IN LOG ------------
            info = 'Sent to ' + ip + ':' + port + ': ' + \
                    line.replace('\r\n', ' ')
            reg(info, config_data)
            # ------------   RECEIVING    ------------
            received = my_socket.recv(1024).decode('utf-8')
            info = 'Received from ' + ip + ':' + port + ': ' + \
                    received.replace('\r\n', ' ')
            reg(info, config_data)
            print('\nRECEIVED:\n' + received)
        print('\nCLOSING THE SOCKET\n')
        reg('Closing socket', config_data)
        my_socket.close()
    except ConnectionRefusedError:
        info = 'Error: No server listening at ' + ip + ' port ' + str(port)
        reg(info, config_data)
        sys.exit(info)
