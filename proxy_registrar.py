#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Programa servidor proxy SIP-SDP"""

import socketserver
import socket
import sys
import os
import time
import json
import hashlib
import random
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaserver import reg


class ProxyXmlHandler(ContentHandler):
    """Handler for XML files"""

    def __init__(self):

        self.tags = {}

    def startElement(self, name, attrs):
        exist_atts = ['name', 'passwdpath', 'ip', 'puerto', 'path']
        exist_tags = ['server', 'database', 'log']
        for tag in exist_tags:
            if name == tag:
                atts_dic = {}
                for att in exist_atts:
                    if str(attrs.get(str(att))) != 'None':
                        atts_dic[str(att)] = attrs.get(str(att), "")
                self.tags[str(name)] = atts_dic

    def get_tags(self):
        return self.tags


class SIPHandler(socketserver.DatagramRequestHandler):
    """Register server class"""
    clients = {}
    user = ['user']
    dest = ['dest']
    nonce = str(random.randint(000000000000000000000,
                               99999999999999999999))

    def get_pass(self, user):

        try:
            file = open(str(config_data['database']['passwdpath']), "r")
            lines = file.readlines()
            password = ""
            for line in lines:
                user_file = line.split()[0].split(":")[0]
                if user == user_file:
                    password = line.split()[0].split(":")[1]
        except FileNotFoundError:
            os.exit('ERROR: passwords file not found')
        return password

    def register_check(self, user):
        """Check if the user is registered"""
        reg = False
        for c in self.clients:
            if user == c:
                reg = True
        return reg

    def register2json(self):
        """Print the list of clients in a json"""
        f = open(str(config_data['database']['path']), 'w')
        json.dump(self.clients, f, indent='\t')

    def json2register(self):
        """Check it there is json and import the clients"""
        if os.path.isfile(str(config_data['database']['path'])):
            with open(str(config_data['database']['path'])) as data_file:
                self.clients = json.load(data_file)

    def check_expired_clients(self):
        """If the client expired, put it in the expired list"""
        expired = []
        for client in self.clients:
            date = time.strftime(
                                    '%Y-%m-%d %H:%M:%S',
                                    time.localtime(time.time()))
            if date >= self.clients[client][2]:
                expired.append(client)
        for client in expired:
            del self.clients[client]

    def send2uaserver(self, msg, ip, port, ack):

        ip_sock = self.clients[self.dest[0]][0]
        p_sock = int(self.clients[self.dest[0]][1])
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            my_socket.connect((ip_sock, p_sock))
            my_socket.send(bytes(msg, 'utf-8'))
            info = 'Sent to ' + ip_sock + ':' + str(p_sock) + ': ' + \
                msg.replace('\r\n', ' ')
            reg(info, config_data)
            print('SENDING:\n' + msg)
            if not ack:
                answer = my_socket.recv(1024).decode('utf-8')
                info = 'Received from ' + ip_sock + ':' + str(p_sock) + \
                    ': ' + answer.replace('\r\n', ' ')
                reg(info, config_data)
            else:
                answer = ''
        except ConnectionRefusedError:
            info = 'Error: No server listening at ' + ip_sock + ':' + \
                    str(p_sock)
            reg(info, config_data)
            print(event)
            answer = 'SIP/2.0 504 Server Time-out\r\n\r\n'
        return answer

    def handle(self):

        # LOS HEMOS QUITADO PORQUE NOS DABAN PROBLEMAS, VER COMO HACERLO(C).
        # self.json2register()
        literal = self.rfile.read().decode('utf-8')
        line = literal.split()
        print('RECEIVED:\n' + literal)
        ip = self.client_address[0]
        port = self.client_address[1]
        info = 'Received from ' + ip + ':' + str(port) + ': ' + \
            literal.replace('\r\n', ' ')
        reg(info, config_data)
        self.check_expired_clients()
        # LOS HEMOS QUITADO PORQUE NOS DABAN PROBLEMAS, VER COMO HACERLO(C).
        # self.register2json()
        if line[0] == 'REGISTER' and len(line) < 6:
            # --------- AUTHENTICATION ----------
            to_send = 'SIP/2.0 401 Unauthorized\r\n' + \
                      'WWW Authenticate: Digest nonce="' + \
                      self.nonce + '"\r\n\r\n'
            self.wfile.write(bytes(to_send, 'utf-8'))
            info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                to_send.replace('\r\n', ' ')
            reg(info, config_data)
            print('SENDING:\n' + to_send)
        elif line[0] == 'REGISTER' and len(line) >= 6:
            # --------- AUTHENTICATION ----------
            user = line[1].split(':')[1]
            authenticate = hashlib.sha1()
            authenticate.update(bytes(self.get_pass(user), 'utf-8'))
            authenticate.update(bytes(self.nonce, 'utf-8'))
            authenticate = authenticate.hexdigest()
            if authenticate == line[7].split('"')[1]:
                registered = self.register_check(user)
                data = []
                # ------- ADDING IP AND PORT --------
                data.append(self.client_address[0])
                data.append(line[1].split(':')[2])
                if line[3] == 'Expires:' and line[4] == '0' and registered:
                    del self.clients[user]
                elif line[3] == 'Expires:' and line[4] != '0':
                    caduc_time = time.localtime(time.time()+int(line[4]))
                    data.append(time.strftime('%Y-%m-%d %H:%M:%S', caduc_time))
                    self.clients[user] = data
                to_send = "SIP/2.0 200 OK\r\n\r\n"
                self.wfile.write(bytes(to_send, 'utf-8'))
                info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                    to_send.replace('\r\n', ' ')
                reg(info, config_data)
                self.register2json()
                print('SENDING:\n' + to_send)
        elif line[0] == 'INVITE':
            self.user[0] = (line[6][2:])
            self.dest[0] = (line[1].split(':')[1])
            registered = self.register_check(self.user[0])
            user_found = self.register_check(self.dest[0])
            if registered and user_found:
                answer = self.send2uaserver(literal, ip, port, False)
                self.wfile.write(bytes(answer, 'utf-8'))
                info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                    answer.replace('\r\n', ' ')
                reg(info, config_data)
                print('RESENDING:\n' + answer)
            elif not registered:
                to_send = 'SIP/2.0 401 Unauthorized\r\n\r\n'
                self.wfile.write(bytes(to_send, 'utf-8'))
                info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                    to_send.replace('\r\n', ' ')
                reg(info, config_data)
                print('SENDING:\n' + to_send)
            elif not user_found:
                to_send = 'SIP/2.0 404 User Not Found\r\n\r\n'
                self.wfile.write(bytes(to_send, 'utf-8'))
                info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                    to_send.replace('\r\n', ' ')
                reg(info, config_data)
                print('SENDING:\n' + to_send)
        elif line[0] == 'ACK':
            registered = self.register_check(self.user[0])
            if registered:
                answer = self.send2uaserver(literal, ip, port, True)
                self.user = []
                self.dest = []
        elif line[0] == 'BYE':
            self.dest[0] = line[1][4:]
            user_found = self.register_check(self.dest[0])
            if user_found:
                answer = self.send2uaserver(literal, ip, port, False)
                self.wfile.write(bytes(answer, 'utf-8'))
                info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                    answer.replace('\r\n', ' ')
                reg(info, config_data)
                print('>>Reenviando:\n' + answer)
            elif not user_found:
                to_send = 'SIP/2.0 404 User Not Found\r\n\r\n'
                self.wfile.write(bytes(to_send, 'utf-8'))
                info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                    to_send.replace('\r\n', ' ')
                reg(info, config_data)
                print('SENDING:\n' + to_send)
        elif line[0] not in ['INVITE', 'ACK', 'BYE']:
            to_send = 'SIP/2.0 405 Method Not Allowed\r\n\r\n'
            self.wfile.write(bytes(to_send, 'utf-8'))
            info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                to_send.replace('\r\n', ' ')
            reg(info, config_data)
            print('SENDING:\n' + to_send)
        else:
            to_send = 'SIP/2.0 400 Bad Request\r\n\r\n'
            self.wfile.write(bytes(to_send, 'utf-8'))
            info = 'Sent to ' + ip + ':' + str(port) + ': ' + \
                to_send.replace('\r\n', ' ')
            reg(info, config_data)
            print('SENDING:\n' + to_send)
if __name__ == "__main__":

    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit("Usage: python3 proxy_registrar.py config")
    parser = make_parser()
    cHandler = ProxyXmlHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    config_data = cHandler.get_tags()
    serv = socketserver.UDPServer(('', int(config_data['server']['puerto'])),
                                  SIPHandler)
    print('>> ' + config_data['server']['name'] + ' listening...\n')
    reg('Starting...', config_data)
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("\nFinalizado servidor")
        reg('Finishing...', config_data)
