import logging
import select
import socket
import re
import struct
from urllib.parse import urlparse
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    username = 'username'
    password = 'password'

    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)
        header = self.connection.recv(2)
        #logging.info(header[1])
        version, nmethods = struct.unpack("!BB", header)
        #logging.info("ver: %s"%version)
        assert version == SOCKS_VERSION
        assert nmethods > 0
        methods = self.get_available_methods(nmethods)
        #logging.info(methods)
        if 2 not in set(methods):
            self.server.close_request(self.request)
            return
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

        if not self.verify_credentials():
            return
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)

        
        port = struct.unpack('!H', self.connection.recv(2))[0]
        logging.info('test %s %s' % (address, port))
        try:
            if cmd == 1: 
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                #logging.info(bind_address)
                logging.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type,addr, port)

        except Exception as err:
            logging.error(err)
            reply = self.generate_failed_reply(address_type, 5)

        self.connection.sendall(reply)
        #logging.info(reply)
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):
        """
        data = client.recv(4096)
        buff=bufferToChunk(data)
        for buff in bufferToChunk(data):
            logging.info("client %s"% buff)
            remote.send(buff)
        """
        while True:
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                
                buff=bufferToChunk(data)
                for buff in bufferToChunk(data):
                    logging.info("client %s"% buff)
                    if remote.send(buff)<=0:
                        break
                """
                if remote.send(data) <= 0:
                    break
                """

            if remote in r:
                data = remote.recv(4096)
                #logging.info(data)
                #data1=data[:2048]
                #data2=data[2048:]
                logging.info("server: %s"%data)
                if client.send(data) <= 0:
                    break
                #if client.send(data2) <= 0:
                #   break


class HTTPproxy(StreamRequestHandler):
    def handle(self):
        req=self.connection.recv(4096)
        req2=req.decode('utf-8').split('\r\n')
        req2=re.split('\s+',req2[0])
        if isCONNECTMethod(req2[0]):
            address=socket.gethostbyname()
            
            handleHTTPS()
        else:
            handleHTTP()
        logging.info("hello%s"%req)
    def handleHTTP()
        pass
        
    def handleHTTPS()
        pass

def isCONNECTMethod(method):
    if method=='CONNECT': 
        return True
    else:
        return False
def bufferToChunk(data):
    r=[]
    l=len(data)
    i=0
    while i<l:
        x=slice(i,i+100)
        i+=100
        r.append(data[x])
    return r
        

if __name__ == '__main__':
    with ThreadingTCPServer(('127.0.0.1', 9011), SocksProxy) as server:
        server.serve_forever()