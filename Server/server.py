__author__ = "Lior Zemah"

import os
import selectors
import uuid
import socket
import zlib

import protocol
from datetime import datetime
from database import Client, File, Database
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode
from Crypto.Util.Padding import pad, unpad


class Server:
    DATABASE = 'server.db'
    PACKET_SIZE = 1024  # Default packet size.
    MAX_QUEUED_CONN = 5  # Default maximum number of queued connections.

    def __init__(self, host, port, is_blocking):
        """ Initialize server, db and create map of request codes to handle """
        self.host = host
        self.port = port
        self.isBlocking = is_blocking
        self.selector = selectors.DefaultSelector()
        self.database = Database(Server.DATABASE)
        self.requestHandlers = {
            protocol.RequestCode.REQUEST_REGISTRATION.value: self.handle_registration_request,
            protocol.RequestCode.REQUEST_SEND_PUBLIC_KEY.value: self.handle_public_key_request,
            protocol.RequestCode.REQUEST_RECONNECT.value: self.handle_reconnect_request,
            protocol.RequestCode.REQUEST_SEND_FILE.value: self.handle_send_file_request,
            protocol.RequestCode.REQUEST_VALID_CRC.value: self.handle_crc_and_finish,
            protocol.RequestCode.REQUEST_INVALID_CRC_RETRY.value: self.handle_invalid_crc_request,
            protocol.RequestCode.REQUEST_INVALID_CRC_FINISH.value: self.handle_crc_and_finish
        }

    def start(self):
        """ Start listen to connections """
        self.database.init_tables()
        try:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(Server.MAX_QUEUED_CONN)
            sock.setblocking(self.isBlocking)
            self.selector.register(sock, selectors.EVENT_READ, self.accept)
        except Exception as err:
            return False
        print(f"Server start listening on port {self.port}..")
        while True:
            try:
                events = self.selector.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                print(f"Server main loop exception: {e}")

    def accept(self, sock, mask):
        """ accept new connection """
        conn, address = sock.accept()
        print(f"Accepted new connection from {address}")
        conn.setblocking(self.isBlocking)
        self.selector.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        """ read data from client and parse it"""
        data = conn.recv(Server.PACKET_SIZE)
        if data:
            self.handle_data(conn, data)
        else:
            print("Receive empty data")
        # Closing connection in the end because it's stateless server
        self.selector.unregister(conn)
        conn.close()

    def handle_data(self, conn, data):
        request_header = protocol.RequestHeader()
        success = False
        if not request_header.unpack(data):
            print("Failed to parse request header!")
        else:
            if request_header.code in self.requestHandlers.keys():
                success = self.requestHandlers[request_header.code](conn, data)  # invoke corresponding handle.
        if not success:  # return global error
            self.send_global_error(conn)
        # update client last seen for any request that different than Registration because it without clientID
        if request_header.code != protocol.RequestCode.REQUEST_REGISTRATION:
            self.database.update_last_seen(request_header.clientID)

    def write(self, conn, data):
        """ Send a response to client"""
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > Server.PACKET_SIZE:
                leftover = Server.PACKET_SIZE
            to_send = data[sent:sent + leftover]
            if len(to_send) < Server.PACKET_SIZE:
                to_send += bytearray(Server.PACKET_SIZE - len(to_send))
            try:
                conn.send(to_send)
                sent += len(to_send)
            except:
                print("Failed to send response to " + conn)
                return False
        print("Response sent successfully.")
        return True

    def try_to_register(self, data):
        request = protocol.RegistrationRequest()
        if not request.unpack(data):
            print("Failed to parse Registration Request")
            return None
        try:
            if self.database.is_client_name_exists(request.name):
                print(f"User name '{request.name}' already exists in {Server.DATABASE}")
                return None
        except:
            print(f"Failed connect to {Server.DATABASE}")
            return None

        client = Client(uuid.uuid4().hex, request.name, "", str(datetime.now()), "")
        if not self.database.insert_new_client(client):
            print(f"Failed to insert client '{request.name}'")
            return None
        print(f"Successfully registered client '{request.name}'")
        return client

    def handle_registration_request(self, conn, data):
        """ Register new client and update db. """
        new_client = self.try_to_register(data)
        if new_client is None:
            response = protocol.RegistrationResponse(False)
        else:
            response = protocol.RegistrationResponse(True)
            response.clientID = new_client.ID
            response.header.payloadSize = protocol.CLIENT_ID_SIZE
        return self.write(conn, response.pack())

    def create_and_send_aes(self, conn, client_id, pub_key, reconnect):
        # create aes key and save it in the db
        aes_key = get_random_bytes(protocol.AES_KEY_SIZE)
        print(f"aes key: {b64encode(aes_key).decode('utf-8')}")

        if self.database.update_aes_key(client_id, aes_key) is False:
            print("Failed to update db with the new aes")

        # encrypt aes key with the public key
        rsa_public_key = RSA.import_key(pub_key)
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes = rsa_public_key.encrypt(aes_key)

        response = protocol.AesKeyResponse(reconnect)
        response.clientID = client_id
        response.encryptedAesKey = encrypted_aes
        response.encryptedAesKeyLen = len(response.encryptedAesKey)
        response.header.payloadSize = protocol.CLIENT_ID_SIZE + len(response.encryptedAesKey)
        print(f"Successfully create aes response for client id ({client_id})")
        return self.write(conn, response.pack())

    def handle_public_key_request(self, conn, data):
        """ respond with public key of requested user id """
        request = protocol.PublicKeyRequest()
        if not request.unpack(data):
            print("Failed to parse PublicKey Request")

        # keep public key in the db
        if self.database.update_public_key(request.header.clientID, request.publicKey) is False:
            print("Failed to update db with the new public key")

        return self.create_and_send_aes(conn, request.header.clientID, request.publicKey, False)

    def handle_reconnect_request(self, conn, data):
        request = protocol.ReconnectRequest()
        if not request.unpack(data):
            print("Failed to parse Reconnect Request")

        rejected = protocol.ReconnectRejectedResponse()
        rejected.clientID = request.header.clientID
        client_for_reconnect = request.name
        exists = self.database.is_client_name_exists(client_for_reconnect)
        if exists is False:
            print(f"Reconnect rejected, client name {client_for_reconnect} is not exists in the db")
            return self.write(conn, rejected.pack())

        client_id = self.database.get_client_id(client_for_reconnect)
        if client_id is None or client_id != request.header.clientID:
            print(f"Reconnect rejected, client id {request.header.clientID} is not match to one in the db: {client_id}")
            return self.write(conn, rejected.pack())

        ras_public_key = self.database.get_client_public_key(client_id)
        if ras_public_key is None or ras_public_key == b'':
            print(f"Reconnect rejected, client id {request.header.clientID} not contains any rsa public key")
            return self.write(conn, rejected.pack())

        return self.create_and_send_aes(conn, client_id, ras_public_key, True)

    def handle_send_file_request(self, conn, data):
        request = protocol.SendFileRequest()
        if not request.unpack(data):
            print("Failed to parse Reconnect Request")

        print("encrypted content size: ", len(request.fileContent))
        print("encrypted content: ", b64encode(request.fileContent).decode('utf-8'))
        print("encrypted content: ", request.fileContent)

        decrypted_content = None
        try:
            # get client aes key
            aes_key = self.database.get_client_aes(request.header.clientID)
            print(f"aes len: {len(aes_key)}, aes key: {b64encode(aes_key).decode('utf-8')}")

            # create aes cipher from the key
            cipher = AES.new(aes_key, AES.MODE_CBC,  bytes(16))

            # decrypt content
            decrypted_content = cipher.decrypt(request.fileContent)
        except:
            print("Failed to create AES key, return global error")
            self.send_global_error(conn)
            return False

        print("decrypted_content size: ", len(decrypted_content))
        print("decrypted_content: ", b64encode(decrypted_content).decode('utf-8'))

        # store file in db
        file_full_path = str(request.fileName)
        head_tail = os.path.split(file_full_path)
        file_dir_path = head_tail[0]
        file_name = head_tail[1]
        new_file = File(request.header.clientID, file_name, file_dir_path, False)
        self.database.insert_new_file(new_file)
        print(f"Store file {str(request.fileName)}")

        # calculate crc from the content
        crc = zlib.crc32(decrypted_content)
        print("file crc: ", crc)

        response = protocol.ValidCrcResponse()
        response.clientID = request.header.clientID
        response.contentSize = request.contentSize
        response.fileName = request.fileName
        response.crc = crc
        response.header.payloadSize = protocol.CLIENT_ID_SIZE + protocol.NAME_SIZE + 8
        print(f"Successfully send valid crc response")
        return self.write(conn, response.pack())

    """
    handle crc request 1104 and 1106 that get crc status (valid and invalid) and after then the communication with 
    the client finished
    """
    def handle_crc_and_finish(self, conn, data):
        request = protocol.CrcStatusRequest()
        if not request.unpack(data):
            print(f"Failed to parse CRC Request code: {request.header.code}")

        # check if the status code is of valid or invalid crc and update verified bit
        verified = False
        if request.header.code is protocol.RequestCode.REQUEST_VALID_CRC:
            verified = True

        # update file verified status to false
        if self.database.update_file_verified(request.fileName, False) is False:
            print(f"Failed to update {request.fileName} verified bit, maybe file not exists")

        response = protocol.MsgRecvResponse()
        response.clientID = request.header.clientID
        response.header.payloadSize = protocol.CLIENT_ID_SIZE
        print(f"Finish Communication with client id: {request.header.clientID}")
        return self.write(conn, response.pack())

    def handle_invalid_crc_request(self, conn, data):
        request = protocol.CrcStatusRequest()
        if not request.unpack(data):
            print(f"Failed to parse invalid CRC Request code: {request.header.code}")

        # update file verified status to false
        if self.database.update_file_verified(request.fileName, False) is False:
            print(f"Failed to update {request.fileName} verified bit, maybe file not exists")
        return True

    def send_global_error(self, conn):
        request_header = protocol.ResponseHeader(protocol.ResponseCode.RESPONSE_GLOBAL_ERROR.value)
        self.write(conn, request_header.pack())
