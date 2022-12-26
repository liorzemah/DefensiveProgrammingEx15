__author__ = "Lior Zemah"

import struct
from enum import Enum

SERVER_VERSION = 3
DEFAULT_INT_VAL = 0  # Default integer value to initialize inner fields.
HEADER_SIZE = 7  # Header size without clientID. (version, code, payload size).
CLIENT_ID_SIZE = 16
MSG_ID_SIZE = 4
MSG_TYPE_MAX = 0xFF
MSG_ID_MAX = 0xFFFFFFFF
NAME_SIZE = 255  # represent client name, file name and file path size
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 16


# Request Codes (compatible to the client)
class RequestCode(Enum):
    REQUEST_REGISTRATION = 1100
    REQUEST_SEND_PUBLIC_KEY = 1101
    REQUEST_RECONNECT = 1002
    REQUEST_SEND_FILE = 1003
    REQUEST_VALID_CRC = 1004
    REQUEST_INVALID_CRC_RETRY = 1005
    REQUEST_INVALID_CRC_FINISH = 1006


# Responses Codes
class ResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCEEDED = 2100
    RESPONSE_REGISTRATION_FAILED = 2101
    RESPONSE_AES_KEY = 2102
    RESPONSE_VALID_CRC = 2103
    RESPONSE_MSG_RECEIVED = 2104
    RESPONSE_RECONNECT_ALLOWED = 2105
    RESPONSE_RECONNECT_REJECTED = 2106
    RESPONSE_GLOBAL_ERROR = 2107




class RequestHeader:
    """ Little Endian unpack Request Header """
    def __init__(self):
        self.clientID = b""
        self.version = DEFAULT_INT_VAL      # 1 byte
        self.code = DEFAULT_INT_VAL         # 2 bytes
        self.payloadSize = DEFAULT_INT_VAL  # 4 bytes
        self.SIZE = CLIENT_ID_SIZE + HEADER_SIZE

    def unpack(self, data):
        try:
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            header_data = data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + HEADER_SIZE]
            self.version, self.code, self.payloadSize = struct.unpack("<BHL", header_data)
            return True
        except:
            self.clientID = b""
            self.version = DEFAULT_INT_VAL
            self.code = DEFAULT_INT_VAL
            self.payloadSize = DEFAULT_INT_VAL
            self.SIZE = CLIENT_ID_SIZE + HEADER_SIZE
            return False


class ResponseHeader:
    """ Little Endian pack Response Header """
    def __init__(self, code):
        self.version = SERVER_VERSION  # 1 byte
        self.code = code               # 2 bytes
        self.payloadSize = DEFAULT_INT_VAL     # 4 bytes
        self.SIZE = HEADER_SIZE

    def pack(self):
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            name_data = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = b""
            return False


class RegistrationResponse:
    def __init__(self, succeeded):
        self.succeeded = succeeded
        if succeeded:
            self.header = ResponseHeader(ResponseCode.RESPONSE_REGISTRATION_SUCCEEDED.value)
        else:
            self.header = ResponseHeader(ResponseCode.RESPONSE_REGISTRATION_FAILED.value)
        self.clientID = b""

    def pack(self):
        try:
            data = self.header.pack()
            if self.succeeded:
                data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""


class ReconnectRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            name_data = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = b""
            return False


class PublicKeyRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.clientName = b""
        self.publicKey = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            client_name = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.clientName = struct.unpack(f"<{NAME_SIZE}s", client_name)[0]
            public_key = data[self.header.SIZE + NAME_SIZE:self.header.SIZE + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.publicKey = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", public_key)[0]
            return True
        except:
            self.clientName = b""
            self.publicKey = b""
            return False


class AesKeyResponse:
    def __init__(self, is_reconnect):
        if is_reconnect:
            self.header = ResponseHeader(ResponseCode.RESPONSE_RECONNECT_ALLOWED.value)
        else:
            self.header = ResponseHeader(ResponseCode.RESPONSE_AES_KEY.value)
        self.clientID = b""
        self.encryptedAesKey = b""
        self.encryptedAesKeyLen = 0

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<{self.encryptedAesKeyLen}s", self.encryptedAesKey)
            return data
        except:
            return b""


class SendFileRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.contentSize = DEFAULT_INT_VAL
        self.fileName = b""
        self.fileContent = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            content_size = data[self.header.SIZE:self.header.SIZE + 4]
            self.contentSize = struct.unpack("<L", content_size)[0]
            file_name = data[self.header.SIZE + 4:self.header.SIZE + 4 + NAME_SIZE]
            self.fileName = struct.unpack(f"<{NAME_SIZE}s", file_name)[0]
            file_content = data[self.header.SIZE + 4 + NAME_SIZE:self.header.SIZE + 4 + NAME_SIZE + self.contentSize]
            self.fileContent = struct.unpack(f"<{self.contentSize}s", file_content)[0]
            return True
        except:
            self.contentSize = DEFAULT_INT_VAL
            self.fileName = b""
            self.fileContent = b""
            return False


class ValidCrcResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_VALID_CRC.value)
        self.clientID = b""
        self.contentSize = DEFAULT_INT_VAL
        self.fileName = b""
        self.crc = DEFAULT_INT_VAL

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<L", self.contentSize)
            data += struct.pack(f"<{NAME_SIZE}s", self.fileName)
            data += struct.pack(f"<L", self.crc)
            return data
        except:
            return b""

"""
CrcStatusRequest represent request code 1104, 1105, 1106 thats 3 different status of crc
(valid, invalid and still trying, and invalid after 3 failed tries)
"""
class CrcStatusRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.fileName = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            file_name = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.fileName = struct.unpack(f"<{NAME_SIZE}s", file_name)[0]
            return True
        except:
            self.fileName = b""
            return False

class MsgRecvResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_MSG_RECEIVED.value)
        self.clientID = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""


class ReconnectRejectedResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_RECONNECT_REJECTED.value)
        self.clientID = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""
