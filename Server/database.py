__author__ = "Lior Zemah"

from datetime import datetime
import sqlite3
import protocol


class Client:
    """ Represents a client entry """

    def __init__(self, cid, cname, public_key, last_seen, aes_key):
        self.ID = bytes.fromhex(cid)  # Unique client ID, 16 bytes.
        self.Name = cname  # Client's name, 255 bytes.
        self.PublicKey = public_key  # Client's public key, 160 bytes.
        self.LastSeen = last_seen  # The time of client last request.
        self.AESKey = aes_key  # Client's AES key, 16 bytes

    def validate_except_keys(self):
        """ Validate Client fields except PublicKey and AESKey that suppose to be empty when new client register"""
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.Name or len(self.Name) >= protocol.NAME_SIZE:
            return False
        if not self.LastSeen:
            return False
        if self.PublicKey or self.AESKey:
            return False
        return True

    def validate(self):
        """ Validate Client fields """
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.Name or len(self.Name) >= protocol.NAME_SIZE:
            return False
        if not self.PublicKey or len(self.PublicKey) != protocol.PUBLIC_KEY_SIZE:
            return False
        if not self.LastSeen:
            return False
        if not self.AESKey or len(self.AESKey) != protocol.AES_KEY_SIZE:
            return False
        return True


class File:
    """ Represents a file entry """
    def __init__(self, fid, filename, pathname, verified):
        self.ID = fid  # Unique client ID, 16 bytes.
        self.Filename = filename  # File name, 255 bytes.
        self.Pathname = pathname  # File path, 255 bytes.
        self.Verified = verified  # Checksum status, boolean.

    def validate(self):
        """ Validate File fields """
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.Filename or len(self.Filename) >= protocol.NAME_SIZE:
            return False
        if not self.Pathname or len(self.Pathname) >= protocol.NAME_SIZE:
            return False
        if not self.Verified or not type(self.Verified) is bool:
            return False
        return True


class Database:
    CLIENTS_DB = 'clients'
    FILES_DB = 'files'

    def __init__(self, name):
        self.name = name

    def connect(self):
        conn = sqlite3.connect(self.name)  # doesn't raise exception.
        conn.text_factory = bytes
        return conn

    def execute_script(self, script):
        conn = self.connect()  # connect to the DB
        try:
            conn.executescript(script)  # execute the script
            conn.commit()  # save changes in DB
        except:
            pass
        conn.close()  # close DB

    def execute(self, query, args, commit=False, get_last_row=False):
        """ Give query and args, execute query, and return the results. """
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()
            if get_last_row:
                results = cur.lastrowid  # special query.
        except Exception as err:
            print(f'Error: Database execute failed with error details: {err}')
        conn.close()  # commit is not required.
        return results

    def init_tables(self):
        # Create tables if not exists
        self.execute_script(f"""
            CREATE TABLE {self.CLIENTS_DB}(
              ID CHAR(16) NOT NULL PRIMARY KEY,
              Name CHAR(255) NOT NULL,
              PublicKey CHAR(160) NOT NULL,
              LastSeen DATE,
              AESKey CHAR(16) NOT NULL
            );
            """)

        self.execute_script(f"""
            CREATE TABLE {self.FILES_DB}(
              ID CHAR(16) NOT NULL PRIMARY KEY,
              FileName CHAR(255) NOT NULL,
              PathName CHAR(255) NOT NULL,
              Verified BIT,
              FOREIGN KEY(ID) REFERENCES {self.CLIENTS_DB}(ID)
            );
            """)

    def insert_new_client(self, client):
        """ Insert new client to the database """
        if not type(client) is Client or not client.validate_except_keys():
            return False
        return self.execute(f"INSERT INTO {Database.CLIENTS_DB} VALUES (?, ?, ?, ?, ?)",
                            [client.ID, client.Name, client.PublicKey, client.LastSeen, client.AESKey], True)

    def insert_new_file(self, file):
        """ Insert new client to the database """
        if not type(file) is File or not file.validate():
            return False
        return self.execute(f"INSERT INTO {Database.FILES_DB} VALUES (?, ?, ?, ?)",
                            [file.ID, file.Filename, file.Pathname, file.Verified], True)

    def is_client_name_exists(self, client_name):
        """ Check if client name already exists """
        results = self.execute(f"SELECT * FROM {Database.CLIENTS_DB} WHERE Name = ?", [client_name])
        if not results:
            return False
        return len(results) > 0

    def is_client_id_exists(self, client_id):
        """ Check if client ID already exists """
        results = self.execute(f"SELECT * FROM {Database.CLIENTS_DB} WHERE ID = ?", [client_id])
        if not results:
            return False
        return len(results) > 0

    def is_file_id_exists(self, fid):
        """ Check if file ID already exists """
        results = self.execute(f"SELECT * FROM {Database.FILES_DB} WHERE ID = ?", [fid])
        if not results:
            return False
        return len(results) > 0

    def update_aes_key(self, client_id, key):
        if self.is_client_id_exists(client_id) is False:
            print(f"Client with id {client_id} not exists")
            return False
        return self.execute(f"UPDATE {Database.CLIENTS_DB} SET AESKey = ? WHERE ID = ?", [key, client_id], True)

    def update_public_key(self, client_id, key):
        return self.execute(f"UPDATE {Database.CLIENTS_DB} SET PublicKey = ? WHERE ID = ?", [key, client_id], True)

    def get_client_aes(self, client_id):
        results = self.execute(f"SELECT AESKey FROM {Database.CLIENTS_DB} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    def get_client_public_key(self, client_id):
        results = self.execute(f"SELECT PublicKey FROM {Database.CLIENTS_DB} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    def get_client_id(self, client_name):
        results = self.execute(f"SELECT ID FROM {Database.CLIENTS_DB} WHERE Name = ?", [client_name])
        if not results:
            return None
        return results[0][0]

    def update_last_seen(self, client_id):
        """ update last seen for client """
        if self.is_client_id_exists(client_id) is False:
            return False
        return self.execute(f"UPDATE {Database.CLIENTS_DB} SET LastSeen = ? WHERE ID = ?",
                            [str(datetime.now()), client_id], True)

    def update_file_verified(self, fid, verified):
        if self.is_file_id_exists(fid) is False:
            return False
        return self.execute(f"UPDATE {Database.FILES_DB} SET Verified = ? WHERE ID = ?",
                            [verified, fid], True)
