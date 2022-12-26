__author__ = "Lior Zemah"

import server


def read_port_info(filepath, default_port):
    """
    Read port from filepath, if the file not contains only valid number return default port 1234
    """
    port = default_port
    try:
        with open(filepath, "r") as port_info:
            port_as_str = port_info.readline().strip()
            port = int(port_as_str)
    except FileNotFoundError as err:
        print(f"Warning: {err}, use default port 1234")
    except ValueError as err:
        print(f"Error: {err}, use default port 1234")
    finally:
        return port


if __name__ == '__main__':
    PORT_FILE = "port.info"
    DEFAULT_PORT = 1234
    server_port = read_port_info(PORT_FILE, DEFAULT_PORT)
    print(f"Server port is: {server_port}")

    serv = server.Server('', server_port, False)
    if not serv.start():
        print(f"Error: Server failed to start")
        exit(1)
