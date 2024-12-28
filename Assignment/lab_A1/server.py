import socketserver
import time
import socket, threading

from functions import *

commands = [
    '?',
    'help',
    'exit',
    'login {name} {password}',
    'register {name} {password}'
]

### Task 2.1 Read user information files
users = load_users(user_inf_txt)
print(users)


## Task 2.1

def main_loop(socket_conn, client_address, login_user):
    """

    :param socket_conn: socket connection
    :param client_address: client IP address
    :param login_user: str current logged-in user
    :return continue flag: boolean for main loop continue judgement, login user: str
    """
    ## Task 1.3
    receive_data = socket_conn.recv(2048).decode('UTF-8').strip()
    if not receive_data:
        return False, None
    with open('command.txt', 'a') as log_file:
        log_file.write(f'{client_address}: {receive_data}' + "\n")
    ## Task 1.3

    # Command processing before login
    if not login_user:
        # Command processing without arguments
        if receive_data == '?' or receive_data == 'help' or receive_data == 'ls':
            feedback_data = 'Available commends: \n\t' + '\n\t'.join(commands)
            feedback_data = SUCCESS(feedback_data)
        elif receive_data == 'exit':
            feedback_data = 'disconnected'
            feedback_data = SUCCESS(feedback_data)
        else:
            # Command processing with arguments
            cmd = receive_data.split(' ')
            if cmd[0] == 'login':
                if len(cmd) < 3:
                    feedback_data = 'Please re-enter the login commend with your username and password'
                    feedback_data = FAILURE(feedback_data)
                elif len(cmd) == 3:
                    ## Task 2.3, 3.2, 3.5
                    feedback_data, login_user = login_authentication(socket_conn, cmd, users)
                    ## Task 2.3, 3.2, 3.5
                else:
                    feedback_data = "Password shouldn't include spaces"
                    feedback_data = FAILURE(feedback_data)
            elif cmd[0] == 'register':
                if len(cmd) < 3:
                    feedback_data = 'Please re-enter the command with username and password'
                    feedback_data = FAILURE(feedback_data)
                elif len(cmd) > 3:
                    feedback_data = "Username or password shouldn't include spaces"
                    feedback_data = FAILURE(feedback_data)
                else:
                    ## Task 2.2
                    feedback_data = user_register(cmd, users)
                    ## Task 2.2
            else:
                feedback_data = "Invalid command"
                feedback_data = FAILURE(feedback_data)
    else:
        ## Task 4
        feedback_data, login_user = login_cmds(receive_data, users, login_user)
        ## Task 4

    socket_conn.sendall(feedback_data.encode('UTF-8'))
    if feedback_data == '200:disconnected':
        return False, None
    return True, login_user


## Task 1.2
## Connection establishment on server
# TODO: finish the codes
class Echo(threading.Thread):
    def __init__(self, conn, address):
        threading.Thread.__init__(self)
        self.conn = conn
        self.address = address
        self.login_user = None

    def run(self):
        while True:
            try:
                continue_flag, self.login_user = main_loop(self.conn, self.address, self.login_user)
                # if self.login_user:
                #     print(f"{self.address}:{self.login_user} log in")
                if not continue_flag:
                    break
            except Exception as e:
                print(f"Error handling client {self.address}: {e}")
                break
        print(f"Connection closed with {self.address}")
        self.conn.close()


def echo(connection_count=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 6016))
    sock.listen(10)
    while True:
        conn, address = sock.accept()
        connection_count += 1
        print(f"Connection established with {address}")
        Echo(conn, address).start()


if __name__ == "__main__":
    try:
        echo()
    except KeyboardInterrupt:
        pass
## Task 1.2
