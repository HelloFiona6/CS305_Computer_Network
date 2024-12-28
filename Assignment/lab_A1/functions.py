import hmac
import json
import os
import socket
import hashlib
import re
import random
import ast
import fileinput

host = "localhost"
port = 6016
user_inf_txt = 'users.txt'

login_commands = [
    '?',
    'help',
    'exit',
    'logout',
    'changepwd {newpassword}',
    'sum [a] [b] ...',
    'sub [a] [b]',
    'multiply [a] [b] ...',
    'divide [a] [b]'
]


def SUCCESS(message):
    """
    This function is designed to be easy to test, so do not modify it
    """
    return '200:' + message


def FAILURE(message):
    """
    This function is designed to be easy to test, so do not modify it
    """
    return '400:' + message


def ntlm_hash_func(password):
    """
    This function is used to encrypt passwords by the MD5 algorithm
    """
    # 1. Convert password to hexadecimal format
    hex_password = ''.join(format(ord(char), '02x') for char in password)

    # 2. Unicode encoding of hexadecimal passwords
    unicode_password = hex_password.encode('utf-16le')

    # 3. The MD5 digest algorithm is used to Hash the Unicode encoded data
    md5_hasher = hashlib.md5()
    md5_hasher.update(unicode_password)

    # Returns the MD5 Hash
    return md5_hasher.hexdigest()


def connection_establish(ip_p):
    """
    Task 1.1 Correctly separate the IP address from the port number in the string
    Returns the socket object of the connected server when the socket server address pointed to by IP:port is available
    Otherwise, an error message is given
    :param ip_p: str 'IP:port'
    :return socket_client: socket.socket() or None
    :return information: str 'success' or error information
    """
    try:
        ip, p = ip_p.split(":")
        p = int(p)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # tcp socket network layer protocol(IPv4) + udp protocol
        client_socket.connect((ip, p))
        return client_socket, 'success'
    except Exception as e:
        return None, e


def load_users(user_records_txt):
    """
    Task 2.1 Load saved user information (username and password)
    :param user_records_txt: a txt file containing username and password records
    :return users: dict {'username':'password'}
    """
    users = {}
    with open(user_records_txt, 'r') as file:
        lines = file.readlines()
    if not lines or lines == ['\n']:
        return users
    for line in lines:
        if line.strip():
            username, password = line.strip().split()
            users[username] = password
    return users


def user_register(cmd, users):
    """
    Task 2.2 Register command processing
    :param cmd: Instruction string
    :param users: The dict to hold information about all users
    :return feedback message: str
    """
    username = cmd[1]
    password = cmd[2]
    if username in users:
        return FAILURE('User already exists')

    users[username] = password
    with open(user_inf_txt, 'a') as file:
        file.write(f"{username} {password}\n")
    return SUCCESS('User registered successfully')

def login_authentication(conn, cmd, users):
    """
    Task 2.3 Login authentication

        It can also be implemented according to the NTLM certification process to obtain Task 3.2 and 3.5 scores
    :param conn: socket connection to the client
    :param cmd: Instruction string
    :param users: The dict to hold information about all users
    :return: feedback message: str, login_user: str
    """
    # TODO: finish the codes
    username = cmd[1]
    pwd= cmd[2]
    if username not in users:
        return FAILURE('User does not exist'), None
    elif hmac.compare_digest(pwd, users[username]):
        return SUCCESS('Login successful'), username
    else:
        return FAILURE('Invalid username or password'), None

def server_message_encrypt(message):
    """
    Task 3.1 Determine whether the command is "login", "register", or "changepwd",
    If so, it encrypts the password in the command and returns the encrypted message and Password
    Otherwise, the original message and None are returned
    :param message: str message sent to server:
    :return encrypted message: str, encrypted password: str
    """
    # finish the codes
    cmd_parts = message.split()
    if cmd_parts[0] in ['login', 'register', 'changepwd'] and len(cmd_parts) == 3:
        encrypted_password = ntlm_hash_func(cmd_parts[2])
        # print(f'original password: {cmd_parts[2]}')
        # print(f'encrypted_password: {encrypted_password}')
        return f"{cmd_parts[0]} {cmd_parts[1]} {encrypted_password}", encrypted_password
    return message, None


def generate_challenge():
    """
    Task 3.2
    :return information: bytes random bytes as challenge message
    """
    # finish the codes
    # 8 random bytes
    return os.urandom(8)

def calculate_response(ntlm_hash, challenge):
    """
    Task 3.3
    :param ntlm_hash: str encrypted password
    :param challenge: bytes random bytes as challenge message
    :return expected response
    """
    # finish the codes
    return hmac.new(key=ntlm_hash.encode(), msg=challenge, digestmod=hashlib.sha256).hexdigest()


def server_response(server, password_hash):
    """
    Task 3.4 Receives the server response and determines whether the message returned by the server is an authentication challenge.
    If it is, the challenge will be authenticated with the encrypted password, and the authentication information will be returned to the server to obtain the login result
    Otherwise, the original message is returned
    :param server: socket server
    :param password_hash: encrypted password
    :return server response: str
    """
    # finish the codes
    response = server.recv(1024).decode('utf-8')
    if response.startswith('challenge:'):
        challenge = response.split(':')[1].encode()
        response_hash = calculate_response(password_hash, challenge)
        server.sendall(response_hash.encode())
        return server.recv(1024).decode('utf-8')
    return response

def login_cmds(receive_data, users, login_user):
    """
    Task 4 Command processing after login
    :param receive_data: Received user commands
    :param users: The dict to hold information about all users
    :param login_user: The logged-in user
    :return feedback message: str, login user: str
    """
    # finish the codes
    feedback = ""

    command_parts = receive_data.split()
    command = command_parts[0].lower()

    if command == "sum":
        # Addition
        if len(command_parts) < 2:
            feedback = "Please enter the numbers to be added"
            return FAILURE(feedback), login_user
        try:
            numbers = list(map(float, command_parts[1:]))
            result = sum(numbers)
            feedback = f"Sum: {result}"
        except ValueError:
            feedback = "Error: Please provide valid numbers."
            return FAILURE(feedback), login_user
        return SUCCESS(feedback), login_user

    elif command == "multiply":
        # Multiplication
        if len(command_parts) < 2:
            feedback = "Please enter the numbers to be multiplied"
            return FAILURE(feedback), login_user
        try:
            numbers = list(map(float, command_parts[1:]))
            result = 1
            for num in numbers:
                result *= num
            feedback = f"Product: {result}"
        except ValueError:
            feedback = "Error: Please provide valid numbers."
            return FAILURE(feedback), login_user
        return SUCCESS(feedback), login_user

    elif command == "subtract":
        # Subtraction
        if len(command_parts) != 3:
            feedback = "Error: Subtraction requires exactly two numbers."
            return FAILURE(feedback), login_user
        else:
            try:
                num1 = float(command_parts[1])
                num2 = float(command_parts[2])
                result = num1 - num2
                feedback = f"Difference: {result}"
            except ValueError:
                feedback = "Error: Please provide valid numbers."
                return FAILURE(feedback), login_user
            return SUCCESS(feedback), login_user

    elif command == "divide":
        # Division
        if len(command_parts) != 3:
            feedback = "Error: Division requires exactly two numbers."
        else:
            try:
                num1 = float(command_parts[1])
                num2 = float(command_parts[2])
                if num2 == 0:
                    feedback = "Error: Division by zero."
                else:
                    result = num1 / num2
                    feedback = f"Quotient: {result}"
            except ValueError:
                feedback = "Error: Please provide valid numbers."
                return FAILURE(feedback), login_user
        return SUCCESS(feedback), login_user

    elif command == "changepwd":
        # Change password
        if len(command_parts) != 2:
            feedback = "Error: Please provide a new password."
            return FAILURE(feedback), login_user
        else:
            new_password = ntlm_hash_func(command_parts[1])
            users[login_user] = new_password
            with open(user_inf_txt, 'r') as file:
                lines = file.readlines()
            modified_lines = []
            for line in lines:
                if line=='\n':
                    continue
                user, password = line.strip().split()
                if user == login_user:
                    modified_line = f'{user} {new_password}\n'
                else:
                    modified_line = f'{user} {password}\n'
                modified_lines.append(modified_line)

            with open(user_inf_txt, 'w') as file:
                file.writelines(modified_lines)
            feedback = "Password changed successfully."
            return SUCCESS(feedback), login_user

    elif command in ["?", "help"]:
        # Help
        feedback = (
            "Available commands:\n"
            "1. sum $(number1) $(number2) ... : Cumulative addition.\n"
            "2. multiply $(number1) $(number2) ... : Cumulative multiplication.\n"
            "3. subtract $(number1) $(number2) : Subtract two numbers.\n"
            "4. divide $(number1) $(number2) : Divide two numbers.\n"
            "5. changepwd $(new_password) : Change your password.\n"
            "6. help or ? : Display this help information.\n"
            "7. exit : Disconnect and stop the client program.\n"
            "8. logout : Log out of the session without disconnecting."
        )

    elif command == "exit":
        return SUCCESS("disconnected"), None

    elif command == "logout":
        feedback = "Logged out successfully."
        return SUCCESS(feedback), None

    elif command == "login":
        feedback = "already login."
        return FAILURE(feedback), login_user

    else:
        feedback = "Error: Unrecognized command. Text 'help' or '?' to get help."

    return feedback, login_user
