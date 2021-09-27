#!/usr/bin/env -S python3 -u

import argparse
import base64
import ctypes
import getpass
import os
import readline
import socket
import sys

def recvmsg():
    global global_remoteconnection
    buf = b""
    while True:
        c = global_remoteconnection.recv(1)
        if c == b"":
            raise EOFError
        if c == b"\n":
            break
        buf += c
    enc_msg = base64.b64decode(buf)
    msg = bytes((c^i^0xff) & 0xff for i,c in enumerate(enc_msg))
    s = msg.decode("ascii")
    return s

def sendmsg(s):
    global global_remoteconnection
    msg = s.encode("ascii")
    enc_msg = bytes((c^i^0xff) & 0xff for i,c in enumerate(msg))
    buf = base64.b64encode(enc_msg)
    global_remoteconnection.sendall(buf+b"\n")

def readinput(prompt=""):
    return input(prompt)+"\n"

def readpassword(prompt=""):
    return getpass.getpass(prompt)

def writeoutput(s):
    print(s, end="", flush=True)

# --------------------------------------

def secure_hash(m):
    global global_libsmartcard
    if len(m) != 16:
        raise Exception
    buf = ctypes.create_string_buffer(m, 16)
    global_libsmartcard.secure_hash(bytes(m), buf)
    return buf.raw

def secure_decrypt(c):
    global global_libsmartcard
    if len(c) != 16:
        raise Exception
    buf = ctypes.create_string_buffer(c, 16)
    global_libsmartcard.secure_decrypt(bytes(c), buf)
    return buf.raw


def decrypt_token(encrypted_token):
    buf = bytes.fromhex(encrypted_token)
    if len(buf) != 16:
        raise Exception
    return secure_decrypt(buf).hex()

def generate_passwordhash(username, password):
    tmp1 = username.encode("ascii")
    tmp2 = password.encode("ascii")
    if len(tmp1) > 4 or len(tmp2) > 12:
        raise Exception
    buf = tmp1.ljust(4, b"\0") + tmp2.ljust(12, b"\0")
    return secure_hash(buf).hex()

def check_token(username, token, passwordhash):
    if len(token) != 32 or set(token)-set("0123456789abcdef"):
        return False
    if len(passwordhash) != 32 or set(passwordhash)-set("0123456789abcdef"):
        return False
    return secure_decrypt(bytes.fromhex(token)) == secure_hash(bytes.fromhex(passwordhash))

# --------------------------------------

def do_login(username=None):
    global global_libsmartcard
    if not username:
        username = readinput("Login: ").strip()

    user_login_tokens_file = ".user_login_tokens"
    user_login_token = None
    if global_libsmartcard and os.path.exists(user_login_tokens_file):
        with open(user_login_tokens_file, "r") as f:
            token_lines = f.readlines()
        for line in token_lines[::-1]:
            line = line.strip()
            if line and not line.startswith("#"):
                name, encrypted_token = line.split(":")
                if name == username:
                    user_login_token = decrypt_token(encrypted_token)
                    break
    
    r = recvmsg()
    if r != "Login: ":
        raise Exception
    sendmsg(username)

    if user_login_token:
        sendmsg("token")
        sendmsg(user_login_token)
    else:
        sendmsg("password")
        r = recvmsg()
        if r != "Password: ":
            raise Exception
        password = readpassword("Password: ")
        sendmsg(password)
        
    r = recvmsg()
    succ = False
    if r.startswith("Login successfully"):
        succ = True
    elif r.startswith("Login incorrect"):
        succ = False
    else:
        raise Exception
    writeoutput(r)
    writeoutput("\n")

    if not succ:
        if user_login_token:
            writeoutput("Login by token failed, give your password to check if it is a valid token.\n")
            password = readpassword("Password: ")
            passwordhash = generate_passwordhash(username, password)
            if check_token(username, user_login_token, passwordhash):
                writeoutput("Your token is valid, but may be outdated.\n")
            else:
                writeoutput("Your token is invalid.\n")
            writeoutput("Please login by password and type 'passwd' to update your password and regenerate token.\n")
        return False

    return True


def shell_interact():
    while True:
        noecho = False
        waitforcmd = False
        
        retstr = recvmsg()
        if retstr.strip().endswith("assword:"):
            noecho = True
            outmsg, prompt = "", retstr
        elif retstr.endswith("$ ") or retstr.endswith("# "):
            waitforcmd = True
            outmsg, prompt = retstr[:-2], retstr[-2:]
        writeoutput(outmsg)

        if noecho:
            inputstr = readpassword(prompt)
        else:
            inputstr = readinput(prompt)
        sendmsg(inputstr)

        if waitforcmd and inputstr.strip() == "exit":
            break


def main():
    global global_remoteconnection

    parser = argparse.ArgumentParser()
    parser.add_argument("destination", metavar="[user@]host", help="remote host address and login user. if user is omitted, it will be asked during runtime")
    parser.add_argument("-p", help="remote port. default is 22021", metavar="port", type=int, default=22021)
    parser.add_argument("-k", help="keep connection even after shell exit", action="store_true")
    args = parser.parse_args()

    destination = args.destination
    pos = destination.find("@")
    if pos != -1:
        default_username = destination[:pos]
        remoteaddr = destination[pos+1:]
    else:
        default_username = None
        remoteaddr = destination
    remoteport = args.p
    keep_remoteconnection = args.k


    global_remoteconnection = socket.socket()
    try:
        global_remoteconnection.connect((remoteaddr, remoteport))
    except ConnectionRefusedError:
        writeoutput(f"{sys.argv[0]}: connect to host {remoteaddr} port {remoteport}: Connection refused\n")
        global_remoteconnection.close()
        return

    while True:
        if do_login(default_username):
            shell_interact()
        r = recvmsg()
        if r != "\n":
            raise Exception

        if not keep_remoteconnection:
            break
        writeoutput("\n")
        default_username = None
    
    global_remoteconnection.close()


global_remoteconnection = None
try:
    global_libsmartcard = ctypes.CDLL("libsmartcard.so")
except OSError:
    global_libsmartcard = None

if __name__ == "__main__":
    try:
        main()
    except:
        os._exit(0)

