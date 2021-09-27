#!/usr/bin/env -S python3 -u

import base64
import string
import sys
import time
from secret import *


def recvmsg():
    buf = input()
    enc_msg = base64.b64decode(buf.encode("ascii"))
    msg = bytes((c^i^0xff) & 0xff for i,c in enumerate(enc_msg))
    s = msg.decode("ascii")
    return s

def sendmsg(s):
    msg = s.encode("ascii")
    enc_msg = bytes((c^i^0xff) & 0xff for i,c in enumerate(msg))
    buf = base64.b64encode(enc_msg).decode("ascii")
    print(buf, flush=True)

# --------------------------------------

class User:
    __slots__ = ["username", "passwordhash", "priviledged", "restricted"]

    def __init__(self, name, pwhash, ispriviledge, isrestricted):
        self.username = name
        self.passwordhash = pwhash
        self.priviledged = ispriviledge
        self.restricted = isrestricted

    def dumps(self):
        return f"{self.username}:{self.passwordhash}:{'1' if self.priviledged else ''}:{'1' if self.restricted else ''}"


class File:
    __slots__ = ["filename", "permission", "owner", "group", "readfunc"]

    def __init__(self, name, perm, ownergroup, func):
        self.filename = name
        self.permission = perm
        self.owner, self.group = ownergroup.split(":") 
        self.readfunc = func

    def read(self):
        return self.readfunc()
    
    @staticmethod
    def readfunc_helpme():
        return '''I don't have permission to read 'flag' file, can you help me get it?
I think baba's priviledge is higher than me. Because of his poor memory, I believe his password only contains digital and no longer than 4.
There is also a good news that the 'shadow' file is world-readable, which stores `passwordhash` of all users.
'''

    @staticmethod
    def readfunc_shadow():
        global global_users
        result = ""
        for u in global_users.values():
            result += u.dumps() + "\n"
        return result

    @staticmethod
    def readfunc_source():
        with open(__file__, "r") as f:
            allcontent = f.read()
        return allcontent

    @staticmethod
    def readfunc_flag():
        return FLAG+"\n"


class Shell:
    __slots__ = ["username", "prompt", "banner_template"]
    def __init__(self, name):
        self.username = name
        self.prompt = "# " if self.username == "root" else "$ "
        self.banner_template = "Welcome, {}!\nType 'help' to see valid commands.\n"

    def interactive(self):
        sendmsg(self.banner_template.format(self.username) + self.prompt)
        while True:
            line = recvmsg()
            line = line.strip()
            if line:
                tokens = line.split()
                cmd, args = tokens[0], tokens[1:]
                if cmd == "exit":
                    break
                r = self.handle_command(cmd, args)
            else:
                r = ""
            sendmsg(r + self.prompt)

    def handle_command(self, cmd, args):
        if cmd == "help":
            result = Shell.command_help()
        elif cmd == "ls":
            result = Shell.command_ls()
        elif cmd == "cat":
            result = Shell.command_cat(args)
        elif cmd == "passwd":
            result = Shell.command_passwd(args)
        else:
            result = f"{cmd}: command not found\n"
        return result

    @staticmethod
    def command_help():
        result = '''- help          : Show this message
- exit          : Exit the shell
- ls            : List information about files
- cat FILE      : Concatenate FILE to standard output
- passwd [USER] : Change USER's password
'''
        return result
    
    @staticmethod
    def command_ls():
        global global_files
        result = ""
        for f in global_files.values():
            result += f"-{f.permission}\t{f.owner} {f.group}\t {f.filename}" + "\n"
        return result
    
    @staticmethod
    def command_cat(args):
        global global_files
        global global_loginuser
        if not args:
            return "cat: must specify a file\n"
        filename = args[0]
        if filename not in global_files:
            return f"cat: {filename}: No such file or directory\n"
        f = global_files[filename]

        user_perm = f.permission[0:3]
        group_perm = f.permission[3:6]
        other_perm = f.permission[6:9]
        if (global_loginuser == f.owner and user_perm[0] == 'r') \
                or (global_loginuser == f.group and group_perm[0] == 'r') \
                or (f.owner != global_loginuser != f.group and other_perm[0] == 'r') \
                or global_loginuser == "root":
            return f.read()
        else:
            return f"cat: {filename}: Permission denied\n"

    @staticmethod
    def command_passwd(args):
        global global_users
        global global_loginuser
        
        choosen_username = args[0] if args else global_loginuser
        if choosen_username not in global_users:
            return f"passwd: user '{choosen_username}' does not exist\n"
        
        current_user = global_users[global_loginuser]
        choosen_user = global_users[choosen_username]
        
        regeneratetoken = False
        showwarning = False
        if choosen_username == global_loginuser:
            regeneratetoken = True
        elif current_user.priviledged:
            showwarning = True
        else:
            return f"passwd: You may not modify password for {choosen_username}.\n"
        
        if showwarning:
            sendmsg("Warning: Change other user's password may cause their token invalid!\n" + "New password: ")
        else:
            sendmsg("New password: ")
        
        newpw = recvmsg()
        if (not 1 <= len(newpw) <= 12) or set(newpw)-set(string.digits+string.ascii_letters):
            return "passwd: invalid input.\npasswd: password unchanged.\n"
        newpasswordhash = generate_passwordhash(choosen_username, newpw)
        choosen_user.passwordhash = newpasswordhash

        result = "passwd: password updated successfully.\n"
        if regeneratetoken:
            newtoken = generate_token(choosen_username, newpasswordhash)
            newtoken_encrypted = encrypt_token(newtoken)
            result += f"passwd: new token (encrypted): {newtoken_encrypted}.\n"

        return result

# --------------------------------------

def handle_login():
    global global_users
    
    sendmsg("Login: ")
    username = recvmsg()
    if username in global_users:
        u = global_users[username]
    else:
        u = None

    succ = False
    logintype = recvmsg()
    if logintype == "password":
        sendmsg("Password: ")
        password = recvmsg()
        if u:
            succ = check_password(username, password, u.passwordhash)
    elif logintype == "token":
        token = recvmsg()
        if u:
            succ = check_token(username, token, u.passwordhash)
    else:
        raise Exception
    
    if succ:
        if u.restricted and logintype == "password":
            return None, "Login incorrect: prohibit password"
        else:
            return username, "Login successfully"
    else:
        time.sleep(3)
        return None, "Login incorrect"

# --------------------------------------

def main():
    global global_loginuser
    while True:
        global_loginuser = None
        username, errmsg = handle_login()
        sendmsg(errmsg + "\n")
        if username:
            global_loginuser = username
            shell = Shell(username)
            shell.interactive()
        global_loginuser = None
        sendmsg("\n")

################################################################################

global_users = {
    "root" : User("root", "*", True, True),
    "baba" : User("baba", "b7a44ef9e4c00312fcf98c6e0833b10e", True, False),
    "baby" : User("baby", "0b868bbe9a1c9b78e762de5abf662e59", False, False)
}

global_files = {
    "helpme.txt" : File("helpme.txt", "rw-------", "baby:baby", File.readfunc_helpme),
    "shadow" : File("shadow", "rw-r--r--", "root:root", File.readfunc_shadow),
    "server.py" : File("server.py", "rw-r-----", "root:baba", File.readfunc_source),
    "flag" : File("flag", "r--------", "root:root", File.readfunc_flag)
}

global_loginuser = None

if __name__ == "__main__":
    try:
        main()
    except EOFError:
        sys.exit(0)
    except Exception:
        sys.exit(1)

