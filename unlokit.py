import os
import sys
import re
import json

VERSION = "0.1a"

# TERMINAL COLORS

NOCOLOR   = '\33[0m'
BOLD      = '\33[1m'
ITALIC    = '\33[3m'
UNDERLINE = '\33[4m'
BLINK     = '\33[5m'
BLINK2    = '\33[6m'
SELECTED  = '\33[7m'

BLACK  = '\33[30m'
RED    = '\33[31m'
GREEN  = '\33[32m'
YELLOW = '\33[33m'
BLUE   = '\33[34m'
VIOLET = '\33[35m'
BEIGE  = '\33[36m'
WHITE  = '\33[37m'

BLACKBG  = '\33[40m'
REDBG    = '\33[41m'
GREENBG  = '\33[42m'
YELLOWBG = '\33[43m'
BLUEBG   = '\33[44m'
VIOLETBG = '\33[45m'
BEIGEBG  = '\33[46m'
WHITEBG  = '\33[47m'

GREY    = '\33[90m'
RED2    = '\33[91m'
GREEN2  = '\33[92m'
YELLOW2 = '\33[93m'
BLUE2   = '\33[94m'
VIOLET2 = '\33[95m'
CYAN    = '\33[96m'
WHITE2  = '\33[97m'

GREYBG    = '\33[100m'
REDBG2    = '\33[101m'
GREENBG2  = '\33[102m'
YELLOWBG2 = '\33[103m'
BLUEBG2   = '\33[104m'
VIOLETBG2 = '\33[105m'
BEIGEBG2  = '\33[106m'
WHITEBG2  = '\33[107m'

# Ensure ANSI/VT100 Escape Codes are properly virtualized
os.system('') # On Windows, this sets Console Mode to Enable Virtual Terminal processing

def parse(loki_fd) -> list:
    print(f"{CYAN}[+] Parse LOKI...{NOCOLOR}")
    res = []
    previous_line: str = None
    for line in loki_fd.readlines():
        # hrex = "(\d{8}T\d{2}:\d{2}:\d{2}Z) (.*?) LOKI: (.*?): (.*?(?=\Z|\n\d{8}T\d{2}:\d{2}:\d{2}Z))"
        hrex = "(.*?) (.*?) LOKI: (.*?): (.*)$" # Fails on multi-line entries
        hmatch = re.match(hrex, line, re.DOTALL)
        if not hmatch: # No results: bad parsing or continuation of previous line.
            print(f"{YELLOW}[*] Parser: Multi-line entry detected.{NOCOLOR}")
            # Pops previous (partial) entry
            e = res.pop()
            # Rebuild entry from scratch adding the new line discovered
            line = previous_line[:-1] + line
            previous_line = line
            hmatch = re.match(hrex, line, re.DOTALL)
            if not hmatch: # No results: bad parsing of unknown format
                print(f"{RED}[!] Parser Error: Unable to handle multi-line entry!{NOCOLOR}")
                return []
        previous_line = line
        hgroups = hmatch.groups()
        entry = {
            "timestamp": hgroups[0],
            "hostname": hgroups[1],
            "log_level": hgroups[2]
        }
        body = hgroups[3]
        #brex = "([A-Z\d_]+): (.+?)(?= [A-Z\d_]+: |$)"
        brex = "([A-Z\d_]+):(.*?)(?= [A-Z\d_]+: |$)"
        bgroupslist = re.findall(brex, body)
        for key, value in bgroupslist:
            key = key.lower()
            value = value.strip()
            if key.startswith("reason_"):
                if "reasons" in entry and entry["reasons"]: entry["reasons"].append(value)
                else: entry["reasons"] = [value]
            else:
                entry[key] = value
        res.append(entry)
    return res

def get_unique(loki: list, key: str) -> list:
    u = []
    for e in loki:
        v = e[key]
        if v not in u:
            u.append(v)
    return u

def get_total_match(loki: list, key: str, value: str) -> int:
    s = 0
    for e in loki:
        if e[key] == value:
            s += 1
    return s

def to_json(loki: list) -> None:
    print(json.dumps(loki, indent=2))

def summary(loki: list) -> None:
    hostnames = get_unique(loki, "hostname")
    modules = get_unique(loki, "module")
    print(f"{CYAN}[+] Hostname(s): {YELLOW2}{', '.join(hostnames)}{NOCOLOR}")
    print(f"{CYAN}[+] Modules: {BLUE2}{', '.join(modules)}{NOCOLOR}")
    log_notice = get_total_match(loki, "log_level", "Notice")
    log_info = get_total_match(loki, "log_level", "Info")
    log_varning = get_total_match(loki, "log_level", "Warning")
    log_error = get_total_match(loki, "log_level", "Error")
    print(f"{CYAN}[+] Results: {RED}{log_error} Errors{CYAN}, {YELLOW}{log_varning} Warnings{CYAN}, {BLUE2}{log_info} Info{CYAN}, {log_notice} Notices.{NOCOLOR}")

def pretty(loki: list) -> None:
    modules = get_unique(loki, "module")
    for mod in modules:
        print(f"\n{CYAN}[+] Module {mod}:{NOCOLOR}")
        for e in loki:
            if not e["module"] == mod: continue
            for k in e:
                v = e[k]
                if not v:
                    continue
                if k == "timestamp":
                    time = e[k].split("T")
                    # print(f"{YELLOW2}{time[0]} {time[1][:-1]} +00:00{NOCOLOR} ", end='')
                    # print(f"{YELLOW2}{time[1][:-1]}{NOCOLOR} ", end='')
                    continue
                elif k == "hostname":
                    # print(f"{BOLD}{e[k]}{NOCOLOR} ", end='')
                    continue
                elif k == "module":
                    continue
                elif k == "log_level":
                    if v == "Notice": print(f"{CYAN}[{e['module']}][{e[k]}]{NOCOLOR} ", end='')
                    elif v == "Info": print(f"{BLUE2}[{e['module']}][{e[k]}]{NOCOLOR} ", end='')
                    elif v == "Warning": print(f"{YELLOW}[{e['module']}][{e[k]}]{NOCOLOR} ", end='')
                    elif v == "Error": print(f"{RED}[{e['module']}][{e[k]}]{NOCOLOR} ", end='')
                    elif v == "Result": print(f"{GREEN}[{e['module']}][{e[k]}]{NOCOLOR} ", end='')
                    else: print(f"{e[k]} ", end='')
                elif k == "message":
                    print(f"{BOLD}{k.upper()}{NOCOLOR}: {CYAN}{BOLD}{e[k]}{NOCOLOR} ", end='')
                elif k =="created" or k =="modified" or k =="accessed":
                    print(f"{BOLD}{k.upper()}{NOCOLOR}: {YELLOW2}{e[k]}{NOCOLOR} ", end='')
                elif k == "match":
                    print(f"{BOLD}{k.upper()}{NOCOLOR}: {RED2}{BOLD}{e[k]}{NOCOLOR} ", end='')
                else:
                    print(f"{BOLD}{k.upper()}{NOCOLOR}: {e[k]} ", end='')
            print("")

def main() -> None:

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} [p(retty)|j(son)] <path/to/loki.log>")
        exit(1)
    unlokit_opt = str(sys.argv[1])
    loki_path = os.path.abspath(sys.argv[2])
    if unlokit_opt.lower() in ["pretty", "p"]:
        unlokit_opt = "pretty"
    elif unlokit_opt.lower() in ["json", "j"]:
        unlokit_opt = "json"
    else:
        print(f"Usage: {sys.argv[0]} [p(retty)|j(son)] <path/to/loki.log>")
        print(f"Error: Provide a valid OPTION: p, j, pretty, json.")
        exit(1)

    print(f'''\
               ____    ________   ____  __ ___  __
  __ __  ____ |    |   \_____  \ |    |/ _|   |/  |_
 |  |  \/    \|    |    /   |   \|      < |   \   __\\
 |  |  /   |  \    |___/    |    \    |  \|   ||  |
 |____/|___|  /_______ \_______  /____|__ \___||__|  {BLUE2}v{VERSION}{NOCOLOR}
            \/        \/       \/        \/\n''')
    
    print(f"{CYAN}[+] Open LOKI at: {BLUE2}{loki_path}{NOCOLOR}")
    loki_fd = open(loki_path, "r")
    loki = parse(loki_fd)
    if unlokit_opt == "pretty":
        summary(loki)
        pretty(loki)
    elif unlokit_opt == "json":
        to_json(loki)
    print(f"{GREEN}[+] Done.{NOCOLOR}")

if __name__ == "__main__":
    main()
