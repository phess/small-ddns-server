#!/usr/bin/env python3

### DDNS server menu process
import sqlite3
from sys import exit as bye
from sys import argv
import os
import configparser
import pathlib
from socket import getfqdn

## Global read-only vars
dbfile = os.environ['dbfile']
HEADER_OUTPUT_ORDER = ('hostname', 'ipaddress', 'ip6address', 'token', 'last_update', 'created_at')
DNS_SUFFIX = [ d for d in os.environ['dns_domains'].split(',') ]
MAX_HOSTNAME_LENGTH = int(os.environ['max_shortname_length'])
ddns_port = os.environ['ddns_port']
admin_email = os.environ['admin_email']

if os.environ['debug']:
    DEBUG = os.environ['debug'] in ('yes', 'true', 'y', '1', 't')
else:
    DEBUG = False

welcome_banner = '''
    *** WELCOME TO THE DDNS SERVER AT {{ ddns_fqdn }} ***

    May I take your order?
'''

class CliMenu:
    def __init__(self, prompt='> '):
        self.prompt = prompt
        self.text = '''
      M E N U
     =========

   [L] List my DDNS systems
   [A] Add new DDNS system
   [D] Delete existing DDNS system
   [Q] Quit
        '''


    def print(self):
        print(self.text)

    def grab_input(self) -> 'str':
        self.print()
        action = input(self.prompt)
        return action

def print_debug(what: 'str') -> 'None':
    ''' Print a debug message if debug is enabled.
    '''
    if DEBUG:
        debug_prefix = "***DEBUG*** "
        print(debug_prefix + what)

    return None


def __generate_token__() -> 'str':
    ''' Generate and return a token.
    '''
    import uuid
    # Strip the random UUID of its hyphens and return it as a string
    return str(uuid.uuid4()).replace('-','')

def __dbconnect__() -> 'sqlite3.Connection':
    ''' Create DB connection and return the connection object.
    '''
    try:
        global dbfile
        return sqlite3.connect(dbfile)
    except Error as e:
        print(e)
        raise e

def __do_dbquery__(column: 'str', value: 'str', 
                   fields: 'tuple') -> 'tuple':
    ''' Do a select on the database with a single search field and value,
        bringing /fields/ as the contents of the tuple.
    '''
    tablename = 'clients'
    #dbconn = __dbconnect__()
    with __dbconnect__() as dbconn:
        dbconn.row_factory = sqlite3.Row
        dbconn.row_factory = sqlite3.Row
        cursor = dbconn.cursor()
        dbcmd = f'''SELECT {','.join(fields)} FROM {tablename} where {column} = "{value}";'''
        print_debug(f"Will run {dbcmd}")
        result = cursor.execute(dbcmd)
    return tuple(result.fetchall())

def __do_dbquery2__(column: 'str', value: 'str', 
                   fields: 'tuple') -> 'tuple':
    ''' Do a select on the database with a single search field and value,
        bringing /fields/ as the contents of the tuple.
    '''
    tablename = 'clients'
    #dbconn = __dbconnect__()
    with __dbconnect__() as dbconn:
        dbconn.row_factory = sqlite3.Row
        cursor = dbconn.cursor()
        dbcmd = f'''SELECT {','.join(fields)} FROM {tablename} where {column} = "{value}";'''
        print_debug(f"Will run {dbcmd}")
        result = cursor.execute(dbcmd)
    return tuple(result.fetchall())

def tabulate_systems(systems: 'tuple'):
    ''' Receives the output of a __do_dbquery__ i.e. a tuple of dicts.
        Returns a tuple containing the headers as the first row and their
        values per-row as rows, e.g.
        (
            ('fruit_name', 'color', 'size'),
            ('apple', 'red', 'medium'),
            ('grape', 'green', 'small'),
            ('watermelon', 'green', 'large'),
        )
    '''
    # Headers are hardcoded
    global HEADER_OUTPUT_ORDER
    header_length = { name:len(name) for name in HEADER_OUTPUT_ORDER }
    print(header_length)
    column_length = {}
    try:
        for col in HEADER_OUTPUT_ORDER:
            print_debug(f'calculating column_length of {col}')
            column_length[col] = max([ len(row[col]) for row in systems ]) 
    except Exception as e:
        print(col)
        raise e
    output_column_length = { col:max(header_length[col],column_length[col]) for col in HEADER_OUTPUT_ORDER }
    ret_rows = [ 
            [ row[col] for col in HEADER_OUTPUT_ORDER ] for row in systems
    ]
    # Print header lines
    for col in HEADER_OUTPUT_ORDER:
        format_str = '%%{}s'.format(output_column_length[col])
        print(format_str % col,)
    # Print dashes of the same length as headers
    for col in HEADER_OUTPUT_ORDER:
        print(output_column_length * '-', end='')
    
    # Print actual rows
    for row in systems:
        for col in HEADER_OUTPUT_ORDER:
            format_str = '%%{}s'.format(output_column_length[col])
            print(format_str % row[col],)


def pretty_print_system_list(systems: 'tuple') -> None:
    ''' Print a system list as best I can.
        Ideally, this would be exactly like sqlite3 does with:
        .mode column
        select * from clients where owner=<username here>;
    '''
    #global HEADER_OUTPUT_ORDER
    indent = 2 * ' '
    line_template = f'{{indent}}{{idx:>}} {{hostname:<{MAX_HOSTNAME_LENGTH+4}}}|' + \
                    '{token:^32}|{ip4:^15}|{ip6:^39}|' + \
                    '{created:^19}|{updated:^19}'
    #enum_template = 'System #{idx} (created {created}, updated {updated})'
    pretty_header = line_template.format(indent=indent, idx='   ',
                                        hostname="HOSTNAME",
                                        ip4="IPv4",
                                        ip6="IPv6",
                                        token="TOKEN",
                                        created="CREATED AT",
                                        updated="LAST UPDATE"
    )
    print(pretty_header)
    for idx,system in enumerate(systems):
        ip4 = system['ipaddress']
        ip6 = system['ip6address']
        if not ip4:
            ip4='<undefined>'
        if not ip6:
            ip6='<undefined>'
        print(line_template.format(indent=indent,
                              idx=f'[{idx}]',
                              hostname=system['hostname'],
                              ip4=ip4,
                              ip6=ip6,
                              token=system['token'],
                              created=system['created_at'],
                              updated=system['last_update']
                            )
        )
    print(f"----[{len(systems)} systems listed]----")


def list_systems(username: 'str') -> 'int':
    ''' List systems belonging to given username
    '''
    systemlist = __get_systems_by_user__(username)
    pretty_print_system_list(systemlist)
    return 0

def __get_systems_by_user__(username: 'str', fields='*') -> 'tuple':
    ''' List all systems owned by user /username/
    '''
    return __do_dbquery__(column='owner', value=username, fields=fields)

def list_user_systems(username: 'str') -> 'int':
    ''' List hostname of all systems belonging to given user.
    '''
    systemlist = __get_systems_by_user__(username, fields='hostname')
    pretty_print_system_list(systemlist)
    return 0
    



def __add_system_to_db__(username: 'str', hostname: 'str') -> 'str':
    ''' Add a new system to the database.
        Parameters:
          - username to own the new system
          - hostname of the new system
        Return values:
          - string-formatted token to be used as primary key on the database
    '''
    if __do_dbquery__(column='hostname', value=hostname, fields='*'):
        return 'EXISTS'
    # Generate token
    token = __generate_token__()
    with __dbconnect__() as dbconn:
        cursor = dbconn.cursor()
        dbcmd = f'''INSERT INTO clients (token, hostname, owner, created_at, last_update) VALUES 
                ("{token}", "{hostname}", "{username}", datetime('now'), datetime('now'));'''
        print_debug(f"Will run {dbcmd}")
        result = cursor.execute(dbcmd)
        dbconn.commit()
        return token


def hostname_is_valid(hostname: 'str') -> 'bool':
    ''' Validate that a hostname complies to requirements, i.e.
        the leftmost component -- the shortname -- contains only letters or numbers or ``-``,
        whereas the rest of the components (if any) contain the same as the shortname or
        underscores.
        VALID hostnames:
          - x.lab.example.com
          - my-host.lab.example.com
          - my-host.at.home.lab.example.com
          - my.host-at-home.lab.example.com
          - my.host_at_home.lab.example.com  <== underscores in the domain part!
        INVALID hostnames:
          - my_host.lab.example.com   <== underscores in the shortname part!
        
        Ensure also some size constraints:
          - Total hostname should be longer than 1 character; we don't want people registering e.g.
            z.lab.example.com for themselves. Let's ensure single-letter subdomains are used
            for group-wide purposes.
          - Total hostname excluding DNS_PREFIX should not be longer than 40 characters either.
    '''
    global MAX_HOSTNAME_LENGTH
    import re
    # Enforce size constraints
    hostname_length = len(hostname)
    if not ( 1 < hostname_length <= MAX_HOSTNAME_LENGTH ):
        print_debug(f"Hostname '{hostname}' ({hostname_length} characters) is longer than the maximum allowed length of {MAX_HOSTNAME_LENGTH}")
        return False
    # Split received hostname into shortname and domainname if a dot is present
    if '.' in hostname:
        shortname, domainname = hostname.split('.', 1)
    else:
        shortname = hostname
        domainname = ''
    shortname_chars = re.compile(r'^[a-zA-Z0-9-]+$')
    domainname_chars = re.compile(r'^[a-zA-Z0-9_.-]*$')
    # Determine if all characters are valid, return false immediately if not
    chars_are_valid = bool(shortname_chars.match(shortname) and domainname_chars.match(domainname))
    if not chars_are_valid:
        return False
    
    # Return true if we reach this point :)
    return True
    

def match_against_a_suffix(hostname: 'str', suffix: 'str') -> str:
    left = hostname
    right = '.' + suffix.lstrip('.')
    #generic_match_length = len(left) + len(right)
    print_debug(f'matching {left} against {right}')
    for i in range(len(right), 0, -1):
        # juxtapose left to right's last `i` characters
        # i.e. given left = 'given-hostname.suf' & right = 'suffix.example.com'
        # try    given-hostname.suf + m
        # then   given-hostname.suf + om
        # ....
        # then   given-hostname.suf + example.com
        # ....
        # then   given-hostname.suf + fix.example.com (MATCH! -> STOP!)
        composition = left + right[i:]
        print_debug(f'Does this work? {composition}')
        if composition.startswith(left) and composition.endswith(right):
            print_debug(f"hostname and suffix match at {composition}")
            return composition
        
    # Quit this function
    return

def find_possible_fqdns(hostname: 'str', suffix_list: 'list') -> list:
    ''' Finds all possible matches between the given hostname and the known suffix list.
    '''
    possible_fqdns = [ match_against_a_suffix(hostname, n) for n in suffix_list ]
    possible_fqdns = [ f for f in possible_fqdns if f is not None ]
    return possible_fqdns
    
def add_system(username: 'str') -> str:
    ''' Add a new system to the database.
        Required parameters: hostname (prompted), username
    '''
    message = ''
    print("  Add new system under {}\n".format(DNS_SUFFIX) +
          "  Type the new hostname to add, excluding {}\n".format(DNS_SUFFIX) +
          "  Example: myhost -> this will create an entry for myhost.{}".format(DNS_SUFFIX))
    hostname = input("> ")
    # Remove dots from beginning of given hostname
    hostname = hostname.lstrip('.')
    # add DNS_SUFFIX to the hostname
    hostname = find_possible_fqdns(hostname, DNS_SUFFIX)
    if len(hostname) > 1:
        message += "ERROR: The hostname matches against more than one of my domains:\n"
        message += f"        {', '.join(hostname)}\n"
        return message
    elif len(hostname) < 1:
        message += f"ERROR: Can't match the given hostname to any of my domains, {','.join(DNS_SUFFIX)}\n"
        return message
    # A single hostname is guaranteed beyond this point. Let's pick that single hostname
    hostname = hostname[0]
    if hostname_is_valid(hostname):
        token = __add_system_to_db__(username, hostname)
        if token == 'EXISTS':
            message += "*** ERROR *** Hostname exists already. Choose another one.\n"
            return message
            
        else:
            ddns_listener_schema = 'https://'
            ddns_listener_fqdn = getfqdn()
            ddns_update_path = f'/token/{token}'
            ddns_cron_path = f'/cron/{token}'
            ddns_update_url = ddns_listener_schema + \
                              ddns_listener_fqdn + \
                              ddns_update_path
            ddns_cron_url = ddns_listener_schema + \
                            ddns_listener_fqdn + \
                            ddns_cron_path
            message += "SUCCESS"
            message += f" {hostname} SUCCESSFULLY created.  Please use token {token} when updating the ddns record from the host,\n like this:\n" + \
                    f"\n  curl -k --silent {ddns_update_url}\n\n"
            message += f" Alternatively, run 'curl -k --silent {ddns_cron_url} > /etc/cron.d/ddns-update' from {hostname} to ensure it will auto-update its ddns record."
    else:
        message += "*** ERROR *** Hostname is invalid.\n"
    
    return message
    

def __delete_system_from_db__(hostname: 'str') -> 'bool':
    ''' Delete a system on the database.
    '''
    with __dbconnect__() as dbconn:
        cursor = dbconn.cursor()
        dbcmd = f'''DELETE FROM clients WHERE hostname = "{hostname}"'''
        print_debug(f"Will run {dbcmd}")
        result = cursor.execute(dbcmd)
        return result


def delete_system(username: 'str') -> None:
    ''' Delete a single system by hostname.
        Parameters:
          - username: user running the command
    '''
    print("  Delete one of your systems. These are your systems:")
    systems = __get_systems_by_user__(username)
    pretty_print_system_list(systems)
    print("  Type the system number (e.g. 1 or 5 or 10) or the hostname to delete")
    response = input("> ")
    if response.isdigit():
        index_to_delete = int(response)
        if index_to_delete <= len(systems):
            hostname_to_delete = systems[index_to_delete]['hostname']
        else:
            print(f"***ERROR*** Tried to delete system number {response} but you have only " +
                  f"{len(systems)} systems")
            return False
    else:
        hostname_to_delete = response
    
    user_hostnames = [ s['hostname'] for s in systems ]
    if hostname_to_delete in user_hostnames:
        result = __delete_system_from_db__(hostname_to_delete)
        print(f"Successful? {bool(result)}")

def end_session(*args) -> None:
    ''' Prints something nice to the user, then does sys.exit()
    '''
    global admin_email
    end_message = f'''
    
    *** Bye-bye, {user}. Thanks for passing by. You are always welcome to come back for all your DDNS needs. ***
    
    *** Let us know at {admin_email} if you have any comments, suggestions, or concerns about this DDNS system. ***
    
    '''
    print(end_message)
    bye()


def warn_on_narrow_terminal(min_columns) -> None:
    ''' Issue a text warning if terminal width is less than the given value.
    '''
    cur_columns = os.get_terminal_size().columns
    if cur_columns < min_columns:
        print('+-------------------------+\n' + \
              '| ugh!  >_<   too narrow! |\n' + \
              '+-------------------------+\n' + \
              '\n' + \
              f'WARNING: this terminal window is narrow. I work better with {min_columns}' + \
              f' columns but this terminal is {cur_columns} columns wide.')


def handle_input(letter: 'str', user: 'str') -> None:
    print_debug(f"handling input: '{letter}'")
    footer = '-------------------------------------'
    actions = {
            'L': list_systems,
            'A': add_system,
            'D': delete_system,
            'Q': end_session
            }
    try:
        letterup = letter.upper()
        assert letterup in actions.keys()
        action = actions.get(letterup)
        print_debug(f"will run function {action.__name__}")
        result_message = action(user)
        print(footer)
        print("*** RESULT ***")
        print(result_message)
        print(footer)
    except AssertionError:
        print(f'\n****** Letter {letter} is not one of {", ".join(actions.keys())} ******\nTry again.\n')
    except Exception as e:
        print('*** Uh-oh... ***')
        raise e



if __name__ == '__main__':
    user = os.getlogin()
    #user = argv[-1]
    menu = CliMenu()
    print(welcome_banner)
    while True:
        warn_on_narrow_terminal(179)
        # try-except below will shut down gracefully on ctrl-c
        try:
            typed = menu.grab_input()
            handle_input(typed.strip(), user)
        except KeyboardInterrupt:
            exit(0)



#vi:ts=4 sw=4 et ai tw=100
