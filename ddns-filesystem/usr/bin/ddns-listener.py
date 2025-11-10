#!/usr/bin/env python3

## Listens on a TCP port for incoming ddns updates, then updates ddns records on the database.

from http import server
from sys import argv, stderr, exit
from urllib.parse import urlparse
import sqlite3
import os
import configparser
import pathlib

from aiohttp import web
import ssl


## Global read-only vars
dbfile = '/var/lib/ddns/hosts.db'
HEADER_OUTPUT_ORDER = ('hostname', 'ipaddress', 'ip6address', 'token', 'last_update', 'created_at')
    

# Remove all spaces from DOMAINS, as well as leading and trailing commas
DNS_SUFFIXES = os.environ['DOMAINS'].replace(' ','')
DNS_SUFFIXES = DNS_SUFFIXES.strip(',')
DNS_SUFFIXES = DNS_SUFFIXES.split(',')


def myurl(schema="https://", path="") -> str:
    ''' Return e.g. 'https://ddns.example.com:8443' if PORT is not 443.
        Return e.g. 'https://ddns.example.com' if PORT is 443.
        Accepts an optional 'path' argument to append to the url, e.g.
        if path="/lala/lele" then this function will return:
          'https://ddns.example.com:8443/lala/lele'
    '''
    # We absolutely need something for the fqdn
    try:
        MYFQDN = os.environ['DDNS_FQDN']
    except NameError:
        MYFQDN = f"<this ddns server>"
    except Exception as e:
        raise e

    # Avoid appending :443 if the port is 443. Will assume port 443 if EXPOSED_PORT is not defined
    try:
        if int(os.environ['EXPOSED_PORT']) != 443:
            port = ""
        else:
            port = f":{port}"
    # KeyError means EXPOSED_PORT is not defined. Assume port 443 in this case.
    except KeyError as e:
        port = ""

    return f"{schema}{MYFQDN}{port}{path}"


MAX_HOSTNAME_LENGTH = os.environ['MAX_LENGTH']   # Excluding the DNS_SUFFIX above

try:
    DEBUG = os.environ['DDNS_DEBUG'].upper() in ('T', 'Y', 'TRUE', 'YES', '1')
    assert DEBUG is True
    print("DEBUG is ON")
except:
    DEBUG = False

def print_debug(text: 'str') -> None:
    global DEBUG
    if DEBUG:
        prefix = '***DEBUG*** '
        print(prefix + text)
    return None
    

class Listener:
    def __init__(self):
        self.ddns = Ddns()
        
    async def get_user_systems(self, request):
        user = request.match_info['user']
        print(f"will get systems belonging to user {user}")
        username = user
        return web.Response(text="")
    
    async def update_ddns_by_token(self, request):
        token = request.match_info['token']
        ipaddr = request.remote
        print(f"will update token {token} with IP address {ipaddr}")
        ipaddr = request.remote
        success = self.ddns.update_record(token=token, ip_address=ipaddr)
        if success:
            raise web.HTTPOk
        else:
            raise web.HTTPUnprocessableEntity
    
    async def delete_ddns_by_token(self, request):
        token = request.match_info['token']
        print(f"will delete token {token}")
        success = self.ddns.delete_record_by_token(token=token)
        if success:
            raise web.HTTPOk
        else:
            raise web.HTTPUnprocessableEntity
            
    async def generate_cron_line(self, request):
        token = request.match_info['token']
        url_with_path = myurl(schema='https://', path=f'/token/{token}')
        response_text_header = f"# Cron line to update the ddns server at {myurl()}"
        cron_line = f"""{response_text_header}
*/5 * * * *     nobody    /usr/bin/curl -k --silent {url_with_path}\n\n"""
        return web.Response(text=cron_line)
        raise web.HTTPOk

    async def create_host(self, request):
        hostname = request.match_info['name'] or request.match_info['hostname']
        user = request.match_info['user']
        print(f"Will create new host '{hostname}' owned by '{user}'")
        new_host = self.

    async def authenticate(self, request):
        ''' Authenticate the request based on the Bearer header.
        '''
        authz_header = request.headers.get('authorization')
        req_token = authz_header.split()[-1]
        user = self.ddns.validate_user_token(req_token):
        return user

    async def create_user(self, request):
        ''' Create a new user.
        '''
        pass

    async def home(self, request):
        print(f"running home")
        
    
    def listen(self) -> None:
        #routes = web.RouteTableDef()
        self.ddns = Ddns()
        
        self.ddns_listener = web.Application()
        self.ddns_listener.add_routes([
            web.get('/', self.home),
            web.get(r'/users/{user:\w+}', self.get_user_systems),
            web.get(r'/token/{token:\w+}', self.update_ddns_by_token),
            web.delete(r'/token/{token:\w+}', self.delete_ddns_by_token),
            web.get(r'/cron/{token:\w+}', self.generate_cron_line),
            web.post(r'/host/{name:\w+}', self.create_host),
            #web.get(r'', self.),
            #web.get(r'', self.),
            #web.get(r'', self.),
            #web.get(r'', self.),
            ])
        #self.ddns_config = self.ddns.config['main']
        ssl_dir = '/etc/ddns/'
        self.ssl_cert = ssl_dir + os.environ['SSL_CERT']
        self.ssl_key = ssl_dir + os.environ['SSL_KEY']
        self.ssl_cabundle = ssl_dir + os.environ['SSL_CA']

        # DEBUG
        for i in (self.ssl_cert, self.ssl_key, self.ssl_cabundle):
            print('self.cert, key, ca = {}'.format(i))

        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, 
                                                 cafile=self.ssl_cabundle)
        ssl_context.load_cert_chain(self.ssl_cert, self.ssl_key)
        web.run_app(self.ddns_listener, ssl_context=ssl_context)


class Ddns:
    def __init__(self):
        ## Read config file
        #homedir = pathlib.Path().home()
        #CONFIG_FILE_PATHS=(
        #    '/etc/ddns.conf',
        #    homedir / '.config' / 'ddns.conf',
        #    homedir / '.ddns.conf'
        #)
        #configfile = [ cf for cf in CONFIG_FILE_PATHS if pathlib.Path(cf).exists() ]
        #self.config = configparser.ConfigParser()

        global dbfile
        self.dbfile = dbfile
        
    def propagate_changes(self, domain: 'str') -> None:
        ''' Re-write the hosts file used by dnsmasq.
        '''
        hostsfile = f'/etc/hosts.d/{domain}'
        print_debug(f'Propagating changes in domain {domain} to {hostsfile}')
        # Grab all hostnames belonging to given domain
        ddnsreader = DdnsDbWriter(self.dbfile)
        # hosts_entries contains a list of hosts file lines
        hosts_entries = ddnsreader.get_hosts_for_hostsfile(domain=domain)
        out_str = '\n'.join(hosts_entries)
        # (over)write the hosts file in a single operation
        with open(hostsfile,'w') as outfile:
            outfile.write(out_str)
            outfile.close()

    def _did_record_change(self, token: 'str', ip_address: 'str') -> bool:
        ''' Find out if the new token-ipaddress tuple differs from the existing one.
        '''
        ddnsreader = DdnsDbWriter(self.dbfile)
        host = Host()
        host.from_db(token)
        print_debug(f'This host is this: {host.__dict__}')
        return ( host.ipv4 != ip_address and host.ipv6 != ip_address )

    def update_record(self, token: 'str', ip_address: 'str') -> bool:
        ''' Talk to whatever service handles actually updating DDNS records.
            Identify the host's domain while at that.
        '''
        ddnsreader = DdnsDbWriter(self.dbfile)
        host = Host()
        host.from_db(token)
        print_debug(f'This is this host now: {host.__dict__}')
        # Is this a real change in this host's IPv4 or IPv6?
        if host.ipv4 != ip_address and host.ipv6 != ip_address:
            ddnswriter = DdnsDbWriter(self.dbfile)
            result = ddnswriter.update_record_from_token(token=token, ip_address=ip_address, ipv6_address=None)
            # Propagate changes from DB to hostsfile if DB change occurred, else return False
            if result:
                print_debug(f'propagating domain {host.domain}')
                self.propagate_changes(host.domain)
            else:
                result = False
        
        # IP didn't change. Return True to indicate success.
        else:
            result = True
        
        return bool(result)

    def delete_record_by_token(self, token: 'str') -> bool:
        ''' Delete a record from the backend.
        '''
        ddnswriter = DdnsDbWriter(self.dbfile)
        result = ddnswriter.delete_record_by_token(token)
        return result

    def validate_user_token(self, user_token: 'str') -> bool:
        ''' Look up given user_token in the database.
        '''
        ddnsreader = DdnsDbWriter(self.dbfile)
        try:
            username = ddnsreader.get_user_from_token(user_token)
        except:
            username = ''
        return username

class Host:
    def __init__(self):
        print_debug('New empty Host object')
        self.hostname = ''
        self.token = ''
        self.ipv4 = ''
        self.ipv6 = ''
        self.domain = ''
        self.creation_time = ''
        self.last_update = ''

    def load_db(self) -> None:
        global dbfile
        self.dbreader = DdnsDbWriter(dbfile)
    
    def fqdn_to_domain(self) -> 'str':
        ''' Receives an FQDN, returns which of "my" domains matches the host.
        '''
        global DNS_SUFFIXES
        print_debug(f'Which domain does {self.hostname} match?')
        for domain in DNS_SUFFIXES:
            print_debug(f'Is {domain} in {self.hostname}?')
            if domain in self.hostname:
                print_debug(f'Hostname {self.hostname} matches domain {domain}')
                return domain
        
        print_debug('Apparently none :(')        
        return ''
        
    def populate_from_tuple(self, list_of_values) -> bool:
        ''' Receives list or tuple of values, add them to the database.
        '''
        print_debug("Entered Host.populate_from_tuple()")
        try:
            ( self.hostname,
            self.token,
            self.ipv4,
            self.ipv6,
            self.creation_time,
            self.last_update
            ) = list_of_values
            self.domain = self.fqdn_to_domain()
            print_debug(f'Host object is now this: {self.__dict__}')
            return True
        except Exception as e:
            print_debug(f'Exception {e} was raised in Host.populate_from_tuple')
            return False

    def new_with_name(self, hostname, owner) -> str:
        ''' Receives a hostname and its owner name, returns a freshly-generated token.
        '''
        token = self.__generate_token__()
        new_host = self.populate_from_tuple((hostname, token, '', '', datetime.datetime.now(), datetime.datetime.now(),))
        return new_host

    def from_db(self, token: 'str') -> bool:
        ''' Receives a database row containing all info about a host,
            generates a Host object from the row.
        '''
        self.load_db()
        print_debug('Looking up host by token:' + token)
        dbrow = self.dbreader.read_one_host(token)
        print_debug(f'Found this: {dbrow}')
        return self.populate_from_tuple(dbrow)

class DdnsDbWriter:
    def __init__(self, dbfile):
        self.dbfile = dbfile
        self.__dbcreate__()

    def __dbcreate__(self) -> None:
        ''' Create the DB tables.'''
        if not os.path.exists(self.dbfile):
            # Create an empty file
            open(self.dbfile, 'w').close()

        try:
            dbconn = self.__dbconnect__()
            cursor = dbconn.cursor()
            cmd_create_table = '''
                CREATE TABLE clients(
                    token TEXT PRIMARY KEY NOT NULL,
                    hostname TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    ipaddress TEXT,
                    ip6address TEXT,
                    created_at TIMESTAMP NOT NULL,
                    last_update TIMESTAMP NOT NULL
            );
                CREATE TABLE users(
                    name TEXT PRIMARY KEY NOT NULL,
                    user_token TEXT NOT NULL
            );'''
            cursor.execute(cmd_create_table)
            dbconn.commit()
            return dbconn.total_changes > 0
        except Exception as e:
            print(f'Failed to create the database: {e}') 
            raise(e)

    def __dbconnect__(self) -> 'sqlite3.Connection':
        ''' Create DB connection and return the connection object.
        '''
        try:
            #global dbfile
            return sqlite3.connect(self.dbfile)
        except Exception as e:
            print(e)
            raise e

    def update_record_from_token(self, token: 'str', ip_address: 'str', ipv6_address: 'str') -> bool:
        ''' Write the update to the ddns database.
        '''
        dbconn = self.__dbconnect__()
        cursor = dbconn.cursor()
        cmd_find_ip = f'''SELECT ipaddress FROM clients WHERE token = '{token}'
                '''
        dbcmd = f'''UPDATE clients SET 
                        (ipaddress, ip6address, last_update) = (
                            '{ip_address}',
                            NULL,
                            datetime('now')
                        )
                    WHERE token = '{token}'
                '''
        result = cursor.execute(dbcmd)
        dbconn.commit()
        #print(f"Result from update_record_from_token is '{ret}'")
        return dbconn.total_changes == 1
    
    def delete_record_by_token(self, token: 'str') -> bool:
        ''' Find the record identified by a token, delete it from the DB.
        '''
        dbconn = self.__dbconnect__()
        cursor = dbconn.cursor()
        dbcmd = f'''DELETE
                    FROM clients
                    WHERE token = {token}
                '''
        result = cursor.execute(dbcmd)
        dbconn.commit()
        return dbconn.total_changes == 1

    def _get_token_ip_tuple(token: 'str', ip_address: 'str') -> tuple:
        pass
    
    def read_one_host(self, token: 'str') -> tuple:
        ''' Receives hostname or tuple from kwargs, reads one host from the database.
        '''
        dbconn = self.__dbconnect__()
        cursor = dbconn.cursor()
        sorted_columns = (
            'hostname',
            'token',
            'ipaddress',
            'ip6address',
            'created_at',
            'last_update'
            )
        get_host = f'''SELECT {','.join(sorted_columns)}
                       FROM clients
                       WHERE token = '{token}' limit 1'''
        cursor.execute(get_host)
        host_found = cursor.fetchone()
        if host_found:
            return tuple(host_found)
        # No host was found
        return None

    def get_hosts_for_hostsfile(self, domain=None, owner=None) -> list:
        ''' Find all hosts in the database, produce lines containing {ip}\t{hostname}
        '''
        filterclause = ""
        if domain:
            filterclause += f"""AND hostname like '%{domain}%' """
        if owner:
            filterclause += f"""AND owner = '{owner}' """

        dbconn = self.__dbconnect__()
        cursor = dbconn.cursor()
        getipv4 = f'''SELECT ipaddress, hostname
                    FROM clients
                    WHERE ipaddress is not null
                    {filterclause}
                    ;'''
        getipv6 = f'''SELECT ip6address, hostname
                    FROM clients
                    WHERE ip6address is not null
                    {filterclause}
                    ;'''
        cursor.execute(getipv4)
        result4 = cursor.fetchall()
        cursor.execute(getipv6)
        result6 = cursor.fetchall()

        result_as_tuples = result4 + result6
        result = [ '\t'.join(i) for i in result_as_tuples ]

        return result

    def get_user_from_token(self, user_token: str = '') -> str:
        ''' Find a single user matching the given user_token.
            If no match, return an empty string.
        '''
        dbconn = self.__dbconnect__()
        cursor = dbconn.cursor()
        token_to_user_cmd = f'''SELECT name
                              FROM users
                              WHERE user_token = {user_token.lower()}
                              LIMIT 1
                              ;'''
        result = cursor.execute(token_to_user_cmd)
        return result
        

class ddns_update_handler(server.BaseHTTPRequestHandler):
    ''' Receive an HTTP request containing a ddns update, identifies originating IP address and ddns token.
    '''
    def authenticate(self, request):
        ''' Return True/False to this request based on authentication criteria.
        '''
        req_token = request.headers.get('Authorization')
        
        

    def do_GET(self):
        ''' GETs should use a path of /token/<token value>
            Optionally, pass another IP address with params, e.g.
            /token/<token value>?ip=<ipv4 address>&ipv6=<ipv6 address>
        '''

        # Find the token:
        url_components = urlparse(self.path)
        url_path = url_components.path
        token = url_path.rstrip('/').split('/')[-1]

        # Find the IP address:

        ### Plan A: use an IP address passed as parameter
        if '&' in url_components.query:
            url_params = url_components.query.split('&')
            kv_pairs = [ i.split('=') for i in url_params ]
            param_dict = { k:v for k,v in kv_pairs }
            if 'ip' in param_dict.keys():
                ip_address = param_dict.get('ip')
            if 'ipv6' in param_dict.keys():
                ipv6_address = param_dict.get('ipv6')

        ### Plan B: use the IP address who submitted the request
        try:
            assert ip_address
        except NameError:
            ip_address = self.client_address[0]

        success = self.ddns_update(token, ip_address)
        if success:
            httpcode=200
            # Also, update dnsmasq records
            update_dnsmasq_records()
        else:
            httpcode=400

        self.send_response(httpcode)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def ddns_update(self, token, ip_address):
        result = ddns_update(token, ip_address)
        print(f"Would be updating ddns with token='{token}' and ip_address='{ip_address}'")
        print(f"Result is '{result}'")
        return result



def run(server_class=server.HTTPServer, handler_class=ddns_update_handler):
    server_address = ('', os.environ['PORT'])
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()



if __name__ == '__main__':
    print(f"Running as uid {os.getuid()} and gid {os.getgid()}")
    listener = Listener()
    listener.listen()
    #run()


#vi:ts=4 sw=4 et ai tw=100
