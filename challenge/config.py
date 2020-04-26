import pymysql, os

generate = lambda x: os.urandom(x).encode('hex')

db_name = 'db_' + generate(3)
db_user = 'user_' + generate(3)

db_conf = {
	'host': '127.0.0.1',
	'user': db_user,
	'password': '',
	'port': 3306,
	'database': db_name,
	'autocommit': True,
	'charset': 'utf8mb4',
	'cursorclass': pymysql.cursors.DictCursor
}

def setup_db():
	config = {
		'host': '127.0.0.1',
		'user': 'root',
		'password': 'fuzzer1337$',
		'port': 3306,
		'autocommit': True,
		'charset': 'utf8mb4',
	}

	conn = pymysql.connect(**config)
	db = conn.cursor()

	queries = [
		'DROP DATABASE IF EXISTS `{db}`',
		'CREATE DATABASE `{db}`', 
		'CREATE TABLE `{db}`.screenshots (id INT AUTO_INCREMENT PRIMARY KEY, url TEXT NOT NULL, filename TEXT NOT NULL, integrity TEXT NOT NUll, created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL)',
		"CREATE USER '{user}'@'%'",
		"GRANT ALL PRIVILEGES ON *.* TO '{user}'@'%'",
		'FLUSH PRIVILEGES'
	]

	for query in queries:
		if 'db' in query:
			db.execute(query.format(db=db_name))
		
		elif 'user' in query:
			db.execute(query.format(user=db_user))

	db.close()
	conn.close()