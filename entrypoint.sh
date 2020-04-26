#!/bin/bash

# Initiate Database
service mysql start

# Wait for mysql to start
while ! mysqladmin ping -h'localhost' --silent; do echo "not up" && sleep .2; done

# Insert data, password protect root user
mysql -u root -e "SET GLOBAL sql_mode = 'NO_ENGINE_SUBSTITUTION'; SET SESSION sql_mode = 'NO_ENGINE_SUBSTITUTION'; GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY 'fuzzer1337$' WITH GRANT OPTION; FLUSH PRIVILEGES;"