#!/bin/sh
chown mysql.mysql /var/run/mysqld/
mysql_install_db
/usr/bin/mysqld_safe &
sleep 5
echo "GRANT ALL ON *.* TO admin@'%' IDENTIFIED BY '1234' WITH GRANT OPTION; FLUSH PRIVILEGES" | mysql
