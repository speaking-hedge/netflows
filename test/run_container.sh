#!/bin/bash

echo
echo "ports exported locally:"
echo "ssh   - 22   root/1234"
echo "http  - 80"
echo "mysql - 3306 admin/1234"
echo 

sudo docker.io run -t -i -p 22:22 -p 80:80 -p 3306:3306 -v $(pwd)/mapped_folders/www:/var/www:rw -v $(pwd)/mapped_folders/mysql/var/lib/mysql:/var/lib/mysql:rw -v $(pwd)/mapped_folders/mysql/etc-mysql:/etc/mysql:rw ring_apache_php5_mysql 

