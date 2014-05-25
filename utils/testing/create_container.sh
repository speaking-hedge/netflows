#!/bin/bash
echo "may need root to run docker..."
sudo true

# create mapped folders/files 
# mysql
mkdir -p mapped_folders/mysql/var/lib/mysql
mkdir -p mapped_folders/mysql/etc-mysql/conf.d
mkdir -p mapped_folders/install_scripts/
cp config/my.cnf mapped_folders/mysql/etc-mysql/
cp config/mysql-setup.sh mapped_folders/install_scripts/
chmod a+x mapped_folders/install_scripts/mysql-setup.sh
# apache
mkdir -p mapped_folders/www/html
echo "<html>it works</html>" > mapped_folders/www/html/index.html

#sudo docker.io rmi ring_apache_php5_mysql
sudo docker.io build -t ring_apache_php5_mysql - < config/apache_php5_mysql.docker

# setup env - mysql
sudo docker.io run -v $(pwd)/mapped_folders/mysql/var/lib/mysql:/var/lib/mysql:rw -v $(pwd)/mapped_folders/install_scripts/:/tmp/install/ --entrypoint="/tmp/install/mysql-setup.sh" ring_apache_php5_mysql 
