#!/bin/bash

echo "*** this will stop and whipe out all local containers and images ***"

read -p "proceed (N/y)?" asw

sudo docker.io stop $(sudo docker.io ps -a -q --no-trunc)

if [ "X$asw" = "Xy" -o "X$asw" = "XY" ] ; then
	if [ $(sudo docker.io ps -a -q | wc -l) -gt 0 ] ; then
		sudo docker.io rm $(sudo docker.io ps -a --no-trunc -q)
		sudo docker.io rmi $(sudo docker.io images -a --no-trunc -q)
	fi
fi
