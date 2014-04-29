#!/bin/bash

echo "*** this will whipe out all local containers and images ***"

read -p "proceed (N/y)?" asw

if [ "X$asw" = "Xy" -o "X$asw" = "XY" ] ; then
	if [ $(sudo docker.io ps -a --no-trunc -q | wc -l) -gt 0 ] ; then
		sudo docker.io rm $(sudo docker.io ps -a --no-trunc -q)
		sudo docker.io rmi $(sudo docker.io images | tail -n+2 | awk '{ print $3}')
	fi
fi
