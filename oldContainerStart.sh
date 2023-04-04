#!/bin/bash
### oldContainerStart.sh ##########################################################################
#
####################################### Description ###############################################
#
# This script is used to start the container for the contiki, and connect to it.
# There is a validation step to make sure that the id provided is a valid id and that is a contiki
# container. If no argument is provided then it will start and connect to the latest created
# container.
#
#
####################################### Arguments ##################################################
#
# Optional Argument: <container id>
#
######################################  Execution ##################################################
#  ./oldContainerStart.sh <container id>
####################################################################################################

args=$1

if [[ ! -z "$args" ]]; then
   echo "provided id is: ${args}"

   # Verify that the container id exists
   checkId=$(docker container ls -a | grep $args | grep contiker | awk '{print $1}')
   if [[ -z "$checkId" ]]; then
      echo "The provided id: ${args} is not a valid contiker container id"
      exit 1
   fi
   echo "Validation: The the container with id ${args} is valid"
else
   echo "Getting the latest contiker container that was created"
   args=$(docker container ls -a | grep contiker | head -n 1  | awk '{print $1}')
   if [[ -z "$args" ]]; then
      echo "There is no valid contiki container. Please create a new one with contiker alias"
      exit
   fi
   echo "The container ID: ${args} is valid contiki container id"
fi

# Verify if the container is running

containerStatus=$(docker container ps | grep $args | awk '{print $1}')

if [[ -z "$containerStatus" ]]; then
   echo "The container ${args} is not running"
   docker container start ${args} 2>&1
   check=$?
   if [[ "$check" != "0" ]]; then
      echo "The command: docker container start ${args} finished with error"
      exit 1
   fi
   #verify that the container started"
   containerStatus=$(docker container ps | awk -v var="$args" '{if($1==var) print $1}')
   if [[ -z "$containerStatus" ]]; then
      echo "The container did not start, please proceed manually"
      exit 1
   fi
   echo "The container with id: ${args} is now running"
else
   echo "The container with id: ${args} is running"
fi

# Connecting to the container
echo "Connecting to the container with id ${args}"
docker container exec -ti ${args} /bin/bash
