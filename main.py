'''
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Saira Hassan, @saiii_h

https://www.github.com/nccgroup/whalescan

Released under Apache license 2.0, see LICENSE for more information

'''


import re
import sys

from time import sleep

import docker
import container_checks
import config_file_checks
import docker_version_checks
import image_checks
import subprocess
import cve_check

client = docker.from_env()
APIClient = docker.APIClient(base_url='')
images = client.images.list()

#Running checks for containers
count = 0
for container in client.containers.list():
     count+=1
     containerID = container.id[:12]
     print("\n################## Running checks for container " + containerID + " (" + str(count) + "/" + str(len(client.containers.list())) + ") ##################")
     container_checks.main(container)


count = 0
for image in images:
     sleep(2)
     imagestr = str(image)
     imagestr = re.findall(r"'(.*?)'", imagestr, re.DOTALL)
     count += 1
     print("\n################## Running checks for image " + str(imagestr[0]) + " (" + str(count) + "/" + str(len(images)) + ") ##################")
     image_checks.main(image)
     print("\n################## Checking image " + str(imagestr[0]) + " (" + str(count) + "/" + str(len(images)) + ")" + " for vulnerabilities ##################")
     cve_check.main(image)

#Checking docker version and updates
print("\n################## Checking docker version ################## ")
docker_version_checks.main()



#Checking configuration files for vulnerabilities
print("\n################## Checking config files ################## ")
config_file_checks.main()


