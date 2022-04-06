'''
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Saira Hassan, @saiii_h

https://www.github.com/nccgroup/whalescan

Released under Apache license 2.0, see LICENSE for more information

'''


from asyncio.windows_events import NULL
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

#Use Docker engine (tcp://, namedpipe:// or Default)
client = docker.from_env()
APIClient = docker.APIClient(base_url='')
#Check all images
images = client.images.list()
#Use this to only check the newest image
lastImage = [images[0]]

#Check for CLI arguments
if len(sys.argv) > 1:
     result = sys.argv[1]
else:
     result = False

if result == False:
     print("USAGE: ./main.py [COMMAND]")
     print("\nChoose one:")
     print("- cicd (limit scan to image CVE scan)")
     print("- full (To scan images, containers plus config settings)")
     sys.exit()
#If CLI arument is 'cicd' only run CVE check
elif result == "cicd":
     count = 0
     for image in lastImage:
          sleep(2)
          #Add count if going over list
          count=+1 
          print("\n################## Running checks for image " + image.id + ") ##################")
          image_checks.main(image)
          print("\n################## Checking image for vulnerabilities ##################")
          cve_check.main(image)

     print("\n [#] Next step in the pipeline is Linting Dockerfile and scanning NuGet packages.\n")
#If CLI argument is 'full' perform container,image,docker & config checks
elif result == "full":
     #Running checks for containers
     count = 0
     for container in client.containers.list():
          count+=1
          containerID = container.id[:12]
          containerName = container.name
          print("\n################## Running checks for container: " + containerName + " (" + containerID + ") (" + str(count) + "/" + str(len(client.containers.list())) + ") ##################")
          container_checks.main(container)


     count = 0
     for image in lastImage:
          sleep(2)
          #Add count if going over list, not needed if only checking last image
          count+=1
          print("\n################## Running checks for image " + image.id + ") ##################")
          image_checks.main(image)
          print("\n################## Checking image for vulnerabilities ##################")
          cve_check.main(image)

     #Checking docker version and updates
     print("\n################## Checking docker version ################## ")
     docker_version_checks.main()



     #Checking configuration files for vulnerabilities
     print("\n################## Checking config files ################## ")
     config_file_checks.main()
else:
     print("USAGE: ./main.py [COMMAND]")
     print("\nChoose one:")
     print("- cicd (limit scan to image CVE scan)")
     print("- full (To scan images, containers plus config settings)")
     sys.exit()

