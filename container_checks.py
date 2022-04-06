'''
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Saira Hassan, @saiii_h

https://www.github.com/nccgroup/whalescan

Released under Apache license 2.0, see LICENSE for more information

'''


import json
import re
import urllib
from urllib.request import urlopen
from flask import current_app
import nltk
import requests
from bs4 import BeautifulSoup

import cve_check
import command
import os
import docker
import pprint
import sys
import subprocess
from docker import APIClient

pp = pprint.PrettyPrinter(indent=4)

def main(container):
    class bcolors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        CGREENBG = '\33[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')
    cli = docker.APIClient(base_url='')

    # Check whether container can acquire new privileges
    def checkNewPrivileges(container):
        print("\n[#] Checking if container can gain new privileges...")

        #mapping docker inspect command output
        host_config = APIClient.inspect_container(container.id)['HostConfig']
        config = APIClient.inspect_container(container.id)['Config']
        
        #Check current running user
        #Using /C to auto terminate the session
        cmdOut = str(container.exec_run("cmd.exe /C echo %username%"))
        #Parse to username
        currentUser = cmdOut[cmdOut.index('\'')+1:cmdOut.index('\\')]

        if "Admin" in currentUser:
            print(bcolors.WARNING + "\n⛔ You're running with elevated privileges! Only run as " + currentUser + " if it's really necessary!" + bcolors.ENDC)
        #Check if ran with --privileged
        if host_config.get("Privileged") == True:
            print(bcolors.WARNING + "\n⛔ Are you sure you want to run your container in PRIVILEGED mode? Try to avoid this as much as possible..." + bcolors.ENDC)
        else:
            print("\n👍 Container is not running in privileged mode (--privileged)")

    #check whether docker services are mapped to any sensitive ports
    def checkDockerPortMappings(container):
        cli = docker.APIClient(base_url='')
        port_mappings = cli.port(container.id, 5000)
        if port_mappings != None:
            for p in port_mappings:
                if((p['HostIp'] == '0.0.0.0') & ([p['HostPort'] == '2375'])):
                    print(bcolors.WARNING + "\n⛔ Docker daemon is listening on " + p['HostPort'] + bcolors.ENDC)
        else:
            print("\n👍 Good news, the docker deamon is not pubicly accessable")

    #check logical drives storing containers
    def checkContainerStorage(container):
        print("\n[#] Checking container storage... ")
        host_config = APIClient.inspect_container(container.id)['Config']

        container_info = client.info()
        logical_drive = host_config.get('WorkingDir')[0:3]
        if(logical_drive == "C:\\"):
            print(bcolors.WARNING + "\n⛔ Potential DoS: An attacker could fill up the C:\ drive, causing containers and the host itself to become unresponsive")
            print("Consider using another drive in your Dockerfile (ex. VOLUME [\"D:\"])" + bcolors.ENDC)

    def checkIsolation(container):
        host_config = APIClient.inspect_container(container.id)['HostConfig']

        output = host_config.get("Isolation")

        if output != 'hyperv':
            print(bcolors.WARNING + "\n⛔ Container " + container.id + ' is not running in isolation (Hyper-V)' + bcolors.ENDC)
        else:
            print("\n👍 Container is running in Isolation using Hyper-V")
    def checkPendingUpdates(container):
        print("\n[#] Checking if there are any pending updates... ")

        pending_updates = []

        hostVersionCmd = 'ver'
        foo = subprocess.getoutput(hostVersionCmd)

        #Format output to compareable int, example:  [Version 10.0.17763.1817] Becomes 100177631817
        hostVersion = foo[foo.index('[')+1:foo.index(']')]
        hostVersionInt = int(foo[foo.index('[')+9:foo.index(']')].replace(".", ""))

        #This is the WRONG way to execute a command in container, but it still gives the version (cmd.exe), so keeping it
        copy = 'docker exec ' + container.id + ' cmd.exe ver | findstr "Version"'
        
        out = subprocess.getoutput(copy)
        #Example output:  100177631817
        containerVersion = out[out.index('[')+1:out.index(']')]
        containerVersionInt = int(out[out.index('[')+9:out.index(']')].replace(".", ""))

        if(hostVersionInt != containerVersionInt):
            print(bcolors.WARNING + "\n⛔ The container is running another Windows version (" + containerVersion + ") than the host (" + hostVersion + ") might consider updating?" + bcolors.ENDC)

        

    checkNewPrivileges(container)
    checkContainerStorage(container)
    checkDockerPortMappings(container)
    checkIsolation(container)
    checkPendingUpdates(container)
