'''
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Saira Hassan, @saiii_h

https://www.github.com/nccgroup/whalescan

Released under Apache license 2.0, see LICENSE for more information

'''


import os
import json
from os import stat
from time import sleep
from numpy import loadtxt
import win32security
import os
import tempfile
import codecs
import win32api
import subprocess
import csv
import sys
import pprint
import re
import docopt

def main():
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

    def checkDockerDaemonJsonFile():
        print("\n[#] Checking IP:port docker daemon is listening on...")

        #if file exists, read docker daemon config
        if os.path.isfile('C:\\ProgramData\\docker\\config\\daemon.json'):
            daemon_config_file = open('C:\\ProgramData\\docker\\config\\daemon.json')
            daemon_config = daemon_config_file.read()

            loaded_json = json.loads(daemon_config)
            for x in loaded_json:
                if (str(loaded_json[x]) == str(['tcp://0.0.0.0:2375'])):
                    print(bcolors.WARNING + "   Root access: Docker daemon can be publicly accessed, root access to host possible" + bcolors.ENDC)
        #file does not exist
        else:
            print(bcolors.WARNING + "     Daemon.json file not found" + bcolors.ENDC)

    def checkFilePermissions():
        #get list of all def files in directory
        def_files = []
        for root, dirs, files in os.walk('C:\\Windows\\System32\\containers'):
            for file in files:
                if file.endswith(".def"):
                    def_files.append(os.path.join(root, file))

        #Check the owner of each file
        for file in def_files:
            print("\n[#] Checking file ownership for " + file + "...")
            f = win32security.GetFileSecurity(file, win32security.OWNER_SECURITY_INFORMATION)
            (username, domain, sid_name_use) = win32security.LookupAccountSid(None, f.GetSecurityDescriptorOwner())
            if username != 'Administrator':
                print(bcolors.WARNING + "   File " + file + " is not owned by Administrator" + bcolors.ENDC)

            #Check who has write permissions using powershell get-acl function, then export to csv
            print("\n[#] Checking file permissions for " + file + "...")
            sleep(8)
            dir = subprocess.Popen('powershell.exe (get-acl ' + file + ').access | Select IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags,access | Sort-Object IdentityReference |  Export-Csv ' + file + '.csv -NoTypeInformation')
            f = open(file + ".csv", "r")

            #Permissions that users other than admin should not have
            disallowed_permissions = ['FullControl','Modify','Write','WriteAttributes','WriteData','WriteExtendedAttributes']

            #Check whether any non-admin users have any permissions they shouldn't have
            dangerous_permissions = 0
            with open(file + ".csv", mode='r') as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    if "Administrator" or "NT AUTHORITY\SYSTEM" not in row["IdentityReference"]:
                        if row["FileSystemRights"] in disallowed_permissions:
                            print(bcolors.WARNING + row["IdentityReference"] + " has " + row["FileSystemRights"] + " rights on " + file + bcolors.ENDC)
                            dangerous_permissions = 1

                #if there are any users with dangerous permissions over the .def file
                if dangerous_permissions == 1:
                    print(bcolors.WARNING + "Only Administrators should be able to modify .def files! " + bcolors.ENDC)


    #Check whether Administrator owns C:\ProgramData\docker, which contains sensitive files such as certificates and keys
    def checkDockerFolderPermissions():
        print("\n[#] Checking permissions for C:\ProgramData\docker...")

        #if os.path.isfile('C:\ProgramData\docker'):
        f = win32security.GetFileSecurity("C:\ProgramData\docker", win32security.OWNER_SECURITY_INFORMATION)
        (username, domain, sid_name_use) = win32security.LookupAccountSid(None, f.GetSecurityDescriptorOwner())

        if username != 'Administrator':
            print(bcolors.WARNING + "Directory C:\\ProgramData\docker is not owned by Administrator" + bcolors.ENDC)
        #else:
            #int("C:\ProgramData\docker not found")

    def checkAddedDevices():
        print("\n[#] Checking if external devices have been added to containers...")

        #Check if a COM port has been added to containers (there are 256 ports in total)
        devices=[]
        f=open('C:\Windows\System32\containers\wsc.def', 'r')
        for line in f:
            if "COM" in line:
                start = 'path="\\'
                end = '" scope='
                s = line
                result = (s.split(start))[1].split(end)[0]
                devices.append(result)

        f.close()

        if devices != 0:
            print(bcolors.WARNING + "Containers can access the following devices: " + ', '.join(devices) + bcolors.ENDC)


    checkDockerDaemonJsonFile()
    checkFilePermissions()
    checkDockerFolderPermissions()
    checkAddedDevices()