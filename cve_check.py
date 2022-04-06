'''
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Saira Hassan, @saiii_h

https://www.github.com/nccgroup/whalescan

Released under Apache license 2.0, see LICENSE for more information

'''


from time import sleep

import requests
import sys
from bs4 import BeautifulSoup
from docker import APIClient
import re
from prettytable import PrettyTable
import ares
from ares import CVESearch
import pprint
import tabulate
import docker
import json
from tabulate import tabulate

pp = pprint.PrettyPrinter(indent=4)

def main(image):
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
    pp = pprint.PrettyPrinter(indent=4)
    images = client.images.list()

    # get list of images
    cli = docker.APIClient(base_url='')
    client = docker.from_env()

    def dotnetCVEs(version):

        # Parse CVEs from advisory page
        url = 'https://github.com/dotnet/announcements/issues?q=is%3Aopen+is%3Aissue+label%3A%22.NET+' + version[0:3] + '%22+label%3ASecurity'
        #url = 'https://github.com/dotnet/announcements/issues?q=is%3Aopen+is%3Aissue+label%3A%22.NET+5.0%22+label%3ASecurity'
        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')

        main_content = soup.find('div', attrs={'class': 'Box mt-3 Box--responsive hx_Box--firstRowRounded0'})
        content = str(main_content.find('div', attrs={'aria-label': 'Issues'}))

        name_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{5}')
        #initialise dict of CVE ID and relevant information
        CVEs = dict(dict.fromkeys(name_pattern.findall(content)))
        t = ""
        if CVEs != None:
            
            print("\n[#] Fetching data...")
            print(bcolors.FAIL + "Found following CVEs for .NET version " + version + " (NOTE: If your version is up-to-date, it most likely won't affect you)" +bcolors.ENDC)
            #get more detail for the CVEs and save it to a dict [CVE: {cve info}]
            for c in CVEs:
                
                #query nvd advisory for information relating to CVE IS
                url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + c
                response = requests.get(url)
                json_data = json.loads(response.text)

                #parse severity, score and summary, save to dict
                try:
                    severity = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                except:
                    severity = 'Unknown'

                try:
                    riskScore = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                except:
                    riskScore = 'Unknown'

                try:
                    summary = json_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
                except:
                    summary = 'Unknown'

                CVEs[c] = [severity, riskScore, summary]

                #initialise table of CVEs
                t = PrettyTable(['CVE ID', 'Severity', 'Summary'])
                t._max_width = {"Summary": 60}

            # create a row in the table for each CVE
            for c in CVEs:
                severity = str(CVEs[c][0]) + ' (' + str(CVEs[c][1]) + ")"
                summary = str(CVEs[c][2])
                t.add_row([c, severity, summary])

            print(t)
            sleep(2)

    def checkifEOL(versionUsed):

        # check if it is end of life
        LatestVersions = []
        url = 'https://github.com/dotnet/core/blob/main/releases.md'
        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')

        main_content = soup.findAll('table')[0]
        tbody = main_content.findAll('tbody')

        #get array of EOL versions
        for tr in tbody:
            tr = tr.findAll("tr")
            # print(tr)
            for each_tr in tr:
                versionString = each_tr.findAll("td")[3].text
                #print(versionString)
                #version = versionString[0:6]
                LatestVersions.append(versionString)
        #print(LatestVersions)
        #print warning if current version is EOL
        if versionUsed not in LatestVersions:
            # Note: LatestVersions[2] index is hardcoded, so need to fix that in the future
            print(bcolors.FAIL + "\n⛔ Using out-dated .NET version! Using: " + versionUsed + " while latest is: " + LatestVersions[2] + bcolors.ENDC)
        else:
            print("\n👍 Using up-to-date .NET version: " + versionUsed)

    if(cli.inspect_image(image.id)['Config']['Env'] != None):
        if ('DOTNET_RUNNING_IN_CONTAINER=true' in cli.inspect_image(image.id)['Config']['Env']):

            # Check if it is DOTNET_SDK
            if re.search('DOTNET_SDK_VERSION', str(cli.inspect_image(image.id)['Config']['Env'])):
                # get .net sdk version
                print('\n[#] Dotnet running, checking version...')
                r = re.compile(".*DOTNET_SDK_VERSION.*")
                sdk_version = str(list(filter(r.match, cli.inspect_image(image.id)['Config']['Env'])))
                start = "DOTNET_SDK_VERSION="
                end = "'"
                s = sdk_version
                sdk_version = (s.split(start))[1].split(end)[0][0:3]
                checkifEOL(sdk_version)
                dotnetCVEs(sdk_version)

            # Check if it is DOTNET
            if re.search('DOTNET_VERSION', str(cli.inspect_image(image.id)['Config']['Env'])):
                # get .net version being used
                print('\n[#] Dotnet running, checking version...')
                r = re.compile(".*DOTNET_VERSION.*")
                version = str(list(filter(r.match, cli.inspect_image(image.id)['Config']['Env'])))
                start = "DOTNET_VERSION="
                end = "'"
                s = version
                #Parsing to 5.0 (instead of full version 5.0.15) here, so I can search for the github issues
                versionTrim = (s.split(start))[1].split(end)[0][0:3]
                #Parsing to 5.0.15 (instead of ['DOTNET_VERSION=5.0.15'])
                versionParse = s[s.index("=")+1:s.index("]")-1]

                checkifEOL(versionParse)
                
                dotnetCVEs(versionTrim)


