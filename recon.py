import os
import sys
import json

# scp -P 9222 quanghieu@14.162.146.239:/opt/results/dpwh.gov.ph/aquatone_urls.txt /home/qhieu291 

###########################
# subdomains.txt 
# ips.txt 
# aquatone_urls.txt 
# nessus.txt
# acunetix.txt
# wappalyzer.txt
# login.txt
# register.txt
# dirsearch.txt
###########################



# Amass
class Amass:
    def __init__(self, domain):
        self.domain = domain

    def scanSubdomains(self, output):
        print(f"amass enum --passive -o /opt/results/{ self.domain }/{ output } -d { self.domain }")
        os.system(f"amass enum --passive -o /opt/results/{ self.domain }/{ output } -d { self.domain }")
        print("Scan subdomains done!")

    def scanIps(self, output):
        print(f"amass enum -ipv4 -o /opt/results/{ self.domain }/{ output } -d { self.domain }")
        os.system(f"amass enum -ipv4 -o /opt/results/{ self.domain }/{ output } -d { self.domain }")
        print("Scan ips done!")

# Dirsearch
class Dirsearch:
    def __init__(self, domain):
        self.domain = domain
    
    def searchForm(self, preffixes):
        print(f"nohup python3 dirsearch.py -l /opt/results/{ self.domain }/aquatone_urls.txt --full-url --format plain --prefixes={ preffixes } -i 200,301,302 -t 5  -o { preffixes }.txt &")
        os.system(f"nohup python3 dirsearch.py -l /opt/results/{ self.domain }/aquatone_urls.txt --full-url --format plain --prefixes={ preffixes } -i 200,301,302 -t 5  -o { preffixes }.txt &")
    
    def searchUrls(self):
        print(f"nohup python3 dirsearch.py -l /opt/results/{ self.domain }/aquatone_urls.txt --full-url --format plain -i 200,301,302 -t 5 -o dirsearch.txt &")
        os.system(f"nohup python3 dirsearch.py -l /opt/results/{ self.domain }/aquatone_urls.txt --full-url --format plain -i 200,301,302 -t 5 -o dirsearch.txt &")


# Nmap
class Nmap:
    def __init__(self, domain):
        self.domain = domain

    def scanOpenPorts(self, subdomains, outputXML):
        print(f"sudo nmap -iL /opt/results/{ self.domain }/{ subdomains } -oX { outputXML }")
        os.system(f"sudo nmap -iL /opt/results/{ self.domain }/{ subdomains } -oX { outputXML } -T2")
        print("Nmap done!")


class Wappalyzer:
    def __init__(self, domain):
        self.domain = domain

    def TechnologiesUsed(self, website, writeToFile):

        #OutputFile

        writeToFile = open("/home/qhieu291/Documents/games/python/wappalyzer.txt", "a")

        # Get json data 
        jsonResult = os.popen(f"node /home/qhieu291/Recon/wappalyzer/src/drivers/npm/cli.js { website }").read()
        result = json.loads(jsonResult)
        # Get domain
        domain = list(result["urls"].keys())[0]
        print(f"[*] { domain }")
        writeToFile.write(f"[*] { domain }\n")

        # Get technologies used in website
        technologies = result["technologies"]
        for technology in technologies:
            print(f'\t{ technology["name"] } version { technology["version"] }')
            writeToFile.write(f'\t{ technology["name"] } version { technology["version"] }\n')

    def scanTechs(self, inputFileUrls):
        fileWebsites = open(inputFileUrls, "r")

        for website in fileWebsites:
            self.TechnologiesUsed(website)
        fileWebsites.close()


# Aquatone
class Aquatone:
    def __init__(self, domain):
        self.domain = domain

    def attackSurface(self, inputXML):
        print(f"cat /opt/results/{ self.domain }/{ inputXML } | aquatone -nmap -scan-timeout 500 -screenshot-timeout 300000 -http-timeout 30000")
        os.system(f"cat /opt/results/{ self.domain }/{ inputXML } | aquatone -nmap -scan-timeout 500 -screenshot-timeout 300000 -http-timeout 30000")
        print("Scan aquatone done! You can open in file aquatone_urls.txt")

class Target:
    def __init__(self, domain):
        self.domain = domain

    def amass(self):
        return Amass(self.domain)
    
    def dirsearch(self):
        return Dirsearch(self.domain)

    def nmap(self):
        return Nmap(self.domain)

    def aquatone(self):
        return Aquatone(self.domain)
    
    def wappalyzer(self):
        return Wappalyzer(self.domain)
    

if __name__ == "__main__":
    print(f"Running { sys.argv[0] } program")
    print(f"Domain: { sys.argv[1] }")
    DOMAIN = sys.argv[1]

    target = Target(DOMAIN)

    # Create path
    newPath = f"/opt/results/{ sys.argv[1] }"
    print(f"Path created in { newPath }")
    os.makedirs(newPath, exist_ok = True, mode = 0o777)

    # Amass
    target.amass().scanSubdomains("subdomains.txt")
    target.amass().scanIps("ips.txt")

    # Nmap
    target.nmap().scanOpenPorts("subdomains.txt", "scan.xml")

    # Aquatone
    target.aquatone().attackSurface("scan.xml")

    # Dirsearch
    forms = ["login", "register"]

    for form in forms:
        target.dirsearch().searchForm(form)

    # Wappalyzer 
    target.wappalyzer().scanTechs()

