import requests

# huntServer = '172.16.33.18'
huntServer = 'demo30.infocyte.com'
baseUrl = f'https://{huntServer}/api'
api = requests.Session()
api.verify = False

credential = {'username':'infocyte', 'password':'hunt'}
temptarget = "Austin Office (CA)"

# 	get login token
def gettoken():
	print(f'Requesting new Token from {huntServer} using account {credential["username"]}')
	r = api.post(f'{baseUrl}/users/login', data = credential)
	r.raise_for_status()
	api.headers.update({'authorization':r.json()["id"]})
	print (f'Recieved new Token: {r.json()["id"]}')
	return r.json()["id"]
gettoken()

def getlist(endpoint, customfilter="", include=""):
	print(f'Retrieving {endpoint} from {huntServer}')
	skip = 0
	more = True
	count = 0
	responses = []
	while more:
		count += 1
		requestfilter = f'{{"where":{{"and":[{customfilter}]}},"include":[{include}],"limit":100,"skip":{skip}}}'
		api.headers.update({"filter": requestfilter})
		r = api.get(f'{baseUrl}{endpoint}')
		r.raise_for_status()
		more = False if len(responses) % 100 != 0 else more
		if len(r.json()) < 1: more = False 
		if count == 5: more = False
		skip += len(r.json())
		responses = responses + r.json()
	print(f'Retrieved {len(responses)} records from {endpoint}')
	return responses

def gettargets():
 	return getlist("/targets")

def getqueries(targetlist):
 	return getlist(f"/queries",f'{{"targetList":"{targetlist}"}}','"credential","sshCredential"')

print(getqueries(temptarget))

def getscans(targetList):
	requestfilter = f'{{"targetList":"{targetList}"}}'
	return getlist("/IntegrationScans", requestfilter)

def getlastscan(targetlist=""):
	print(f'Retrieving last scan from {huntServer}')
	targetfilter = ""
	if targetlist != "": targetfilter = f'"where":{{"and":[{{"targetList": "{targetlist}"}}]}},'
	requestfilter = f'{{{targetfilter}"limit":1,"order": ["scanCompletedOn desc"]}}'
	print(requestfilter)
	api.headers.update({"filter": requestfilter})
	r = api.get(f'{baseUrl}/IntegrationScans/')
	r.raise_for_status()
	print(f'Retrieved latest scan record')
	return r.json()[0]

def getscanresults(scanid):
	results = {}
	endpoints = [
		"Autostarts",
		"Connections",
		"Drivers",
		"Hosts",
		"MemScans",
		"Modules",
		"Processes"
	]
	for endpoint in endpoints:
		objectresults = getlist(f'/Integration{endpoint}', f'{{"scanId":"{scanid}"}}')
		results.update({endpoint: objectresults})

	return results

bigscanid = "ba2ae5cc-850c-4d52-a387-5737b1f18c21"

def getfilereports(scanid):
	filereports = getlist(f'/ScanReportFiles', f'{{"scanId":"{scanid}"}}')

	for file in filereports:
		# print(file)
		filerep = getlist(f'/FileReps', f'{{"sha1":"{file["sha1"]}"}}')[0]
		# todo signature = getlist(f'/Signatures', f'{{"sha1":"{file["sha1"]}"}}')
		file.update(filerep)
		print(file)	
	return filereports

def getactivetasks():
	activetasks = getlist('/usertasks/active')
	return activetasks

def getusertasks():
	usertasks = getlist('/usertasks')
	return usertasks

def getjobs():
	jobs = getlist('/jobs')
	return jobs

def getactivejobs():
	activejobfilter = f'{{"status":"Scanning"}}'
	activejobs = getlist('/jobs', activejobfilter)
	return activejobs

def getcredentials():
	credentials = getlist('/credentials');
	return credentials

# def getqueries():
# 	queries = getlist('/queries', "")

#done 	get scan metadata
#done	get ic scans
#done	Get Full FileReports on all Suspicious and Malicious objects by scanId
#done 	Get target groups
#done 	Get objects by scanId
#done 	get tasks
#done	get active tasks
#done	get all tasks
#done 	get last scan id
#done 	get jobs
#done 		get active jobs
#done 		get core jobs
# 	get credentials
# 	get queries
# 	create target list
# 	create credential
# 	create query
# 	create enumeration for target list
# 	create scan for target list
# 	remove addresses from target list 
# invoke hunt workflow
	# Create new login Token and add it to Script variable
	# Get Target Lists.  If our specified list isn't there, create it.
	# If we don't clear the target list, we would enumerate and scan all the other addresses already in there again
	# Create new Query for target
	# Initiate Enumeration
	# Track Status of Enumeration
	# Initiate Scan
	# Track Status of Scan