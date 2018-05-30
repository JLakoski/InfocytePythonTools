import requests
import time
import datetime
import json

# huntServer = '172.16.33.18'
huntServer = 'localhost'
baseUrl = f'https://{huntServer}/api'
api = requests.Session()
api.verify = False

targetname = 'localhost'
credential = {'username':'infocyte', 'password':'hunt'}


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

def gettargetbyname(name):
	requestfilter = f'{{"name":"{name}"}}'
	target = getlist('/targets', requestfilter)
	if len(target) >=1:
		return target[0]
	else:
		return 0

def createtarget(name):
	body = {"name":name}
	r = api.post(f'{baseUrl}/targets', data = body)
	r.raise_for_status()
	return r.json()

def getqueries(targetid):
 	return getlist(f"/targets/{targetid}/queries", "",'"credential","sshCredential"')

def createquery(query, name, targetlistid, credentialid, sshcredentialid=""):
	body = {
		"name": name,
		"value":query,
		"targetId":targetlistid,
		"credentialId":credentialid
		# "sshCredentialId":sshcredentialid
	}
	r = api.post(f'{baseUrl}/queries', data = body)
	r.raise_for_status()
	return r.json()


# query = createquery('localhost', 'integration-default: 2018-05-29 18:19:36', 'aaa73f25-d87b-499f-b370-389dbc4812ec', 'c5065ad9-06da-440c-829e-4dcb7e81c9dc')
# print(query)

def removequery(queryid):
	r = api.delete(f'{baseUrl}/queries/{queryid}')
	return r.json()

def getscans(targetid):
	requestfilter = f'{{"targetid":"{targetid}"}}'
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

def getfilereports(scanid):
	filereports = getlist(f'/ScanReportFiles', f'{{"scanId":"{scanid}"}}')
	for file in filereports:
		filerep = getlist(f'/FileReps', f'{{"sha1":"{file["sha1"]}"}}')[0]
		# todo signature = getlist(f'/Signatures', f'{{"sha1":"{file["sha1"]}"}}')
		file.update(filerep)
	return filereports

def getactiveusertasks():
	activetasks = getlist('/userTasks/active')
	return activetasks

def getusertasks():
	usertasks = getlist('/userTasks')
	return usertasks

def getusertask(usertaskid):
	r = api.get(f'{baseUrl}/userTasks/{usertaskid}')
	return r.json()

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

def getcredentialsbyname(name):
	credentials = getcredentials()
	for credential in credentials:
		if credential['name'] == name:
			return credential
	raise ValueError('Credential not found')

def createcredential(name, username, password):
	body = {'name': name, 'username': username, 'password': password}
	r = api.post(f'{baseUrl}/credentials', data = body)
	r.raise_for_status()
	return r.json()

def createenumeration(targetid, queryid):
	body = {"queries":[queryid, queryid]}
	r = api.post(f'{baseUrl}/targets/{targetid}/enumerate', data = body)
	r.raise_for_status()
	return r.json()

def enumerate(targetid, queryid):
	enumeration = createenumeration(targetid, queryid)
	status = "Active"
	print("Enumerating...", end='')
	while status == "Active":
		task = getusertask(enumeration['userTaskId'])
		status = task['status']
		time.sleep(3)
		print('.', end='')

	if status == "Completed":
		print("Enumeration successful")
		return {'status':'Completed', 'targetid': targetid, 'queryid': queryid}
	else:
		raise ValueError("enumeration failed")

def createscan(targetid, queryid):
	body = {'queries': [queryid, queryid]}
	r = api.post(f'{baseUrl}/targets/{targetid}/scan', data = body)
	r.raise_for_status()
	return r.json()

def scan(targetid, queryid):
	scan = createscan(targetid, queryid)
	status = "Active"
	task = ""
	print("Scanning...", end='')
	while status == "Active":
		task = getusertask(scan['userTaskId'])
		status = task['status']
		time.sleep(3)
		print('.', end='')

	if status == "Completed":
		print("Scan successful")
		return {'status':'Completed', 'targetid': targetid, 'queryid': queryid}
	else:
		raise ValueError("Scan failed")

def createhunt(query, credentialname, targetname='integration-default'):
	# gettoken()
	# Create new login Token and add it to Script variable
	target = gettargetbyname(targetname)
	
	if target == 0:
		targetid = createtarget(targetname)['id']
	else: 
		targetid = target['id']
	
	credential = getcredentialsbyname(credentialname)
	print(credential)
	credentialid = credential['id']

	queryname = f'{targetname}: {str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}'

	query = createquery(query, queryname, targetid, credentialid)
	queryid = query['id']

	print(f'Hunting {query["value"]} in {target["name"]} with {credentialname}')

	enumeration = enumerate(targetid, queryid)
	scantask = scan(targetid, queryid)

	removequery(queryid)

	print(f'Successfully scanned {query} with {credentialname} as part of the {targetname} target list.')
	return f'Successfully scanned {query} with {credentialname} as part of the {targetname} target list.'

huntrun = createhunt('localhost', '.\\INFOCYTE', 'localhost')
print(huntrun)













# targetid = gettargets()[0]["id"]
# scanid = createscan(targetid, queryid)
# # enumerationid = createenumeration(targetid, queryid)
# print(scanid)

# task = getusertask(enumerationid)
# task = getusertask('b3a62d3a-e6ab-4b2e-9d2c-f1de295f4441')
# print(task)



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
#done 	get credentials
#done 	get queries
#done 	create target list
#		create credential
# 	create query
#done 	create enumeration for target list
#	track enumeration
#done 	create scan for target list
#done	track scan
#done 	remove addresses from target list/deletequery
# invoke hunt workflow


#todo: add support for linux/sshcredential