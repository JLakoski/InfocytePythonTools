import requests

# huntServer = '172.16.33.18'
huntServer = 'demo30.infocyte.com'
baseUrl = f'https://{huntServer}/api'
class Session:
	username: 'infocyte'
	password: 'hunt'

api = requests.Session()
api.verify = False


# class Credential():
# 	username = 'infocyte'
# 	password = 'hunt'

# credential = Credential()


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

# functions in powershell script.txt

# filter is formatted:  "where":{"scanId":"'+$scanId+'"}


def getlist(endpoint, requestfilter=""):
	print(f'Retrieving {endpoint} from {huntServer}')
	skip = 0
	responses = []
	while  len(responses) % 1000 == 0:
		api.headers.update({requestfilter "limit":"1000","skip":str(skip)})
		r = api.get(f'{baseUrl}/{endpoint}')
		r.raise_for_status()
		print(len(r.json()))
		skip += len(r.json())
		responses += r.json()
	return responses

print (getlist("integrationscans"))


# 	get scan metadata
# 	get ic scans
# 	Get Full FileReports on all Suspicious and Malicious objects by scanId
# 	Get target groups
# 	Get objects by scanId
# 		get ic processes
# 		get ic modules
# 		get ic drivers
# 		get ic autostarts
# 		get ic memscans
# 		get ic connections
# 		get ic accounts
# 		get ic hosts
# 		get ic addreses
# 	get tasks
# 		get active tasks
# 		get all tasks
# 	get last scan id
# 	get jobs
# 		get active jobs
# 		get core jobs
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