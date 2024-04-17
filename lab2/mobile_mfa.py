#!/usr/bin/python3

# ECE568: Lab 2, Part 2
# Biometric Mobile MFA

# Copyright 2021, 2022 by Courtney Gibson (gibson@ecf.utoronto.ca)
# (Why is there a copyright notice there? Because people keep posting my
# code to github... please don't. Thank you!)

import sys
import time
import json
import requests
import qrcode_terminal

exec(compile(source=open('../setup/server_config.py').read(),
	filename='server_config.py', mode='exec'))


class BioConnect:

	bcaccesskey		= ''
	bcentitykey		= ''
	bctoken			= ''
	userId			= ''
	authenticatorId		= ''
	stepupId		= ''

	# ===== login: Authenticates and obtains access credentials

	def login(self):

		global	hostname
		global	username
		global	password

		url = 'https://%s/v2/console/login' % hostname

		headers = {
			'Content-Type':		'application/json',
			'accept':		'application/json'
		}

		data = {
			'username':		username,
			'password':		password
		}

		# Send our POST request to the server
		result = requests.post(url, data=json.dumps(data), headers=headers)

		if result == False:
			# Error: we did not receive an HTTP/200
			print(headers)
			print(result.content)
			sys.exit("Error: unable to authenticate")

		try:
			# Parse the JSON reply
			reply = json.loads(result.content.decode('utf-8'))

			# Extract the authentication tokens
			self.bcaccesskey = reply.get("bcaccesskey","")
			self.bcentitykey = reply.get("bcentitykey","")
			self.bctoken = reply.get("bctoken","")

		except ValueError:
			self.bctoken = ""


	# ===== createUser: Creates a new Multi-Factor Authenticator user

	def createUser(self,
		externalId="%f" % time.time(),
		firstName = 'UofT',
		lastName = 'Student',
		shortName = 'UofTstudent',
		email = 'lab2@ece568.ca',
		phoneNumber = '4165555555',
		mailingAddress = 'NA',
		title = 'NA'):

		global	hostname

		url = 'https://%s/v2/users/create' % hostname

		headers = {
			'Content-Type':		'application/json',
			'accept':		'application/json',
			'bcaccesskey':		self.bcaccesskey,
			'bcentitykey':		self.bcentitykey,
			'bctoken':		self.bctoken
		}

		data = {
			'external_id':		externalId,
			'first_name':		firstName,
			'last_name':		lastName,
			'short_name':		shortName,
			'email':		email,
			'phoneNumber':		phoneNumber,
			'mailingAddress':	mailingAddress,
			'title':		title
		}

		# Send our POST request to the server
		result = requests.post(url, data=json.dumps(data), headers=headers)

		if result == False:
			# Error: we did not receive an HTTP/200
			print(headers)
			print(json.dumps(data))
			print(result.content)
			sys.exit("Error: unable to create user")

		try:
			# Parse the JSON reply
			reply = json.loads(result.content.decode('utf-8'))

			# Extract the userId
			self.userId = reply.get("uuid","")

		except ValueError:
			self.userId = ""


	# ===== createAuthenticator: Creates a new mobile phone for the user

	def createAuthenticator(self,
		name = 'mobile',
		description = 'Mobile',
		authenticatorType = 'mobile'):

		global	hostname

		url = 'https://%s/v2/users/%s/authenticators/create' % \
			( hostname, self.userId )

		headers = {
			'Content-Type':		'application/json',
			'accept':		'application/json',
			'bcaccesskey':		self.bcaccesskey,
			'bcentitykey':		self.bcentitykey,
			'bctoken':		self.bctoken
		}

		data = {
			'name':			name,
			'description':		description,
			'authenticator_type':	authenticatorType
		}

		# Send our POST request to the server
		result = requests.post(url, data=json.dumps(data), headers=headers)

		if result == False:
			# Error: we did not receive an HTTP/200
			print(headers)
			print(json.dumps(data))
			print(result.content)
			sys.exit("Error: unable to create authenticator")

		try:
			# Parse the JSON reply
			reply = json.loads(result.content.decode('utf-8'))

			# Extract the authenticatorId
			self.authenticatorId = reply.get("uuid","")

		except ValueError:
			self.authenticatorId = ""


	# ===== getAuthenticatorQRcode: Get and display the app QR code

	def getQRcode(self):

		global	hostname

		url = 'https://%s/v2/users/%s' \
			'/authenticators/%s/activation_string/v2.txt' % \
			( hostname, self.userId, self.authenticatorId )

		headers = {
			'Content-Type':		'application/json',
			'accept':		'application/json',
			'bcaccesskey':		self.bcaccesskey,
			'bcentitykey':		self.bcentitykey,
			'bctoken':		self.bctoken
		}

		# Send our GET request to the server
		result = requests.get(url, headers=headers)

		if result == False:
			# Error: we did not receive an HTTP/200
			print(headers)
			print(result.content)
			sys.exit("Error: unable to get QR code")

		try:
			# Parse the JSON reply
			reply = json.loads(result.content.decode('utf-8'))

		except ValueError:
			print(headers)
			print(result.content)
			sys.exit("Error: unexpected reply for QR code")
	
		# Extract the activation URL for this mobile phone
		activationString = reply.get("activation_string","")

		# Display the QR code on the terminal
		qrcode_terminal.draw(activationString)
		print("%s\n" % activationString)


	# ===== getAuthenticatorStatus: Mobile phone registration status

	def getAuthenticatorStatus(self):

		# >>> Add code here to call
		#    .../v2/users/<userId>/authenicators/<authenticatorId>
		# and process the response

		""" ECE568 BEGIN """
		url = 'https://%s/v2/users/' % hostname + self.userId + '/authenticators/' + self.authenticatorId
		
		headers = {
			'Content-Type':		'application/json',
			'accept':		'application/json',
			'bcaccesskey':		self.bcaccesskey,
			'bcentitykey':		self.bcentitykey,
			'bctoken':		self.bctoken
		}

		result = requests.get(url, headers=headers)

		if result == False:
			print(headers)
			print(result.content)
			sys.exit("Error: unable to get authenticator status")

		try:
			reply = json.loads(result.content.decode('utf-8'))

			status = reply.get("status", "")
			biometric_l = [
       			reply.get("face_status", ""),
          		reply.get("voice_status", ""),
            	reply.get("fingerprint_status", ""),
            	reply.get("eye_status", ""),
			]

			if status == "active" and any([x == "enrolled" for x in biometric_l]):
				return('active')

		except ValueError:
			sys.exit("Error: unexpected reply for `getAuthenticatorStatus`")

		""" ECE568 END """

		return('')


	# ===== sendStepup: Pushes an authentication request to the mobile app

	def sendStepup(self,
		transactionId = '%d' % int(time.time()),
		message='Login request'):

		# >>> Add code here to call
		#     .../v2/user_verifications
		# to push an authentication request to the mobile device

		# Send our POST request to the server
		""" ECE568 BEGIN """
		url = 'https://%s/v2/user_verifications/' % hostname

		headers = {
			'Content-Type':		'application/json',
			'accept':		'application/json',
			'bcaccesskey':		self.bcaccesskey,
			'bcentitykey':		self.bcentitykey,
			'bctoken':		self.bctoken
		}

		data = {
			'user_uuid': self.userId,
			'transaction_id': transactionId,
			'message': message
		}

		result = requests.post(url, data=json.dumps(data), headers=headers)

		if result == False:
			print(headers)
			print(result.content)
			sys.exit("Error: unable to set up authentication request")

		try:
			reply = json.loads(result.content.decode('utf-8'))
			self.stepupId = reply.get("user_verification", "").get("uuid")

		except ValueError:
			self.stepupId = ""
		""" ECE568 END """

		pass

	# ===== getStepupStatus: Fetches the status of the user auth request

	def getStepupStatus(self):

		# >>> Add code here to call
		#     .../v2/user_verifications/<verificationId>
		# to poll for the current status of the verification

		""" ECE568 BEGIN """
		url = 'https://%s/v2/user_verifications/' % hostname + self.stepupId
		
		headers = {
			'Content-Type':		'application/json',
			'accept':		'application/json',
			'bcaccesskey':		self.bcaccesskey,
			'bcentitykey':		self.bcentitykey,
			'bctoken':		self.bctoken
		}

		result = requests.get(url, headers=headers)

		if result == False:
			print(headers)
			print(result.content)
			sys.exit("Error: unable to verify set up status")

		try:
			reply = json.loads(result.content.decode('utf-8'))
			status = reply.get("user_verification","").get("status")
			return(status)

		except ValueError:
			sys.exit("Error: unexpected reply for `getStepupStatus`")
		""" ECE568 END """

		return('declined')


	# ===== deleteUser: Deletes the user and mobile phone entries

	def deleteUser(self):

		# Deletes the user and authenticator records, for privacy

		global	hostname

		url = 'https://%s/v2/users/%s/delete' % (hostname, self.userId)

		headers = {
			'Content-Type':		'application/json',
			'accept':		'application/json',
			'bcaccesskey':		self.bcaccesskey,
			'bcentitykey':		self.bcentitykey,
			'bctoken':		self.bctoken
		}

		# Send our POST request to the server
		result = requests.post(url, headers=headers)

		if result == False:
			# Error: we did not receive an HTTP/200
			print(result.content)
			sys.exit("Error: unable to delete user %s" % self.userId)

		self.userId = ''


	# ===== logout: Invalidates the access token, for security

	def logout(self):

		global	hostname

		url = 'https://%s/v2/console/logout' % hostname

		headers = {
			'accept':		'application/json',
			'bcaccesskey':		self.bcaccesskey,
			'bcentitlykey':		self.bcentitykey,
			'bctoken':		self.bctoken
		}

		# Send our POST request to the server
		requests.post(url, headers=headers)
		self.bctoken = ''


	# ===== Destructor: Attempts to perform cleanup before exiting

	def __del__(self):

		if self.userId != '':
			self.deleteUser()

		if self.bctoken != '':
			self.logout()


# ===== Execution starts here...

session = BioConnect()

# Log into the cloud service and provision the mobile device

session.login()
session.createUser()
session.createAuthenticator()
session.getQRcode()

# Loop for up to two minutes, waiting for the user to provision the device

for i in range(120):

	status = session.getAuthenticatorStatus()

	if session.getAuthenticatorStatus() == "active":
		break
	time.sleep(1)

if status != "active":
	del session
	sys.exit("Mobile device was not activated")

# Simulate a "login" prompt

for i in range(3):

	username = input("login: ")
	password = input("password: ")

	if username == 'ece568' and password == 'password':

		session.sendStepup()

		status = session.getStepupStatus()
		while status == "pending":
			time.sleep(1)
			status = session.getStepupStatus()

	else:
		status = "invalid"

	if ( status == "success" ):
		print("login successful\n")
		break
	else:
		print("login failed\n")

del session

