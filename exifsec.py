import os
import base64
import getpass
import piexif
import json
import pickle
import uuid
import inspect
import colorama
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# To start virtual environment
# workon EXIFSEC

# For Debugging
DEBUG = False

# Define globally used options
yes = ['y','yes']
no = ['n','no']
yes_no = yes + no

# Define options
op0 = "\t 0. EXIT\n"
op1 = "\t 1. Secure\n"
op2 = "\t 2. Restore\n"
ops = [0,1,2]

total_files = 0
processed = 0
err_count = 0 

def main():
	# Init colors if on windows
	colorama.init()

	while True:

		global total_files
		global processed
		global err_count 
		total_files = 0
		processed = 0
		err_count = 0

		# Grab the user inputted option
		option = get_option()

		if(option == 0):                # Option 0 = Exit
			break

		elif(option == 1):              # Option 1 = Encrypt Test.JPG
			op3_path_encrypt()

		elif(option == 2):              # Option 2 = Decrpyt Test.JPG
			op4_path_decrypt()

	# Deinit
	colorama.deinit()

def get_option():
	# Loop for valid input
	while True:
		# Get the input
		try:
			option = int(input("\nSelect an option number: \n" + op0 + op1 + op2))
		except ValueError:
			printError("ERROR: Please type the option number.")
			continue
		if(option not in ops):          # If not a valid option
			printError("ERROR: Please select a number from: " + str(ops))
			continue
		else:
			break

	return option

def get_path(operation):
	print("\t ~ \t get_path()") if DEBUG else None
	# Loop for a valid path
	while True:
		# Get the path
		path = input("Enter a path:\n")

		if(os.path.isfile(path)):                               # Check if this is a single file
			you_sure = input("This is a single file. Are you sure you only want to " + operation + " one file? y/n \n")
			return path if(get_yes_no(you_sure)) else None

		elif(os.path.isdir(path)):                              # Check if this is a directory
			you_sure = input("Do you want to " + operation + " all files in this directory? y/n \n")
			return path if(get_yes_no(you_sure)) else None 
		else:
			printError("ERROR: Please enter a valid path.")
			continue    

def get_yes_no(ans):
	while True:
		if(ans not in yes_no):  # Not yes or no answer
			print("Please type yes or no.")
			continue
		elif(ans in yes):       # Said yes
			return 1
		elif(ans in no):        # Said no
			return 0

def op3_path_encrypt():
	file_path = get_path("secure")

	# Handle Cancel
	if(file_path == None): return
	# Handle file/s
	file_walker_encrypt(file_path)

def op4_path_decrypt():
	file_path = get_path("restore data for")

	# Handle Cancel
	if(file_path == None): return
	# Handle file/s
	file_walker_decrypt(file_path)


# Get password securely
def get_pass():
	pswd = str.encode(getpass.getpass('Enter password:'))
	return pswd

##################################
#### 	    MAIN WALKERS      ####
##################################

# Encryptor
def file_walker_encrypt(file_path):
	print("\t ~ \t file_walker_encrypt()", file_path, sep=", ") if DEBUG else None
	
	pswd = get_pass()
	prev_data = {}

	prev_data = load_previous_data(pswd)
	paths = load_all_paths(file_path)
	global total_files
	total_files = len(paths)
	global processed
	processed = 0


	for file_name in paths:
		prev_data = add_and_strip(file_name, prev_data, pswd)



	enc_dat, salt = pickle_and_encrypt(prev_data, pswd)
	write_files(enc_dat, salt)
	printGood("Secured " + str(processed) + " of " + str(total_files) + " files with " + str(err_count) + " errors.")

# Decryptor
def file_walker_decrypt(file_path):
	print("\t ~ \t file_walker_decrypt()", file_path, sep=", ") if DEBUG else None
	pswd = get_pass()
	prev_data = {}

	prev_data = load_previous_data(pswd)
	paths = load_all_paths(file_path)
	global total_files
	total_files = len(paths)
	global processed
	processed = 0

	for file_name in paths:
		restore_data(file_name, prev_data)					# Restore

	printGood("Restored " + str(processed) + " of " + str(total_files) + " files with " + str(err_count) + " errors.")

##################################
#### 	    MAIN LOADERS      ####
##################################
def load_previous_data(pswd):
	print("\t ~ \t load_previous_data()", pswd, sep=", ") if DEBUG else None

	prev_data = {}

	if(os.path.isfile('EXIFSEC_DATA') and os.path.isfile('EXIFSEC_DATA')):
		with open('EXIFSEC_DATA', 'rb') as content_file:	
			enc_data = content_file.read()

		with open('EXIFSEC_SALT', 'rb') as content_file2:
			salt = content_file2.read()
	
		prev_data = decrypt_data(enc_data, pswd, salt)						# Decrypt data

	return prev_data 

def load_all_paths(file_path):
	print("\t ~ \t load_all_paths()", file_path, sep=", ") if DEBUG else None

	paths = []

	if(os.path.isfile(file_path)):
		paths.append(file_path)
		return paths

	for root, dirs, files in os.walk(file_path):
		for name in files:
			file_name = os.path.join(root, name)
			if(file_name.lower().endswith(('.jpg', '.jpeg'))):		# Is a JPEG
				paths.append(file_name)

	#print("\t ~ \t paths", paths, sep=", ") if DEBUG else None
	
	return paths
	

###############################
#### 	Add and Strip  	   ####
###############################
def add_and_strip(file_name, prev_data, pswd):
	print("\t ~ \t add_and_strip()", file_name, pswd, sep=", ") if DEBUG else None

	global err_count

	try:
		tags = piexif.load(file_name)								# 1) Load tags
	except Exception:
		printError(file_name + " has broken EXIF. Stripping and trying again.")
		handle_broken(file_name)
		tags = piexif.load(file_name)
		err_count += 1

	tags = UUIDJanitor(tags)										# 2) Check and fix for UUID

	uniqueID = tags["Exif"][piexif.ExifIFD.ImageUniqueID]

	giveProgress()

	try:
		if(uniqueID not in prev_data):									# 3) Check if already in encrypted data
			prev_data[uniqueID] = tags 									# 4) Add if not
			printNotice("Securing " + file_name + "... ")
		else:
			printGood(file_name + " already secured. ")
			check_more_data(prev_data[uniqueID], tags)
					
		strip_data(file_name, uniqueID)									# 5) Strip the file
		printCheck()

	except Exception:
		err_count += 1
		printError("X")
												
	return prev_data


# Writes data and salt
def write_files(data, salt):
	print("\t ~ \t write_files()", sep=", ") if DEBUG else None

	f = open('EXIFSEC_DATA', 'wb')
	f.write(data)
	f.close()

	f2 = open('EXIFSEC_SALT', 'wb')
	f2.write(salt)
	f2.close()


def check_more_data(prev_data, new_data):
	if(len(prev_data) < len(new_data)):
		printNotice("HUH? Why ism")

def handle_broken(file_name):
	image_file = open(file_name, 'rb')
	image = Image.open(image_file)

	# next 3 lines strip exif
	data = list(image.getdata())
	image_without_exif = Image.new(image.mode, image.size)
	image_without_exif.putdata(data)

	image_without_exif.save(file_name)
 
###############################
#### 	DATA ADDING   	   ####
###############################

# Pickles the data and encrypts it
def pickle_and_encrypt(data, pswd):
	print("\t ~ \t pickle_and_encrypt()", data.keys(), pswd, sep=", ") if DEBUG else None

	pickle_bytes = pickle.dumps(data)                               # 1) Convert data to pickle bytes
	enc_dat, salt = encrypt_data(pickle_bytes, pswd)                # 2) Encrypt data
	return enc_dat, salt


###############################
#### 	DATA REMOVAL   	   ####
###############################

# Strip data helper
def strip_data(file_name, uniqueID):
	print("\t ~ \t strip_data()", file_name, uniqueID, sep=", ") if DEBUG else None

	try:
		piexif.remove(file_name)										# 1) Strip all tags
		empty_exif = piexif.load(file_name)								# 3) Get the empty file tags
	except:
		handle_broken(file_name)
		empty_exif = piexif.load(file_name)								# 3) Get the empty file tags


	
	empty_exif["Exif"][piexif.ExifIFD.ImageUniqueID] = uniqueID 	# 4) Add uniqueID to empty data
	exif_bytes = piexif.dump(empty_exif)							# 5) Convert to bytes
	piexif.insert(exif_bytes, file_name)							# 6) Insert into file

	#printNotice("Stripping " + file_name + " data.")
 

###############################
#### 	ENCRYPTION         ####
###############################

def encrypt_data(data, pswd):
	print("\t ~ \t encrypt_data()", sep=", ") if DEBUG else None

	salt = os.urandom(16)
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
	key = base64.urlsafe_b64encode(kdf.derive(pswd))
	f = Fernet(key)
	token = f.encrypt(data)
	return token, salt


###############################
#### 		DECRYPTION     ####
###############################
def decrypt_data(data, pswd, salt):
	print("\t ~ \t decrypt_data()", sep=", ") if DEBUG else None

	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
	key = base64.urlsafe_b64encode(kdf.derive(pswd))
	f = Fernet(key)
	pickle_data = f.decrypt(data)									# 1) Data is decrypted
	data = pickle.loads(pickle_data)								# 2) Depickle data
	return data


###############################
#### 	RESTORATION        ####
###############################

# Restoration of one
def restore_data(file_name, prev_data):
	print("\t ~ \t restore_data()", file_name, sep=", ") if DEBUG else None

	#image_file = open(file_name, 'rb')
	tags = piexif.load(file_name)									# 1) Load tags
	tags = UUIDJanitor(tags)										# 2) Check and fix for UUID

	uniqueID = tags["Exif"][piexif.ExifIFD.ImageUniqueID]

	giveProgress()
	try:
		if(uniqueID in prev_data):										# 3) Check if already in encrypted data
			printNotice("Restoring " + file_name + "... ")
			file_data = prev_data[uniqueID]
			exif_bytes = piexif.dump(file_data)							# 4) Convert to bytes
			piexif.insert(exif_bytes, file_name)						# 5) Insert EXIF data into file
			printCheck()
			
		elif(DEBUG):
			print("No data to restore")
	except Exception:
		err_count += 1
		printError("X")


###############################
#### 		HELPERS        ####
###############################

# Checks for a valid UUID; Generates one if not
def UUIDJanitor(tags):
	print("\t ~ \t UUIDJanitor()", sep=", ") if DEBUG else None

	exifTags = tags["Exif"]
	# Check for anything in the UniqueID Field
	if(piexif.ExifIFD.ImageUniqueID in exifTags):
		uniqueID = exifTags[piexif.ExifIFD.ImageUniqueID].decode("utf-8") 	# 1) Get id field
		try:
			#print("Valid UUID")
			valid = uuid.UUID(uniqueID, version=4)							# 2) Check if its an UUID
		except Exception:
			#print("Not valid")
			uniqueID = uuid.uuid4().hex										# 3) Generate a new one if not
	else:
		#print("Doesn't Exist")
		uniqueID = uuid.uuid4().hex											# 4) Generate a new one if nothing

	tags["Exif"][piexif.ExifIFD.ImageUniqueID] = uniqueID

	return tags

def printError(error):
	print(colorama.Fore.RED + error)
	print(colorama.Style.RESET_ALL)

def printNotice(notice):
	print(colorama.Fore.YELLOW + notice, end='')
	print(colorama.Style.RESET_ALL, end='')

def printGood(text):
	print(colorama.Fore.GREEN + text, end='')
	print(colorama.Style.RESET_ALL, end='')

def printCheck():
	print(colorama.Fore.GREEN + (u'\u2713'))
	print(colorama.Style.RESET_ALL, end='')

def giveProgress():
	global processed
	processed += 1
	print("["+str(processed)+"/"+str(total_files)+"]", end=' ')

if __name__ == "__main__":
	main()