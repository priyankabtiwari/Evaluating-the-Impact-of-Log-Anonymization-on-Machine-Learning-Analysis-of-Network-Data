#This is drop_field script is using for drop, encrypt, keep colums for the internet traffic logs for Purdue PULSAR system
#This code is written by Nanxin Jin, 04-18-2019
#In order to use this script, you need to give it a input file(log), this script will generate a lookup-table for each field.
#The operation for each field will be followed with lookup-table.
#operations: 0-keep
#            1-drop
#            2-encrypt
#            3-hash
#For connect log, the lookup-table should be 1 0 1 2 0 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1
import csv
import numpy
import crypt
from cryptopan import CryptoPan
c = CryptoPan("asdfasdfasdfasdfasdfasdfasdfasdf")

#count how many field we have for the log and create a lookup-table for these fields
with open("conn-test.log") as infile:
	reader = csv.reader(infile, delimiter='\t',skipinitialspace=True)
	first_row = next(reader)
	num_cols = len(first_row)

print 'number_of_cols: ', num_cols

lookup_table = numpy.zeros((1,num_cols))
#This lookup_table can be changed
# 4 is for IP address encrypt test only
# 5 is for hash field  TEST only
lookup_table = (1,0,1,4,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,5,5)

#TEST: Print original data
print('Original data set:')
with open('conn-test.log', 'r') as fp:
	line = fp.readline()
	cnt = 1
	while line:
		str1 = "".join(line)
		row = str1.split('\t')
		print(row)
		line = fp.readline()
		cnt += 1


#Drop colums
print('New data with dropped column:')
outfile = open('conn-test-drop.log', 'w')
with open('conn-test.log','r') as fp:
	line = fp.readline() #read line by line
	cnt = 1
	while line:
		str1 = "".join(line)
		row=str1.split('\t') #split each field from each row
		i = 0
		while i < num_cols: #check with lookup_table that which field should be dropped
			if lookup_table[i] == 1:
				row[i] = '*'
            		elif lookup_table[i] == 4: #encrypt the IP address
                		row[i] = c.anonymize(row[i])
			elif lookup_table[i] == 5: #hash the orig_12_addr, resp_12_addr
				print(row[i])
				row[i] = crypt.crypt(row[i],"$6$pulsar")
			i += 1 		
		print(row)
		new_row = '\t'.join(row) #combine array to string in order to write in to a new file
		outfile.write(new_row) #write the dropped field row to the output file
		outfile.write('\n') #add a new line 
		line = fp.readline() #read next line from original data
		cnt += 1
outfile.close()
