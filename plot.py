
import datetime
import csv

csvfilename="mstat.csv"

ts = "2017-06-26 19:24:12"

time_fmt = "%Y-%m-%d %H:%M:%S"


dt = datetime.datetime.strptime(ts, time_fmt)

print dt
#print dt.timetuple()
#print dt.weekday()
isoc = dt.isocalendar()
print isoc

a = ts[11:].split(':')
mindex = (int(a[0]) * 12) + ( int(a[1]) / 5 )
print "week =", isoc[1]
print "day =", isoc[2]
print "5m =", mindex

with open('scapy-watch_stdout', 'r') as f:
    x = f.readlines()

# ['2017-06-26', '19:14:03', '54:be:f7:69:09:f7',
# 'set_status', 'is_pc_on', ':',
# '0/0', '->', '1', ':', 'MainThread',
# '50181.18', '49251.18']

active_macs = {}
for l in x:
    if l.startswith("2017"):
	a = l.split()
	if a[3] == 'set_status' and  a[8] == "1":
	    active_macs[a[2]] = a[4]

print active_macs



csvf = open(csvfilename, 'w')

fields = ["ts"] + sorted(active_macs.keys())


print fields

writer = csv.DictWriter(csvf, delimiter=',', fieldnames=fields)

# writer.writeheader()
active_macs['ts'] = 'ts'

writer.writerow(active_macs)
print "active_macs", active_macs


mdata = { m: 0 for m in fields } 
mindex = {fields[m]: m * 10  for m in range (len(fields)) }

#print fields
#print mdata
#print mindex

for l in x:
    if not l.startswith("2017"):
	continue

    a = l.split()
    if a[3] == 'set_status':
	# print l[:19], a[2], a[8]
	mdata['ts'] =  l[:19]
	mdata[a[2]] = int(a[8]) * mindex[a[2]]
	writer.writerow(mdata)
	#print a[1], a[2], a[6], a[6][:1], a[8]

 #   print a


