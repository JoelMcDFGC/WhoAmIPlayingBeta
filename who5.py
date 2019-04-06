from scapy.all import *
import geoip2.database
from collections import Counter
import _thread
import ipaddress
import csv
import pickle

IPseen = ["", "", "", "", "", "", "", "", ""]
FalseIPs = []
reader = geoip2.database.Reader('GeoLite2-City.mmdb')
stop = ""
count = 0
pause = "hiouh"
blacklist = ""
TIME = time.time()
dict =	{"95.146.229.158" : "God"}
with open('notes.txt', 'rb') as handle:
    dict = pickle.loads(handle.read())

def Check(Seen): #Check IP frequency
    check = (Counter(Seen))
    for x in check:
        if x != "":
            if check[x] > 5:
               return (x) #CHECK if this is good or not


def input_thread(a_list):
    hello = "udshiushda"
    global count
    global stop
    global pause
    global blac
    global IPseen
    global blacklist
    global dict
    while True:
        hello = input()
        if (hello != "udshiushda"):
            pause = "pause"
            time.sleep(0.2)
            hello = input("::>")
        if hello.lower() == "quit" or hello == "q":
            print("Quiting")
            stop = "shit"
            time.sleep(0.5)
        elif hello.lower() == "help" or hello == "?" or hello == "":
            print("help I need an adult\nCommands:\nhelp - ? = THIS\nadd = add somthing to blacklist\nr - Restart = reset all\nn - notes = add notes about IP, IE player name, character, personal black list of players\nquit - q = Quit")
            time.sleep(1)
        elif hello.lower() == "add":
            pause = "pause"
            print("The IP Address you have seen are: " + str(IPseen))
            hello = input("IP to add to blacklist?\n::>")
            blacklist += (" and !(dst " + hello + ")")  # add check to make sure it's an IP address?
        elif hello.lower() == "r" or hello.lower() == "restart" :
            count = 0
        elif hello.lower() == "notes" or hello.lower() == "n":
            pause = "pause"
            time.sleep(0.2)
            with open('notes.txt', 'rb') as handle:
                dict = pickle.loads(handle.read())
            if IPseen[0] in dict:
                print("Notes for " + IPseen[0] + " " + dict.get(IPseen[0]) + ": ")
                notes = input("Creating new notes\nq to quit\n::>")
                if notes != "" and notes != "q":
                    dict.update({IPseen[0]: notes})
                    with open('notes.txt', 'wb') as handle:
                        pickle.dump(dict, handle)
            else:
                notes = input("Creating new notes for: " + IPseen[0] + "\nq to quit\n::>")
                if notes != "" and notes != "q":
                    dict.update({IPseen[0]: notes})
                    with open('notes.txt', 'wb') as handle:
                        pickle.dump(dict, handle)
            pass
        pause = "sdsa"

a_list = []
_thread.start_new_thread(input_thread, (a_list,))

def PrivateIPs(IP):
    if ipaddress.ip_address(IP) in ipaddress.ip_network('192.168.0.0/16'):
        return
    elif ipaddress.ip_address(IP) in ipaddress.ip_network('10.0.0.0/8'):
        return
    elif ipaddress.ip_address(IP) in ipaddress.ip_network('172.16.0.0/12'):
        return
    elif ipaddress.ip_address(IP) in ipaddress.ip_network('34.192.0.0/10'):#AMAZON probably the publisher capcom namco etc ++ This might need to be removed for SFV. we will see
        return
    elif ipaddress.ip_address(IP) in ipaddress.ip_network('224.0.0.0/4'):  # I don't even know what this is but I see it some times so *shrugs*
        return
    else:
        return "GOOD"

def MainSniffer(packet):
    global TIME
    global IPseen
    global dict
    if packet.haslayer(IP) and PrivateIPs(str(packet[IP].dst)) == "GOOD":
        if time.time() - TIME >= 3:#Reset if no packets for a while - may need adjjusting
            IPseen = ["", "", "", "", "", "", "", "", ""]
        TIME = time.time()
        if str(packet[IP].dst) not in FalseIPs:
            IPseen.insert(0, str(packet[IP].dst))
            IPseen.pop()
        Cheked = Check(IPseen)
        if Cheked:
            if Cheked in dict:
                try:
                    print(reader.city(Cheked).country.name + " " + reader.city(Cheked).city.name + " " + Cheked + " NOTES: " + dict.get(Cheked))
                except Exception:
                    try:
                        print(reader.city(Cheked).country.name + " " + Cheked + " NOTES: " + dict.get(Cheked))
                    except Exception:
                        print("No/ don't ready up yet: " + Cheked + " NOTES: " + dict.get(Cheked))
            else:
                try:
                    print(reader.city(Cheked).country.name + " " + reader.city(Cheked).city.name + " " + Cheked)
                    time.sleep(1)
                except Exception:
                    try:
                        print(reader.city(Cheked).country.name + " " + Cheked)
                    except Exception:
                        print("No/ don't ready up yet: " + Cheked)

        elif IPseen[0]:
            if IPseen[0] in dict:
                try:
                    print("No/ don't ready up yet ## Current: " + reader.city(str(IPseen[0])).country.name + " " + reader.city(str(IPseen[0])).city.name + " " + str(IPseen[0]) + " NOTES: " + dict.get(IPseen[0]))
                except Exception:
                    try:
                        print("No/ don't ready up yet ## Current: " + reader.city(str(IPseen[0])).country.name + " " + str(IPseen[0])  + " NOTES: " + dict.get(IPseen[0]))
                    except Exception:
                        print("No/ don't ready up yet " +str(IPseen[0])  + " NOTES: " + dict.get(IPseen[0]))

            else:
                try:
                    print("No/ don't ready up yet ## Current: " + reader.city(str(IPseen[0])).country.name + " " + reader.city(str(IPseen[0])).city.name + " " + str(IPseen[0]))
                except Exception:
                    try:
                        print("No/ don't ready up yet ## Current: " + reader.city(
                            str(IPseen[0])).country.name + " " + str(IPseen[0]))
                    except Exception:
                        print("No/ don't ready up yet " + str(IPseen[0]))


def FalsePos(packet):           #Returns False Possitives seen in first 5 seconds
    global a
    if packet.haslayer(IP):
        if str(packet[IP].dst) not in FalseIPs:
            FalseIPs.append(str(packet[IP].dst))

print("Starting now")

def Main():
    global count
    global pause
    global blacklist
    while not stop:
        #print (pause)
        if pause != "pause":
            #sniff(count=1, filter="udp and portrange 1000-65535 and !(dst 192.168.1.206)", prn=MainSniffer)
            if count < 1:
                print("Collecting False Positives don't start search for players yet!!")
                blacklist = "udp and portrange 1000-65535"
                FalseIPs = []
                sniff(timeout=5, filter=blacklist, prn=FalsePos)
                for i in FalseIPs:
                    blacklist += (" and !(dst " + str(i) + ")")
                print("Good to GO!")
            sniff(timeout=0.5, count=1, filter=blacklist, prn=MainSniffer)
            count += 2
try:
    Main()
except KeyboardInterrupt:
    stop = "shit"
    exit()
print ("GGs WP")