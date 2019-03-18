#a simple network scanner which returns the IP and 
#Mac addresses on the network using scapy library
#you can try removing the '#' to see different form of result (non-filtered result)
try:
    import argparse
    import sys
    sys.path.append(r'/usr/lib/python2.7/dist-packages/')
    import scapy.all
except AttributeError :
    print("[-] Attribute error from scapy\n")
except IndentationError :
    print("[-] Indentation error from scapy\n")

else:
    try:
        def inputArguments():
            parser = argparse.ArgumentParser()
            parser.add_argument("-i", "--ipadd", dest="ip", help=" specify target ip address ")
            options = parser.parse_args()
            if not options.ip:
                print("[-] Please specify ip address , type --help for more info ")
                exit(0)
            else:
                return options.ip

        def scan(ip):
            arp_req = scapy.all.ARP(pdst=ip)
            arp_req.pdst = ip
            #to make sure the destination is all Mac addresses and not just depend on IP address
            broadcast_mac = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_req_broadcast_mac = broadcast_mac/arp_req
            #to access just the answered list
            answered_list = scapy.all.srp(arp_req_broadcast_mac, timeout=1.5, verbose=False)[0]
            client_list = []

            for element in answered_list:
                #for each element, create a dictionary
                client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
                #to print all data in answered list i.e two parts of list : packets sent, answers
                #print(element)
                client_list.append(client_dict)
                #print("----------------------------------------------------------------")
                #to print only the second part of answerd_list i.e answers recieved
                #print(element[1].psrc, "\t\t", element[1].hwsrc)
            return client_list

        def print_result(result_list):
            print("IP\t\t\t Mac Address\n")
            for client in result_list:
                print(client["ip"], "\t\t", client["mac"])

        ip = inputArguments()
        client_list = scan(ip)

    except KeyboardInterrupt:
        print("[-] Program terminated ")

    except Exception:
        print("[-] Some error :(")

    else:
        print_result(client_list)
        print("\n\nFinished\n----X-----X------X------X------X-------X------X----\n")