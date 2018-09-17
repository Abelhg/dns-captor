# -*- encoding=utf-8 -*-

import socket
import sys

PORT = 53

try:
    # Sets IP
    hex_ip = ""
    valid = False
    while not valid:
        ip = raw_input("\n[?] IP to redirect: ")
        fields = ip.split('.')
        if(len(fields) != 4):
            print "\n[!] Error. Enter a valid IPv4 address."
        else:
            i = 0
            noerror = True
            while i < 4 and noerror:
                field = fields[i]
                try:
                    val = int(field)
                    if val >= 0 and val <= 255:
                        hex_ip += chr(val)
                    else:
                        print "\n[!] Error. Value", field, "must be in range [0-255]."
                        noerror = False
                except ValueError:
                    print "\n[!] Error. Value", field, "is not a number."
                    noerror = False
                
                i += 1

            if noerror: valid = True

    # UDP packet
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # TTL set to 0 to avoid DNS poisoning effect
    serverSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 0)

    try:
        serverSocket.bind(("", PORT))
    except socket.error, exc:
        print "\n[!!!] Caught exception socket.error:", exc
        sys.exit()
        
    print "[*] Socket bind completed."

    while True:
        data, clientAddress = serverSocket.recvfrom(1024)
        print "[DEBUG] data:", data
        dns_response = ""
        t_id = data[:2]
        flags = "\x81\x80" # Standard query response, no error
        questions = "\x00\x01"
        answerRRs = "\x00\x01"
        nullRRs = "\x00\x00\x00\x00"
        query = data[12:]
        answer = "\xC0\x0C\x00\x01\x00\x01\x00\x00\x38\x3F\x00\x04" + hex_ip

        dns_response = t_id + flags + questions + answerRRs + nullRRs + query + answer
        print "[DEBUG] Response:", dns_response
        serverSocket.sendto(dns_response, clientAddress)
except KeyboardInterrupt:
    pass

print "\nBye bye."