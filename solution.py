from socket import *
import os
import sys
import struct
import time
import select
import binascii


ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
struct_format = "bbHHh"

# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise


def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0


    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2


    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff


    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.
    process_id = os.getpid() & 0xFFFF
    checkSum = 0
    header = struct.pack(struct_format, ICMP_ECHO_REQUEST, 0, checkSum,process_id,1)
    data = struct.pack("d", time.time())

    checkSum = checksum (header + data)

    if sys.platform == "darwin":
       checkSum = htons(checkSum) & 0xffff
    else:
       checkSum = htons(checkSum)

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    header = struct.pack(struct_format, ICMP_ECHO_REQUEST, 0, checkSum, process_id,1)

    # Don’t send the packet yet , just return the final packet in this function.
    #Fill in end

    # So the function ending should look like this


    packet = header + data
    return packet


def get_route(hostname):
    #print("first check",hostname)
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace 
    tracelist2 = [] #This is your list to contain all traces


    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)
            print("destadd", destAddr)
            #Fill in start
            icmp_sock = getprotobyname("icmp")
            # Make a raw socket named mySocket
            mySocket = socket (AF_INET, SOCK_RAW, icmp_sock)
            #Fill in end
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                #print("host",hostname)
                mySocket.sendto(d, (hostname, 0))
                print("sent", hostname)
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                #print("whatReady", whatReady)
                howLongInSelect = (time.time() - startedSelect)
                #print("howlong", howLongInSelect)
                if whatReady[0] == []: # Timeout
                    tracelist1.append("* * * Request timed out.")
                    #Fill in start
                    tracelist2.append(tracelist1)
                    #You should add the list above to your all traces list
                    #Fill in end
                #print("check")
                recvPacket, addr = mySocket.recvfrom(1024)
            
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    #Fill in start
                    tracelist2.append(tracelist1)
                    #You should add the list above to your all traces list
                    #Fill in end
                
                #print("tracelist1", tracelist1)
                #print("tracelist2", tracelist2)


            except timeout:
                continue


            else:
                #Fill in start
                #Fetch the icmp type from the IP packet
                
                icmp_header = recvPacket [20:28]
                types, code, checksum, pkt_id, seq = struct.unpack(struct_format,icmp_header)
                calc_time = str((timeReceived-t)*1000)

                #Fill in end
                try: #try to fetch the hostname
                    #print("hey")
                    resolved_host = gethostbyaddr(addr[0])[0]
                    #resolved_host = gethostbyaddr(addr[0])
                    #print("doublehey")
                    #Fill in end
                except herror:   #if the host does not provide a hostname
                    #print("here")
                    #Fill in start
                    tracelist1.append(ttl)
                    tracelist1.append("hostname not returnable")
                    #Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    tracelist1.append(ttl)
                    tracelist1.append(calc_time + "ms")
                    tracelist1.append(addr[0])
                    #tracelist1.append(destAddr)
                    tracelist2.append(tracelist1)
                    #You should add your responses to your lists here
                    #Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    tracelist1.append(ttl)
                    tracelist1.append(calc_time + "ms")
                    tracelist1.append(addr[0])
                    #tracelist1.append(destAddr)
                    tracelist2.append(tracelist1)
                    #You should add your responses to your lists here 
                    #Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    tracelist1.append(ttl)
                    tracelist1.append(calc_time + "ms")
                    tracelist1.append(addr[0])
                    #tracelist1.append(addr[0])
                    tracelist2.append(tracelist1)
                    return tracelist2
                    #You should add your responses to your lists here and return your list if your destination IP is met
                    #Fill in end
                else:
                    #Fill in start
                    tracelist1.append("Reuqst timed out")
                    tracelist2.append(tracelist1)

                #print("list1", tracelist1)
                #print("list2", tracelist2)


                    #If there is an exception/error to your if statements, you should append that to your list here
                    #Fill in end
                break
            finally:
                mySocket.close()
        print(tracelist2)
    return tracelist2
    


get_route("www.cnbc.com")
