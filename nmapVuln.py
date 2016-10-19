#!/usr/bin/python

import nmap
import optparse
import socket
from subprocess import call

def nmapScan(tgtHost,options):
    nmScan = nmap.PortScanner()
    try:
        socket.inet_aton(tgtHost)
        print '[+] Scanning ' + tgtHost + '\n'
    except socket.error:
        print '[-] Invalid host or IP address\n'
        exit(0)
    if options.scanFull:
        print '[+] Performing full scan of 65535 ports' 
        nmScan.scan(tgtHost, '0-65535', '-sV --script=banner')
    elif options.scanPplr:
        print '[+] Performing scan of 1000 popular ports'
        nmScan.scan(hosts=tgtHost, arguments='-sV --top-ports 1000  --script=banner')
    else:
        print '[+] Scanning up to port 1024'
        nmScan.scan(tgtHost, '0-1024', '-sV --script=banner')
    if  nmScan[tgtHost].has_key('tcp'):
        ports=nmScan[tgtHost]['tcp'].keys()
    else:
        print "[-] No open TCP ports"
        exit(0)
    for port in ports:
        name = nmScan[tgtHost]['tcp'][int(port)]['name']
        product = nmScan[tgtHost]['tcp'][int(port)]['product']
        state = nmScan[tgtHost]['tcp'][int(port)]['state']
        version = nmScan[tgtHost]['tcp'][int(port)]['version']
        print " [*] " + tgtHost + " tcp/" + str(port) + " " + state + " " + name + " " + product + " " + version + "\n"
        if product == None or product == True:
            findVuln(name,version)
            print '[+] Searchsploit ' + name + ' ' + version + '\n'
        else:
            findVuln(product,version)
            print '[+] Searchsploit ' + product + ' ' + version + '\n'

def findVuln(product,version):
    call(["searchsploit", product, version])

def main():
    parser = optparse.OptionParser('usage: %prog -H <target host>')
    parser.add_option('-F', '--full', dest='scanFull', action='store_true', help='full scan 65535 ports')
    parser.add_option('-H', '--host', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-P', '--popular', dest='scanPplr', action='store_true', help='scan top 1000 \033[1mpopular\033[0m ports')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    if (tgtHost == None):
        print parser.usage
        exit(0)
    nmapScan(tgtHost,options)

if __name__ == '__main__':
    main()
