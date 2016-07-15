#!/usr/bin/python

import nmap
import optparse
import socket
from subprocess import call

def nmapScan(tgtHost):
    nmScan = nmap.PortScanner()
    try:
        socket.inet_aton(tgtHost)
        print '[+] Scanning ' + tgtHost + '\n'
    except socket.error:
        print '[-] Invalid host or IP address\n'
        exit(0)
    nmScan.scan(tgtHost, '0-1023', '-sV --script=banner')
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
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    if (tgtHost == None):
        print parser.usage
        exit(0)
    nmapScan(tgtHost)

if __name__ == '__main__':
    main()
