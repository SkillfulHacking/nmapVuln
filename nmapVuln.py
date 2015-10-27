#!/usr/bin/python

import nmap
import optparse
from subprocess import call

def nmapScan(tgtHost):
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost, '0-1023', '-sV -sC = banner')
    ports=nmScan[tgtHost]['tcp'].keys()
    for port in ports:
        name = nmScan[tgtHost]['tcp'][int(port)]['name']
        product = nmScan[tgtHost]['tcp'][int(port)]['product']
        state = nmScan[tgtHost]['tcp'][int(port)]['state']
        version = nmScan[tgtHost]['tcp'][int(port)]['version']
        print " [*] " + tgtHost + " tcp/" + str(port) + " " + state + " " + name + " " + product + " " + version + "\n"
        if product == none:
            findVuln(name,version)
        else:
            findVuln(product,version)

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
