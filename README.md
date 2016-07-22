#Instructions for creating SFC with ONOS and OpenStack

There is a guide on how to create a SFC.

#DPDK apps
some useful DPDK apps.

## packet_gen

- creates packets with
    + ethernet header (set destination with `-m MAC`)
    + IP header (set source with `-s IP` and destination with `-d IP`)
    + UDP header (setting dest port does not work)
    + UDP Data (type in text after `message>`)

## logging

- logs packets and prints
    + ehternet: source, dest, type
    + ip: soruce ip, dest ip
    + udp: content as text

## forwarder

- forwards packets
    + blocks packets with destination MAC diffrent than own MAC
    + counts incomming and outgoing packets