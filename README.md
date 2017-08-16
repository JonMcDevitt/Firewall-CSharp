#Firewall

A revisiting of my Firewall program from a NetSec course assignment, redoing in the .NET framework. The program is used as follows:

1. Pass a JSON string to FireWallInterface.

    The FireWallInterface parses the string and constructs JObjects from each firewall designate in the object.
    
2. Pass a set of packets to FireWall containing source and destination.
    
    For the purposes of this rudimentary code, packets are simply lines of text containing a source and destination IP.