# ASA-Config-to-HTML

Use by copying the output of a show running-configuration command into a file named "config.txt" in the same folder as the script an then execute the script.
The output will be a HTML-File named "Config_Parse"

This file contains ACLs, Anyconnect user, IPSec Tunnel, Group Policies each divided into "need to be checked" and "are configured properly" as well as IPPools and Objects/Object-Groups that need to be checked.

There is a lot of stuff that still needs to be added and if you find that the scipt ends prematurely or parses something wrong, please don't hesitate to tell me.
The last entry of the output file will always be the "Object-Groups" table.
