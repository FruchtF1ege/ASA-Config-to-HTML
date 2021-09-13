import os
import re
import sys



###################################################### Regexes and Os ######################################################
#IP Pools
re_ippool = re.compile('^ip\slocal\spool\s(?P<ippool>\S*)\s(?P<iprange>\S*)', re.IGNORECASE)
# object network mynet1
re_objnet = re.compile('^object\s+network\s(?P<obj_name>\S+)', re.IGNORECASE)
# subnet 10.1.2.0 255.255.255.0
re_subnet = re.compile('^\s*subnet\s+(?P<ip>\S+)\s+(?P<mask>\S+)', re.IGNORECASE)
# host 10.2.1.41
re_host = re.compile('^\s*host\s+(?P<ip>\S+)', re.IGNORECASE)
# object-group network mynetgrp1
re_netgrp = re.compile('^object-group\s+network\s(?P<net_grp>\S+)', re.IGNORECASE)
# network-object 10.1.1.1 255.255.255.255
re_netobj = re.compile('^\s*network-object\s+(?P<ip>\S+)\s+(?P<mask>\S+)', re.IGNORECASE)
# network-object host 10.1.1.1
re_netobj_host = re.compile('^\s*network-object\s+host\s+(?P<ip>\S+)', re.IGNORECASE)
# network-object object mynet1
re_netobj_obj = re.compile('^\snetwork-object\s+object\s(?P<obj_name>\S+)', re.IGNORECASE)
# object services mynet1
re_objser = re.compile('^object\s+service\s(?P<obj_name>\S+)', re.IGNORECASE)
# object-group service mysrvgrp1
re_srvgrp = re.compile('^object-group\s+service\s(?P<srv_grp>\S+)\s*$', re.IGNORECASE)
# object-group service srv_tcp tcp
re_srvgrp_obj = re.compile('^\sservice-object\sobject\s+(?P<obj_name>\S+)', re.IGNORECASE)
# object-group service srv_tcp tcp
re_srvgrp_proto = re.compile('^\s*object-group\s+service\s+(?P<srv_grp>\S+)\s+(?P<proto>\S+)', re.IGNORECASE)
# port-object eq ldaps
re_portobj = re.compile('^\s*port-object\s+(?P<service>.*$)', re.IGNORECASE)
# group-object net-10.1.0.0-16
re_grpobj = re.compile('^\sgroup-object\s(?P<obj_name>\S+)', re.IGNORECASE)
# service-object tcp destination eq 123
re_srvobj = re.compile('^\s*service-object\s+(?P<proto>\S+)(\s+destination)?\s+(?P<service>.*$)', re.IGNORECASE)
# service-object 97
re_srvobj_ip = re.compile('^\s*service-object\s+(?P<proto>\d+)', re.IGNORECASE)
# access-list acl_name extended ...
re_isacl = re.compile('^\s*access-list\s+\S+\s+extended', re.IGNORECASE)
# access-list name
re_aclname = re.compile('^\s*access-list\s+(?P<acl_name>\S+)\s+', re.IGNORECASE)
# access-group management_acl in interface management
re_aclgrp = re.compile('^\s*access-group\s+(?P<acl_name>\S+)\s+in\sinterface\s(?P<acl_int>.*$)', re.IGNORECASE)
# objects in acl
re_obj = re.compile('object\s(?P<obj>\S+)', re.IGNORECASE)
# fqdn name
re_fqdn = re.compile('^\sfqdn\s(?P<fqdn>.*)', re.IGNORECASE)
# Crypto Map and IPSec Name
re_ipsec = re.compile('\s+(?P<crypto_map>\S+)\s+(?P<map_number>\S+)\s*match\saddress\s+(?P<ipsec_name>\S+)', re.IGNORECASE)
# pfs with DH group
re_pfs = re.compile('^crypto\smap\s(?P<crypto_map>.*)\s(?P<map_number>.*)\sset\s+pfs\s+(?P<dh_group>.*$)', re.IGNORECASE)
# pfs without DH group
re_pfs_wo = re.compile('\s*set\s+pfs$', re.IGNORECASE)
# ipsec peers
re_peer = re.compile('^crypto\smap\s(?P<crypto_map>.*)\s(?P<map_number>.*)\sset\s+peer\s+(?P<peer_ip>.*$)', re.IGNORECASE)
# security associations Phase 2 (with ASS in it!!)
re_sec_ass_sec = re.compile('^crypto\smap\s(?P<crypto_map>.*)\s(?P<map_number>.*)\sset\ssecurity-association\slifetime\s(?P<seconds>seconds)\s(?P<number>.*)', re.IGNORECASE)
# security associations Phase 2 (with ASS in it!!)
re_sec_ass_kil = re.compile('^crypto\smap\s(?P<crypto_map>.*)\s(?P<map_number>.*)\sset\ssecurity-association\slifetime\s(?P<kilobytes>kilobytes)\s(?P<number>.*)', re.IGNORECASE)
# encryption proposal Phase 2
re_proposal = re.compile('^crypto\smap\s(?P<crypto_map>.*)\s(?P<map_number>.*)\sset\s+(?P<ikev>\S+)\s(ipsec-proposal|transform-set)\s+(?P<proposal_grp>.*$)', re.IGNORECASE)
# Peering Interface
re_peering_int = re.compile('crypto\smap\s(?P<crypto_map>.*)\sinterface\s+(?P<interface>.*)', re.IGNORECASE)
# Ikev1 Proposal Phase 2
re_ikev1_prop = re.compile('crypto\sipsec\sikev1\stransform-set\s(?P<Phase_2_name>\S*)\s(?P<proposals>.*)', re.IGNORECASE)
# Ikev2 Proposal Phase 2
re_ikev2_prop = re.compile('crypto\sipsec\sikev2\sipsec-proposal\s(?P<Phase_2_name>\S*)', re.IGNORECASE)
# Ikev2 Encryption Proposal Phase 2
re_ikev2_encr_prop = re.compile('^\sprotocol\sesp\sencryption\s(?P<ikev2_encryption>.*)', re.IGNORECASE)
# Ikev2 Integrity Proposal Phase 2
re_ikev2_inte_prop = re.compile('^\sprotocol\sesp\sintegrity\s(?P<ikev2_integrity>.*)', re.IGNORECASE)
# Ikev1 policy priority
re_ikev1_pol = re.compile('crypto\sikev1\spolicy\s(?P<priority>.*)', re.IGNORECASE)
# Ikev1 authentification Phase 1
re_ikev1_auth = re.compile('\sauthentication\s(?P<auth>.*)', re.IGNORECASE)
# Ikev1 encryption Phase 1
re_ikev1_enc = re.compile('\sencryption\s(?P<enc>.*)', re.IGNORECASE)
# Ikev1 integrity Phase 1
re_ikev1_hash = re.compile('\shash\s(?P<hash>.*)', re.IGNORECASE)
# Ikev1 DH Group Phase 1
re_ikev1_grp = re.compile('\sgroup\s(?P<group>.*)', re.IGNORECASE)
# Ikev1 lifetime Phase 1
re_ikev1_life = re.compile('\slifetime\s(?P<life>.*)', re.IGNORECASE)
# Ikev2 policy priority
re_ikev2_pol = re.compile('crypto\sikev2\spolicy\s(?P<priority>.*)', re.IGNORECASE)
# Ikev2 encryption Phase 1
re_ikev2_enc = re.compile('\sencryption\s(?P<enc>.*)', re.IGNORECASE)
# Ikev2 integrity Phase 1
re_ikev2_hash = re.compile('\sintegrity\s(?P<int>.*)', re.IGNORECASE)
# Ikev2 DH Group Phase 1
re_ikev2_grp = re.compile('\sgroup\s(?P<group>.*)', re.IGNORECASE)
# Ikev2 lifetime Phase 1
re_ikev2_life = re.compile('\slifetime\sseconds\s(?P<life>.*)', re.IGNORECASE)
# Ikev2 PRF Phase
re_ikev2_prf = re.compile('\sprf\s(?P<prf>.*)', re.IGNORECASE)
# webvpn enabled interfaces
re_webvpn_interface = re.compile('\senable\s(?P<interface>.*)', re.IGNORECASE)
# local ip pools for remote usage
re_ip_pools = re.compile('ip\slocal\spool\s(?P<poolname>.*)\s(?P<ip_range>.*\S)', re.IGNORECASE)
# tunnel_groups
re_tgrp_type = re.compile('^tunnel-group\s(?P<tgrp_name>.*)\stype\s(?P<tgrp_type>.*)', re.IGNORECASE)
# ikev1 preshared key
re_tgrp_key = re.compile('^\sikev1\spre-shared-key\s.*', re.IGNORECASE)
# ikev2 preshared key
re_tgrp_v2_key = re.compile('\sikev2\slocal-authentication\spre-shared-key\s.*', re.IGNORECASE)
# General Attributes of Tunnel Groups
re_tgrp_general_attributes = re.compile('^tunnel-group\s(?P<tgrp_name>.*)\sgeneral-attributes', re.IGNORECASE)
# Default Group Policy of Tunnel Groups
re_dflttgrp_general_attributes = re.compile('\sdefault-group-policy\s(?P<dflt_grp_pol_name>.*)', re.IGNORECASE)
# Tunnel Group webvpn attributes
re_tgrp_webvpn_attributes = re.compile('^tunnel-group\s(?P<tgrp_name>.*)\swebvpn-attributes', re.IGNORECASE)
# Tunnel Group Groupalias enable
re_trgp_grpalias_enable = re.compile('\sgroup-alias\s(?P<alias_name>.*)\senable', re.IGNORECASE)
# Tunnel Group Address Pool
re_tgrp_addr_pool = re.compile('\saddress-pool\s(?P<addr_pool>.*)', re.IGNORECASE)
# group-policy attributes
re_grp_pol_att = re.compile('group-policy\s(?P<group_name>.*)\sattributes', re.IGNORECASE)
# group-policy idle
re_grp_pol_idle = re.compile('^\svpn-idle-timeout\s(?P<seconds>.*)', re.IGNORECASE)
# group-policy split Tunnel
re_grp_pol_split = re.compile('^\ssplit-tunnel-policy\stunnelspecified', re.IGNORECASE)
# group-policy split Tunnel Value
re_grp_pol_split_acl = re.compile('^\ssplit-tunnel-network-list\svalue\s(?P<ACL>.*)', re.IGNORECASE)
# group-policy address pools (which override local pool settings)
re_grp_pol_pool = re.compile('^\saddress-pools\svalue\s(?P<address_pool>.*)', re.IGNORECASE)
# username for anyconnect vpn
re_user_name = re.compile('^username\s(?P<username>.*)\sattributes', re.IGNORECASE)
# Group-Policy/Username vpn-filter value
re_user_acl = re.compile('^\svpn-filter\svalue\s(?P<ACL>.*)', re.IGNORECASE)
# username group-lock
re_user_grplock = re.compile('^\sgroup-lock\svalue\s(?P<group>.*)', re.IGNORECASE)
# Phase 1
re_phase_1 = re.compile('^crypto\s(?P<ikev>(ikev1|ikev2))\senable\s(?P<interface>.*)', re.IGNORECASE)
# Crypto Numbers Unused
re_match_cnumber = re.compile('^crypto\smap\s\S+\s(?P<map_number>\S+)\s.*', re.IGNORECASE)
# Dynmap Number
re_match_dynmapnumber = re.compile('^crypto\smap\s\S+\s(?P<map_number>\S+)\s\S+\sdynamic\s.*', re.IGNORECASE)
# Anyconnect User
re_service_type_remote = re.compile('^\sservice-type\sremote-access', re.IGNORECASE)


###################################################### Initialise variables n Stuff. False? True? YOU Decide! ######################################################
AG = 'access-group'
number = 0
rulecnt = 0  # ACL rule counter
curacl = ''  # current ACL name
cur_ipsec = ' '
cur_transformset = ' '
cur_ipsec_proposal = ' '
cur_ike_pol = ' '
local_ip_pools = {}
cur_tgrp = ' '
cur_type = ' '
cur_grp_pol = ' '
cur_usr = ' '
start_ikev2_prop = False
start_ikev1_pol = False
start_ikev2_pol = False
anyconnect_enabled = False
webvpn = False
grp_pol = False
any_user = False
trgp = False
webvpn_ints = []
webvpn_joined = ''
list_drop_down = False
ikev1_pols = {}
ikev2_pols = {}
webvpn_set = []
ipsec_encr_int = {}
ipsec_dict = {}
crypto_int = {}
phase1_int_ike = {}
anyconnect_check = set()
anycon_pol_tunnel_acl = set()
tunnel_grp_set = set()
used_tgroups = set()
unused_tgroups = set()
peers_set = set()
acl_check = set()
ipsec_check = set()
ike_check = set()
grp_pol_check = set()
used_tgroups_remote = set()
used_tgroups_ipsec = set()
grp_pol_used = set()
grp_pol_all = set()
pol_acl_check_set = set()
pol_acl_used_set = set()
acls_used_set = set()
acls_users_used = set()
acls_all_set = set()
ippools_used = set()
ippools_unused = set()
ike_pol_used = set()
ike_pol_unused = set()
crypto_map_nr_used = set()
crypto_map_nr_unused = set()
# object-groups
objects_all = set()
objects_used = set()
objects_unused = set()
# object-groups including objects, but without hosts or subnets
obj_grps_all = {}
obj_grps_used = set()
obj_grps_unused = set()
cur_grp = ' '
ikev1_offerings = set()
nat = {} ########################## NAT is currently not supported ######################################################
dynmap = {} ########################## ikev1 and ikev2 dynmaps are currently not supported ######################################################
ikev2_proposals = {} # All available ikev2 proposals
transformsets = {} # All available Transformsets (Ikev1 Proposals)
access_grps_n_interf = {}  # All ACL names and corresponding interfaces
access_grps_n_interf_used = {}  # Actually used ACLs
network_objects = {}  # All configured network objects
network_groups = {}  # All configured network groups
service_objects = {}  # All configured serviceobjects
service_groups = {}  # All configured services groups
ipsec = {}  # All configured IPsec Crypto Maps
tunnel_group = {}  # All configured anyconnect Tunnel-Groups
group_policy = {}  # All configured anyconnect group policies
anyconnect_user = {}  # All configured anyconnect user
network_objects_used = {}  # Actually used network_objects
network_groups_folded = {}  # Actually used network groups
service_objects_used = {}  # Actually used serviceobjects
service_groups_used = {}  # Actually used services groups
ipsec_used = {}  # Actually used configured IPsec Crypto Maps
tunnel_group_used = {}  # Actually used anyconnect Tunnel-Groups
group_policy_used = {}  # Actually used anyconnect group policies
anyconnect_user_used = {}  # Actually used anyconnect user
network_objects_unused = {}  # Not used network_objects
network_groups_unused = {}  # Not used network groups
service_objects_unused = {}  # Not used serviceobjects
service_groups_unused = {}  # Not used services groups
ipsec_unused = set()  # Not used configured IPsec Crypto Maps
group_policy_unused = {}  # Not used anyconnect group policies
anyconnect_user_unused = {}  # Not used anyconnect user
user_name = 'Yeah'
ikev1_offerings = set()


###################################################### HTML Header and Table Functions ######################################################
def html_hdr(title):
    print('<html lang=en><head><title>' + title + '</title></head><body> <style> \
		body {background: #FFF5DD; color: #000080; font-family: sans-serif; padding-left: 20px; } \
		table {color: #000080; font-size: 0.8em; border: solid 1px #000080; border-collapse: collapse; } \
		th { font-size: 1em; padding: 0.8em; }\
		td {padding-left: 15px; padding-top: 5px; padding-bottom: 5px; padding-right: 15px;} \
		a {color: #0000d0; text-decoration: none;} \
		.permit {color: DarkGreen;} \
		.deny {color: DarkRed;} </style> \
		<h1>' + title + '</h1>')

def html_tbl_hdr(title, title1):
    print(
        '<table border=1><caption id=' + title + ' in Interface ' + title1 + '><h2>' + title + ' in Interface ' + title1 + '</h2></caption> \
	<tr><th>Line #</th><th>Access-List</th><th>Source-Objects</th><th>Source-Subnet</th><th>Destination-Objects</th><th>Destination-Subnet</th><th>Service-Objects</th><th>Service-Ports</th><th>Action</th></tr>')

def html_tbl_acl_hdr():
    print(
        '<table border=1><caption id=' + 'With the corresponding Access-Lists:' + '><h2>' + 'With the corresponding Access-Lists:' + '</h2></caption><tr><th>Line #</th><th>Access-List</th><th>Source-Objects</th><th>Source-Subnet</th><th>Destination-Objects</th><th>Destination-Subnet</th><th>Service-Objects</th><th>Service-Ports</th><th>Action</th></tr>')

def html_tbl_hdr_ipsec():
    print(
        '<table border=1><caption id=' + 'none' + ' in Interface ' + 'none' + '><h2>' '</h2></caption> \
	<tr><th>Line #</th><th>Access-List</th><th>Source-Objects</th><th>Source-Subnet</th><th>Destination-Objects</th><th>Destination-Subnet</th><th>Service-Objects</th><th>Service-Ports</th><th>Action</th></tr>')

def html_tbl_hdr_ipsec_2(encryption_domain, title1):
    print(
        '<table border=1><caption id=' + encryption_domain + ' in Interface ' + title1 + '><h2>' + encryption_domain + ' in Interface ' + title1 + '</h2></caption> \
            <tr><th>Peer</th><th>Phase 1 IKE Parameters</th><th>Phase 2 Parameters</th>')

# Display all Anyconnect Users that need to be checked
def anyconnect_users_check():
    colspan_len = len(anyconnect_check)
    print('<table border=1><caption id=' + 'Please check these Users' + '><h2>' + 'Please check these Users' + '</h2></caption><tr><th colspan='+ str(colspan_len) + '>Username</th></tr>')
    for user in anyconnect_check:
        print('<td>' + user + '</td>')

# Display all Access-Lists that need to be checked
def acl_check_tbl():
    print('<table border=1><caption id=' + 'Please check the following Access-Lists' + '><h2>' + 'Please check the following Access-Lists' + '</h2></caption><tr><th>Line #</th><th>Access-List</th><th>Source-Objects</th><th>Source-Subnet</th><th>Destination-Objects</th><th>Destination-Subnet</th><th>Service-Objects</th><th>Service-Ports</th><th>Action</th></tr>')

# Display all Crypto Map Numbers that can't work and are thus unused
def ipsec_check_tbl():
    colspan_len = len(crypto_map_nr_unused)
    print('<table border=1><caption id=' + 'Please check the following IPSec-VPNs' + '><h2>' + 'Please check the following IPSec-VPNs' + '</h2></caption><tr><th colspan='+ str(colspan_len) + '>Crypto Map Number</th></tr>')
    for map_nr in crypto_map_nr_unused:
        print('<td>' + map_nr + '</td>')

#print webvpn settings
def html_webvpn_tbl_header():
    print('<tr><th>Anyconnect User</th><th>Tunnel-Groups Available</th><th>Source IP Pool</th><th>Split Tunneling</th><th>Routed Traffic</th><th>Access-List</th>')

def html_tbl_ftr():
    print('</table><br /><br />')

def html_ftr(content):
    print('<div id=content><h2>Content</h2><ul>')
    for i in content:
        print('<li><a href=#' + i + '>' + i + '</a> ' + content[i] + '</i>')
    print('</ul></div></body></html>')

def html_tbl_tgp_hdr(title, title1):
    print(
        '<table border=1><caption id=' + 'Traffic is Routed through ACL ' + title + ' for the following Group-Policies ' + title1 + '><h2>' + 'Traffic is Routed through ACL ' + title + ' for the following Group-Policies ' + title1 + '</h2></caption> \
	<tr><th>Line #</th><th>Access-List</th><th>Source-Objects</th><th>Source-Subnet</th><th>Destination-Objects</th><th>Destination-Subnet</th><th>Service-Objects</th><th>Service-Ports</th><th>Action</th></tr>')

def html_tbl_tgp_check_hdr():
    print(
        '<h3>Traffic is Routed through the following ACLs for these corresponding Group-Policies that need to be checked</h3>')

def html_ippools_check_hdr():
    print('<h3>The following ippools need to be checked </h3>')

def html_grp_obj_check_hdr():
    print('<h3>The following Object-Groups and Objects need to be checked </h3>')

def html_tbl_pol_hdr():
    print(
        '<table border=1><caption id=' + 'Group-Policies' + '><h2>' + 'Group-Policies' + '</h2></caption> \
	<tr><th>Policy-Name</th><th>Idle-Timeout (Minutes)</th><th>Access-List</th><th>Split-Tunneling</th><th>Routing</th><th>Address-Pool</th></tr>')

def html_tbl_pol_check_hdr():
    print(
        '<table border=1><caption id=' + 'Group-Policies not assigned as Default-Group-Policy to Tunnel-Group' + '><h2>' + 'Group-Policies not assigned as Default-Group-Policy to Tunnel-Group' + '</h2></caption> \
	<tr><th>Policy-Name</th><th>Idle-Timeout (Minutes)</th><th>Access-List</th><th>Split-Tunneling</th><th>Routing</th><th>Address-Pool</th></tr>')

def html_tbl_tgrp_hdr():
    print(
        '<table border=1><caption id=' + 'Anyconnect Tunnel-Groups defined as group-alias or group-lock-value' + '><h2>' + 'Anyconnect Tunnel-Groups defined as group-alias or group-lock-value' + '</h2></caption> \
	<tr><th>Tunnel-Group Name</th><th>Address-Pools (Source)</th><th>Default-Group-Policy</th><th>PreShared-Keys</th></tr>')

def html_tbl_tgrp_check_hdr():
    print(
        '<table border=1><caption id=' + 'Tunnel-Group not defined as group-alias or group-lock-value for anyconnect or has no peer as IPSec' + '><h2>' + 'Tunnel-Group not defined as group-alias or group-lock-value for anyconnect or has no peer as IPSec' + '</h2></caption> \
	<tr><th>Tunnel-Group Name</th><th>Address-Pools (Source)</th><th>Default-Group-Policy</th><th>PreShared-Keys</th></tr>')

# Print settings per policy that is probably not in use
def hmtl_ippools_check_bdy():
    colspan_len = len(ippools_unused)
    print('<table border=1><tr><th colspan='+ str(colspan_len) + '>IP-Pools</th></tr>')
    for ippool in ippools_unused:
        print('<td>' + ippool + '</td>')

# Print object-groups that are probably not in use
def hmtl_obj_grp_check_bdy():
    colspan_len = len(obj_grps_unused)
    if colspan_len == 0:
        print('<table border=1><tr><th colspan='+ str(colspan_len) + '>There are no Object-Groups that need to be checked</th></tr>')
    else:
        print('<table border=1><tr><th colspan='+ str(colspan_len) + '>Object-Groups</th></tr>')
    for obj_grps in obj_grps_unused:
        print('<td>' + obj_grps + '</td>')

# Print objects that are probably not in use
def hmtl_obj_check_bdy():
    colspan_len = len(objects_unused)
    if colspan_len == 0:
        print('<table border=1><tr><th colspan='+ str(colspan_len) + '>There are no Objects that need to be checked</th></tr>')
    else:
        print('<table border=1><tr><th colspan='+ str(colspan_len) + '>Objects</th></tr>')
    for object in objects_unused:
        print('<td>' + object + '</td>')

# Print IPSec Peer as a HTML table column
def html_ipsec_peer_tbl(key):
    for value in ipsec[key]:
        if 'Peer:' in value.split(' '):
            peer = value.split(' ')[1]
            print(peer + '</td>')

#Print IPSec Phase 1 Parameters as a HTML table column
def html_ipsec_phase1_tbl(key):
    tunnelgrp = ''.join([peer.split(' ')[1] for peer in ipsec[key] if 'Peer:' in peer])
    if 'ikev1' == ''.join([phase1.split(' ')[1] for phase1 in tunnel_group[tunnelgrp] if 'Pre-Shared-Key:' in phase1]):
        for ikev1_key in list(ikev1_pols.keys()):
            print('<br/>' + ikev1_key + '<br/>' + '<br/>'.join([str(x) for x in ikev1_pols.get(ikev1_key)]) + '<br/>')
    elif 'ikev2' == ''.join([phase1.split(' ')[1] for phase1 in tunnel_group[tunnelgrp] if 'Pre-Shared-Key:' in phase1]):
        for ikev2_key in list(ikev2_pols.keys()):
            print('<br/>' + ikev2_key + '<br/>' + '<br/>'.join([str(x) for x in ikev2_pols.get(ikev2_key)]) + '<br/>')

# Print all IPsec Parameters
def html_ipsec_phase2_ike_tbl(key):
    sec = False
    bytes = False
    pfs_on = False
    value1 = 'ikev1'
    value2 = 'ikev2'
    if key in ipsec and value1 in ipsec[key]:
        for value in ipsec[key]:
            if 'PFS:' in value.split(' '):
                pfs = value.split(' ', 1)[1]
                pfs_on = True
            elif 'seconds' in value.split(' '):
                life_sec = value
                sec = True
            elif 'kilobytes' in value.split(' '):
                life_byte = value
                bytes = True
            elif 'Phase' in value.split(' ', 2)[0]:
                tset = value.split(' ', 2)[2]
                if tset in transformsets.keys():
                    for offering in str(transformsets[tset][0]).split(' '):
                        ikev1_offerings.add(offering)
            elif 'PFS:' not in value.split(' ') and not pfs_on:
                pfs = 'PFS not set'
        if sec and bytes:
            print('<tr><td>') 
            html_ipsec_peer_tbl(key)
            print('<td>')
            html_ipsec_phase1_tbl(key)
            print('</td>' + '<td>' + 'ikev1' + '<br />' + pfs + '<br />' + '<br />'.join([str(x) for x in ikev1_offerings]) + '<br />' + life_byte + '<br />' + life_sec + '<br />' + '</td></tr>')
        elif sec:
            print('<tr><td>')
            html_ipsec_peer_tbl(key)
            print('<td>')
            html_ipsec_phase1_tbl(key)
            print('</td>' + '<td>' + 'ikev1' + '<br />' + pfs + '<br />' + '<br />'.join([str(x) for x in ikev1_offerings]) + '<br />' + life_sec + '<br />' + '</td></tr>')
        elif bytes:
            print('<tr><td>')
            html_ipsec_peer_tbl(key)
            print('<td>')
            html_ipsec_phase1_tbl(key)
            print('</td>' + '<td>' + 'ikev1' + '<br />' + pfs + '<br />' + '<br />'.join([str(x) for x in ikev1_offerings]) + '<br />' + life_byte + '<br />' + '</td></tr>')
        else:
            print('<tr><td>')
            html_ipsec_peer_tbl(key)
            print('<td>')
            html_ipsec_phase1_tbl(key)
            print('</td>' + '<td>' + 'ikev1' + '<br />' + pfs + '<br />' + '<br />'.join([str(x) for x in ikev1_offerings]) + '<br />' + '</td></tr>')
    elif key in ipsec and value2 in ipsec[key]:
        for value in ipsec[key]:
            if 'PFS:' in value.split(' '):
                pfs = value.split(' ', 1)[1]
                pfs_on = True
            elif 'seconds' in value.split(' '):
                life_sec = value
                sec = True
            elif 'kilobytes' in value.split(' '):
                life_byte = value
                bytes = True
            elif 'Phase' in value.split(' ', 2)[0]:
                p2_prop = value.split(' ', 2)[2]
                if p2_prop in ikev2_proposals.keys():
                    ikev2_offerings = ikev2_proposals[p2_prop]
            elif 'PFS:' not in value.split(' ') and not pfs_on:
                pfs = 'PFS not set'
        if sec and bytes:
            print('<tr><td>')
            html_ipsec_peer_tbl(key)
            print('<td>')
            html_ipsec_phase1_tbl(key)
            print('</td>' + '<td>' + 'ikev2' + '<br />' + pfs + '<br />' + '<br />'.join([str(x) for x in ikev2_proposals]) + '<br/>' + life_byte + '<br/>' + life_sec + '<br/>' + '</td></tr>')
        elif sec:
            print('<tr><td>')
            html_ipsec_peer_tbl(key)
            print('<td>')
            html_ipsec_phase1_tbl(key)
            print('</td>' + '<td>' + 'ikev2' + '<br />' + pfs + '<br />' + '<br />'.join([str(x) for x in ikev2_offerings]) + '<br/>' + life_sec + '<br/>' + '</td></tr>')
        elif bytes:
            print('<tr><td>')
            html_ipsec_peer_tbl(key)
            print('<td>')
            html_ipsec_phase1_tbl(key)
            print('</td>' + '<td>' + 'ikev2' + '<br />' + pfs + '<br />' + '<br />'.join([str(x) for x in ikev2_offerings]) + '<br/>' + life_byte + '<br/>' + '</td></tr>')
        else:
            print('<tr><td>')
            html_ipsec_peer_tbl(key)
            print('<td>')
            html_ipsec_phase1_tbl(key)
            print('</td>' + '<td>' + 'ikev2' + '<br />' + pfs + '<br />' + '<br />'.join([str(x) for x in ikev2_offerings]) + '<br/>' + '</td></tr>')

# Print settings per policy that is probably not in use
def hmtl_policy_check_tbl_bdy():
    for policy_name in grp_pol_check:
        print('<tr><td>' + policy_name + '</td>')
        list = group_policy[policy_name]
        i = 0
        if i == 0:
            i += 1
            if 'Idle' in ''.join([idle.split(' ')[0] for idle in group_policy[policy_name] if 'Idle Timeout:' in idle]):
                print('<td>' + ''.join([idle.split(' ')[2] for idle in group_policy[policy_name] if 'Idle Timeout:' in idle]) + '</td>')
                list.remove(''.join([idle for idle in group_policy[policy_name] if 'Idle Timeout:' in idle]))
            else:
                print('<td>' + 'Not defined' + '</td>')
        if i == 1:
            i += 1
            if 'Access-List:' in ''.join([x.split(' ')[0] for x in group_policy[policy_name] if 'Access-List:' in x]):
                print('<td>' + ''.join([x.split(' ')[1] for x in group_policy[policy_name] if 'Access-List:' in x]) + '</td>')
            else:
                print('<td>' + 'Not defined' + '</td>')
        if i == 2:
            i += 1
            if 'Split-Tunneling:' in ''.join([x.split(' ')[0] for x in group_policy[policy_name] if 'Split-Tunneling:' in x]):
                print('<td>' + ''.join([x.split(' ')[1] for x in group_policy[policy_name] if 'Split-Tunneling:' in x]) + '</td>')
            else:
                print('<td>' + 'Not defined' + '</td>')
        if i == 3:
            i += 1
            if 'Split_Tunnel_Dst:' in ''.join([route.split(' ')[0] for route in group_policy[policy_name] if 'Split_Tunnel_Dst:' in route]):
                print('<td>' + ''.join([route.split(' ')[1] for route in group_policy[policy_name] if 'Split_Tunnel_Dst:' in route]) + '</td>')
            else:
                print('<td>' + 'Not defined' + '</td>')
        if i == 4:
            i += 1
            if 'Address-Pool:' in ''.join([addr.split(' ')[0] for addr in group_policy[policy_name] if 'Address-Pool:' in addr]):
                print('<td>' + ''.join([addr.split(' ')[1] for addr in group_policy[policy_name] if 'Address-Pool:' in addr]) + '</td>')
            else:
                print('<td>' + 'Not defined' + '</td>')


# Print settings per policy that is probably in use
def hmtl_tbl_tgrp_bdy():
    for tgr in tunnel_group.keys():
        if tgr in peers_set:
            pass
        else:
            if tgr in used_tgroups_remote:
                i = 5
                if len(''.join([x for x in tunnel_group[tgr] if 'type: remote-access' in x])) > 0:
                    i = 0
                if i == 0:
                    i += 1
                    print('<tr><td>' + tgr + '</td>')
                if i == 1:
                    i += 1
                    if [pool.split(' ')[0] for pool in tunnel_group[tgr] if 'Address Pool:' in pool]:
                        print('<td>' + '<br/>'.join([pool.split(' ')[2] for pool in tunnel_group[tgr] if 'Address Pool:' in pool]) + '</td>')
                    else:
                        print('<td>' + 'Not defined' + '</td>')
                if i == 2:
                    i += 1
                    if [dftl_pol.split(' ')[0] for dftl_pol in tunnel_group[tgr] if 'Default Group:' in dftl_pol]:
                        print('<td>' + ''.join([dftl_pol.split(' ')[2] for dftl_pol in tunnel_group[tgr] if 'Default Group:' in dftl_pol]) + '</td>')
                    else:
                        print('<td>' + 'Not defined' + '</td>')
                if i == 3:
                    print('<td>' + 'Not defined' + '</td>')
                else:
                    pass
            elif tgr in used_tgroups and [x for x in tunnel_group[tgr] if 'type: ipsec-l2l' in x]:
                i = 5
                if len(''.join([x for x in tunnel_group[tgr] if 'type: ipsec-l2l' in x])) > 0:
                    i = 0
                if i == 0:
                    i += 1
                    print('<tr><td>' + tgr + '</td>')
                if i == 1:
                    i += 1
                    print('<td>' + 'Not defined' + '</td>')
                if i == 2:
                    i += 1
                    print('<td>' + 'Not defined' + '</td>')
                if i == 3:
                    if [dftl_pol.split(' ')[1] for dftl_pol in tunnel_group[tgr] if 'Pre-Shared-Key:' in dftl_pol]:
                        print('<td>' + ''.join([dftl_pol.split(' ')[1] for dftl_pol in tunnel_group[tgr] if 'Pre-Shared-Key:' in dftl_pol]) + '</td>')
                    else:
                        print('<td>' + 'Not defined' + '</td>')
                else:
                    pass
            else:
                pass


# Print settings per policy that is probably not in use
def hmtl_tbl_tgr_check_bdy():
    for tgr in tunnel_group.keys():
        if tgr in unused_tgroups and [x for x in tunnel_group[tgr] if 'type: remote-access' in x]:
            i = 5
            if len(''.join([x for x in tunnel_group[tgr] if 'type: remote-access' in x])) > 0:
                i = 0
            if i == 0:
                i += 1
                print('<tr><td>' + tgr + '</td>')
            if i == 1:
                i += 1
                if [pool.split(' ')[0] for pool in tunnel_group[tgr] if 'Address Pool:' in pool]:
                    print('<td>' + '<br/>'.join([pool.split(' ')[2] for pool in tunnel_group[tgr] if 'Address Pool:' in pool]) + '</td>')
                else:
                    print('<td>' + 'Not defined' + '</td>')
            if i == 2:
                i += 1
                if [dftl_pol.split(' ')[0] for dftl_pol in tunnel_group[tgr] if 'Default Group:' in dftl_pol]:
                    print('<td>' + ''.join([dftl_pol.split(' ')[2] for dftl_pol in tunnel_group[tgr] if 'Default Group:' in dftl_pol]) + '</td>')
                else:
                    print('<td>' + 'Not defined' + '</td>')
            if i == 3:
                print('<td>' + 'Not defined' + '</td>')
            else:
                pass
        elif tgr in unused_tgroups and [x for x in tunnel_group[tgr] if 'type: ipsec-l2l' in x]:
            i = 5
            if len(''.join([x for x in tunnel_group[tgr] if 'type: ipsec-l2l' in x])) > 0:
                i = 0
            if i == 0:
                i += 1
                print('<tr><td>' + tgr + '</td>')
            if i == 1:
                i += 1
                print('<td>' + 'Not defined' + '</td>')
            if i == 2:
                i += 1
                print('<td>' + 'Not defined' + '</td>')
            if i == 3:
                if [dftl_pol.split(' ')[1] for dftl_pol in tunnel_group[tgr] if 'Pre-Shared-Key:' in dftl_pol]:
                    print('<td>' + ''.join([dftl_pol.split(' ')[1] for dftl_pol in tunnel_group[tgr] if 'Pre-Shared-Key:' in dftl_pol]) + '</td>')
                else:
                    print('<td>' + 'Not defined' + '</td>')
            else:
                pass
        else:
            pass

def html_tbl_tgp_check_bdy(curacl, cur_route):
    colspan_len = len(pol_acl_check_set)
    print('<table border=1><tr><th>ACL</th><th colspan='+ str(colspan_len) + '>Group-Policies</th></tr><td>' + curacl + '</td>')
    for route in cur_route.split('/'):
        print('<td>' + route + '</td>')

# Print Anyconnect Table Header
def html_webvpn_hdr():
    if 'anyconnect enabled' in webvpn_set:
        for item in webvpn_set:
            if 'list_drop_down enabled' in item:
                list_drop_down = True
            elif 'list_drop_down enabled' not in item:
                list_drop_down = False
        if len(webvpn_ints) > 0 and list_drop_down:
            webvpn_joined = '/'.join(webvpn_ints)
            print('<table border=1><caption id=' + 'Anyconnect is enabled in Interface ' + webvpn_joined + ' and Tunnel Group Drop Down Menue is enabled' + '><h2>' + 'Anyconnect is enabled in Interface ' + webvpn_joined + ' and Tunnel Group Drop Down Menue is enabled' + '</h2></caption>')
        elif len(webvpn_ints) > 0 and not list_drop_down:
            webvpn_joined = '/'.join(webvpn_ints)
            print('<table border=1><caption id=' + 'Anyconnect is enabled in Interface ' + webvpn_joined + ' and Tunnel Group Drop Down Menue is disabled' + '><h2>' + 'Anyconnect is enabled in Interface ' + webvpn_joined + ' and Tunnel Group Drop Down Menue is disabled' + '</h2></caption>')
    else:
        print('<table border=1><caption id=' + 'Anyconnect is disabled' + '><h2>' + 'Anyconnect is disabled' + '</h2></caption>')

# Print settings per policy that is actually used
def hmtl_policy_tbl_bdy():
    for policy_name in grp_pol_used:
        print('<tr><td>' + policy_name + '</td>')
        list = group_policy[policy_name]
        i = 0
        if i == 0:
            i += 1
            if 'Idle' in ''.join([idle.split(' ')[0] for idle in group_policy[policy_name] if 'Idle Timeout:' in idle]):
                print('<td>' + ''.join([idle.split(' ')[2] for idle in group_policy[policy_name] if 'Idle Timeout:' in idle]) + '</td>')
                list.remove(''.join([idle for idle in group_policy[policy_name] if 'Idle Timeout:' in idle]))
            else:
                print('<td>' + 'Not defined' + '</td>')
        if i == 1:
            i += 1
            if 'Access-List:' in ''.join([x.split(' ')[0] for x in group_policy[policy_name] if 'Access-List:' in x]):
                print('<td>' + ''.join([x.split(' ')[1] for x in group_policy[policy_name] if 'Access-List:' in x]) + '</td>')
            else:
                print('<td>' + 'Not defined' + '</td>')
        if i == 2:
            i += 1
            if 'Split-Tunneling:' in ''.join([x.split(' ')[0] for x in group_policy[policy_name] if 'Split-Tunneling:' in x]):
                print('<td>' + ''.join([x.split(' ')[1] for x in group_policy[policy_name] if 'Split-Tunneling:' in x]) + '</td>')
            else:
                print('<td>' + 'Not defined' + '</td>')
        if i == 3:
            i += 1
            if 'Split_Tunnel_Dst:' in ''.join([route.split(' ')[0] for route in group_policy[policy_name] if 'Split_Tunnel_Dst:' in route]):
                print('<td>' + ''.join([route.split(' ')[1] for route in group_policy[policy_name] if 'Split_Tunnel_Dst:' in route]) + '</td>')
            else:
                print('<td>' + 'Not defined' + '</td>')
        if i == 4:
            i += 1
            if 'Address-Pool:' in ''.join([addr.split(' ')[0] for addr in group_policy[policy_name] if 'Address-Pool:' in addr]):
                print('<td>' + ''.join([addr.split(' ')[1] for addr in group_policy[policy_name] if 'Address-Pool:' in addr]) + '</td>')
            else:
                print('<td>' + 'Not defined' + '</td>')

###################################################### Processing Functions ######################################################
# If new object is found, add it to the group and set the current names
def newobj(obj, key):
    global curobj, curname
    curobj = obj
    curname = key
    curobj[curname] = []                                                        

def newobj_name(obj, key):
    global curobj_name, curname_name
    curobj_name = obj
    curname_name = key
    curobj_name[curname_name] = []                                               


# Append keys and multiple values to a key in dictionary
def add_values(dict, key, values):
    """Append multiple values to a key in the given dictionary"""
    if key in dict:
        # Key exists in dict. Check if type of value of key is list or not
        if not isinstance(dict[key], list):
            # If type is not list then make it list
            dict[key] = [dict[key]]
        # Append the value in list
        dict[key].append(values)
    else:
        # As key is not in dict,
        # so, add key-value pair
        dict[key] = [values]
    return dict

# Create CIDR from subnet masks
def cidr(ip, mask):
    if "255.255.255.255" in mask:
        return ip + "/32"
    elif "255.255.255.254" in mask:
        return ip + "/31"
    elif "255.255.255.252" in mask:
        return ip + "/30"
    elif "255.255.255.248" in mask:
        return ip + "/29"
    elif "255.255.255.240" in mask:
        return ip + "/28"
    elif "255.255.255.224" in mask:
        return ip + "/27"
    elif "255.255.255.192" in mask:
        return ip + "/26"
    elif "255.255.255.128" in mask:
        return ip + "/25"
    elif "255.255.255.0" in mask:
        return ip + "/24"
    elif "255.255.254.0" in mask:
        return ip + "/23"
    elif "255.255.252.0" in mask:
        return ip + "/22"
    elif "255.255.248.0" in mask:
        return ip + "/21"
    elif "255.255.240.0" in mask:
        return ip + "/20"
    elif "255.255.224.0" in mask:
        return ip + "/19"
    elif "255.255.192.0" in mask:
        return ip + "/18"
    elif "255.255.128.0" in mask:
        return ip + "/17"
    elif "255.255.0.0" in mask:
        return ip + "/16"
    elif "255.254.0.0" in mask:
        return ip + "/15"
    elif "255.252.0.0" in mask:
        return ip + "/14"
    elif "255.248.0.0" in mask:
        return ip + "/13"
    elif "255.240.0.0" in mask:
        return ip + "/12"
    elif "255.224.0.0" in mask:
        return ip + "/11"
    elif "255.192.0.0" in mask:
        return ip + "/10"
    elif "255.128.0.0" in mask:
        return ip + "/9"
    elif "255.0.0.0" in mask:
        return ip + "/8"
    elif "254.0.0.0" in mask:
        return ip + "/7"
    elif "252.0.0.0" in mask:
        return ip + "/6"
    elif "248.0.0.0" in mask:
        return ip + "/5"
    elif "240.0.0.0" in mask:
        return ip + "/4"
    elif "224.0.0.0" in mask:
        return ip + "/3"
    elif "192.0.0.0" in mask:
        return ip + "/2"
    elif "128.0.0.0" in mask:
        return ip + "/1"
    elif "0.0.0.0" in mask and ip == '0.0.0.0':
        return 'any'
    elif "0.0.0.0" in mask:
        return ip + "/0"
    else:
        return ""

# Iterate through all objects in netgrp or srvgrp
def unfold_folded(objarr):
    for obj in objarr.keys():
        unfold_folded_rec(objarr[obj], objarr)

# Unfold all included objects to rearrange them like the unfold() function does, but don't add IP/Subnet
def unfold_folded_rec(obj, objarr, index=0):
    for i in range(index, len(obj)):
        item = obj[i]
        # If object-group is found, add obj-grp name a number of times equal to length of list
        if "object-group" in str(item):
            for j in objarr[item.split()[1]]:
                obj.append(item.split()[1])
            # Remove the item with object-group once
            del obj[i]
            # and dive into the new updated object. We are passing the index we are currently on
            unfold_folded_rec(obj, objarr, i)
        elif 'net-object' in str(item):
            # if net-object is in the group add it's name
            obj.append(item.split()[1])
            del obj[i]
            unfold_folded_rec(obj, objarr, i)

# Iterate through all objects in netgrp or srvgrp
def unfold(objarr):
    for obj in objarr:
        unfold_rec(objarr[obj], objarr)

# Unfold all included objects
def unfold_rec(obj, objarr, index=0):
    # We are starting with the index from the previous iteration
    for i in range(index, len(obj)):
        item = obj[i]
        # If object-group is found, recurse through the object-groups
        if "object-group" in str(item):
            # Add the content of the object-group item by item
            for j in objarr[item.split()[1]]:
                obj.append(j)
            # Remove the item with object-group
            del obj[i]
            # and dive into the new updated object. We are passing the index we are currently on
            unfold_rec(obj, objarr, i)
        elif 'net-object' in str(item):
            # if net-object is in the group get its address from netobj
            obj.append(network_objects[item.split()[1]])
            del obj[i]
            unfold_rec(obj, objarr, i)

# Print Any connect user setting per User
def hmtl_webvpn_tbl_bdy(user_name):
    if user_name in anyconnect_user:
        print('<tr><td>' + user_name + '</td>')
        if ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]) in anyconnect_user[user_name] and ''.join([acl for acl in anyconnect_user[user_name] if 'Access-List:' in acl]) in anyconnect_user[user_name]:
            grp_pol_key = ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]).split(' ')[1]
            pool_name = ''.join([pool.split(' ')[1] for pool in group_policy[grp_pol_key] if 'Address-Pool:' in pool])
            usr_pool = ''.join(local_ip_pools[pool_name])
            grp_lock = ''.join([grp_lock.split(' ')[1] for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock])
            print('<td>' + 'Only Group ' + grp_lock + ' available' '</td>')
            print('<td>' + usr_pool + '</td>')
            print('<td>' + ''.join([x.split(' ')[1] for x in group_policy[grp_pol_key] if 'Split-Tunneling:' in x]) + '</td>')
            usr_split_tnl = ''.join([split.split(' ')[1] for split in group_policy[grp_pol_key] if 'Split_Tunnel_Dst:' in split])
            print('<td>' + usr_split_tnl + '</td>')
            usr_acl = ''.join([acl.split(' ')[1] for acl in anyconnect_user[user_name] if 'Access-List:' in acl])
            print('<td>' + usr_acl + '</td>')
        elif ''.join([acl for acl in anyconnect_user[user_name] if 'Access-List:' in acl]) in anyconnect_user[user_name] and ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]) not in anyconnect_user[user_name]:
            print('<td>' + 'All Tunnel-Groups Available' + '</td>')
            print('<td>' + 'IP Pool dependant on chosen Group' + '</td>')
            print('<td>' + 'Split Tunneling dependant on chosen Group' + '</td>')
            print('<td>' + 'Traffic Routing dependant on chosen Group' + '</td>')
            usr_acl = ''.join([acl.split(' ')[1] for acl in anyconnect_user[user_name] if 'Access-List:' in acl])
            print('<td>' + usr_acl + '</td>')
        elif ''.join([acl for acl in anyconnect_user[user_name] if 'Access-List:' in acl]) not in anyconnect_user[user_name] and ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]) in anyconnect_user[user_name]:
            grp_lock = ''.join([grp_lock.split(' ')[1] for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock])
            grp_pol_key = ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]).split(' ')[1]
            pool_name = ''.join([pool.split(' ')[1] for pool in group_policy[grp_pol_key] if 'Address-Pool:' in pool])
            usr_pool = ''.join(local_ip_pools[pool_name])
            print('<td>' + 'Only Group ' + grp_lock + ' available' '</td>')
            print('<td>' + usr_pool + '</td>')
            print('<td>' + ''.join([x.split(' ')[1] for x in group_policy[grp_pol_key] if 'Split-Tunneling:' in x]) + '</td>')
            usr_split_tnl = ''.join([split.split(' ')[1] for split in group_policy[grp_pol_key] if 'Split_Tunnel_Dst:' in split])
            print('<td>' + usr_split_tnl + '</td>')
            print('<td>' + 'No Access-List Configured' + '</td>')
        else:
            print('<td>' + 'All Tunnel-Groups Available' + '</td>')
            print('<td>' + 'IP Pool dependant on chosen Group' + '</td>')
            print('<td>' + 'Split Tunneling dependant on chosen Group' + '</td>')
            print('<td>' + 'Traffic Routing dependant on chosen Group' + '</td>')
            print('<td>' + 'No Access-List Configured' + '</td>')

###################################################### Classes ######################################################
class IPSEC:
    'Class for IPSec rules'

    # access-list myacl remark My best rule
    re_acl_rem = re.compile('^\s*access-list\s+\S+\s+remark\s+(?P<acl_rem>.*$)', re.IGNORECASE)

    # All subsequent remarks are concatenated in this persistent variable
    remark = ''

    def __init__(self, lnum, line):
        self.lnum = lnum
        self.line = line
        self.name = ''
        self.src = []
        self.src_name = []
        self.dst = []
        self.dst_name = []
        self.srv = []
        self.srv_name = []
        self.proto = ''
        self.action = ''
        self.rem = ''
        self.cleanup()
        self.parse()

    # Simple clean-up
    def cleanup(self):
        self.line = re.sub(r'\s+log$|\s+log\s+.*$', '', self.line)
        self.line = re.sub(r'\bany\b|\bany4\b', '0.0.0.0 0.0.0.0', self.line)

    def parse(self):
        if IPSEC.re_acl_rem.search(self.line):
            # Found Remarked ACL
            # Was the prev rule also remarked? If yes, add <br>
            if IPSEC.remark: IPSEC.remark += '<br />'
            IPSEC.remark += IPSEC.re_acl_rem.search(line).group('acl_rem').strip()
        else:
            # Clean the remarks
            self.rem = IPSEC.remark
            IPSEC.remark = ''
            arr = self.line.split()
            # ACL name
            self.name = arr[1]
            # Permit or deny
            self.action = arr[3]
            del arr[0:4]
            if 'object-group' in arr[0]:
                self.srv = service_groups[arr[1]]
                self.srv_name = service_groups_used[arr[1]]
                del arr[0:2]
            else:
                self.proto = arr[0]
                del arr[0]
            # Source
            if 'object-group' in arr[0]:
                self.src = network_groups[arr[1]]
                self.src_name = network_groups_folded[arr[1]]
            elif 'object' in arr[0]:
                self.src = [network_objects[arr[1]]]
                self.src_name = [arr[1]]
            elif 'host' in arr[0]:
                self.src = [cidr(arr[1], '255.255.255.255')]
            else:
                self.src = [cidr(arr[0], arr[1])]
            del arr[0:2]
            # Source ports are not supported
            if "range" in arr[0]: del arr[0:3]
            if "eq" in arr[0] or "lt" in arr[0] or "gt" in arr[0] or "neq" in arr[0]:
                del arr[0:2]
            # Destination
            if 'object-group' in arr[0]:
                self.dst = network_groups[arr[1]]
                self.dst_name = network_groups_folded[arr[1]]
            elif 'object' in arr[0]:
                self.dst = [network_objects[arr[1]]]
                self.dst_name = [arr[1]]
            elif 'host' in arr[0]:
                self.dst = [cidr(arr[1], '255.255.255.255')]
            else:
                self.dst = [cidr(arr[0], arr[1])]
            del arr[0:2]
            # Services
            if len(arr) > 0:
                if 'object-group' in arr[0]:
                    self.srv = service_groups[arr[1]]
                    self.srv_name = [arr[1]]
                else:
                    self.srv = [self.proto + ':' + ' '.join(arr[:])]
            elif not self.srv:
                self.srv = [self.proto]
      
    # Highlight the action in green or red
    def html_color_action(self, act):
        if 'permit' in act:
            return '<span class=permit>' + act + '</span>'
        else:
            return '<span class=deny>' + act + '</span>'
    
     # Print rule as an HTML table row
    def html(self):
        if not Rule.remark:
            # Are there accumulated comments?
            if self.rem:
                print('<tr><td colspan=5>' + self.rem + '</td></tr>')
            print(
                '<tr><td>' + str(self.lnum) + '</td>' + '<td>' + (str(self.line)).split(' extended ', 1)[1] + '</td>' 
                + self.html_obj(self.src_name) + self.html_obj(self.src) + self.html_obj(self.dst_name) + self.html_obj(self.dst)
                + self.html_obj(self.srv_name) + self.html_obj(self.srv) + '<td>' + self.html_color_action(self.action) + '</td></tr>')

    # Print out the content of the object-group with <br /> in between
    def html_obj(self, obj):
        return '<td>' + '<br />'.join([str(x) for x in obj]) + '</td>'

class Rule:
    'Class for an ACL rule'
    # access-list myacl remark My best rule
    re_acl_rem = re.compile('^\s*access-list\s+\S+\s+remark\s+(?P<acl_rem>.*$)', re.IGNORECASE)

    # All subsequent remarks are concatenated in this persistent variable
    remark = ''

    def __init__(self, lnum, line):
        self.lnum = lnum
        self.line = line
        self.name = ''
        self.src = []
        self.src_name = []
        self.dst = []
        self.dst_name = []
        self.srv = []
        self.srv_name = []
        self.proto = ''
        self.action = ''
        self.rem = ''
        self.cleanup()
        self.parse()

    # Simple clean-up
    def cleanup(self):
        self.line = re.sub(r'\s+log$|\s+log\s+.*$', '', self.line)
        self.line = re.sub(r'\bany\b|\bany4\b', '0.0.0.0 0.0.0.0', self.line)

    def parse(self):
        if Rule.re_acl_rem.search(self.line):
            # Found Remarked ACL
            # Was the prev rule also remarked? If yes, add <br>
            if Rule.remark: Rule.remark += '<br />'
            Rule.remark += Rule.re_acl_rem.search(line).group('acl_rem').strip()
        else:
            # Clean the remarks
            self.rem = Rule.remark
            Rule.remark = ''
            arr = self.line.split()
            # ACL name
            self.name = arr[1]
            # Permit or deny
            self.action = arr[3]
            del arr[0:4]
            if 'object-group' in arr[0]:
                self.srv = service_groups[arr[1]]
                self.srv_name = service_groups_used[arr[1]]
                del arr[0:2]
            else:
                self.proto = arr[0]
                del arr[0]
            # Source
            if 'object-group' in arr[0]:
                self.src = network_groups[arr[1]]
                self.src_name = network_groups_folded[arr[1]]
            elif 'object' in arr[0]:
                self.src = [network_objects[arr[1]]]
                self.src_name = [arr[1]]
            elif 'host' in arr[0]:
                self.src = [cidr(arr[1], '255.255.255.255')]
            else:
                self.src = [cidr(arr[0], arr[1])]
            del arr[0:2]
            # Source ports are not supported
            if "range" in arr[0]: del arr[0:3]
            if "eq" in arr[0] or "lt" in arr[0] or "gt" in arr[0] or "neq" in arr[0]:
                del arr[0:2]
            # Destination
            if 'object-group' in arr[0]:
                self.dst = network_groups[arr[1]]
                self.dst_name = network_groups_folded[arr[1]]
            elif 'object' in arr[0]:
                self.dst = [network_objects[arr[1]]]
                self.dst_name = [arr[1]]
            elif 'host' in arr[0]:
                self.dst = [cidr(arr[1], '255.255.255.255')]
            else:
                self.dst = [cidr(arr[0], arr[1])]
            del arr[0:2]
            # Services
            if len(arr) > 0:
                if 'object-group' in arr[0]:
                    self.srv = service_groups[arr[1]]
                    self.srv_name = service_groups_used[arr[1]]
                else:
                    self.srv = [self.proto + ':' + ' '.join(arr[:])]
            elif not self.srv:
                self.srv = [self.proto]

    # Print rule as an HTML table row
    def html(self):
        if not Rule.remark:
            # Are there accumulated comments?
            if self.rem:
                print('<tr><td colspan=5>' + self.rem + '</td></tr>')
            print(
                '<tr><td>' + str(self.lnum) + '</td>' + '<td>' + (str(self.line)).split(' extended ', 1)[1] + '</td>' 
                + self.html_net_names(self.src_name) + self.html_obj(self.src) + self.html_obj(self.dst_name) + self.html_obj(self.dst)
                + self.html_obj(self.srv_name) + self.html_obj(self.srv) + '<td>' + self.html_color_action(self.action) + '</td></tr>')


    def html_filter(self):
        if not Rule.remark:
            # Are there accumulated comments?
            if self.rem:
                print('<tr><td colspan=5>' + self.rem + '</td></tr>')
            print(
                '<tr><td>' + str(self.lnum) + '</td>' + '<td>' + str(self.line) + '</td>' 
                + self.html_net_names(self.src_name) + self.html_obj(self.src) + self.html_obj(self.dst_name) + self.html_obj(self.dst)
                + self.html_obj(self.srv_name) + self.html_obj(self.srv) + '<td>' + self.html_color_action(self.action) + '</td></tr>')


    def html_check(self):
        if not Rule.remark:
            # Are there accumulated comments?
            if self.rem:
                print('<tr><td colspan=5>' + self.rem + '</td></tr>')
            print(
                '<tr><td>' + str(self.lnum) + '</td>' + '<td>' + str(self.line) + '</td>' 
                + self.html_net_names(self.src_name) + self.html_obj(self.src) + self.html_obj(self.dst_name) + self.html_obj(self.dst)
                + self.html_obj(self.srv_name) + self.html_obj(self.srv) + '<td>' + self.html_color_action(self.action) + '</td></tr>')


    # Highlight the action in green or red
    def html_color_action(self, act):
        if 'permit' in act:
            return '<span class=permit>' + act + '</span>'
        else:
            return '<span class=deny>' + act + '</span>'

    # Print out the content of the object-group with <br /> in between
    def html_obj(self, obj):
        return '<td>' + '<br />'.join([str(x) for x in obj]) + '</td>'

    # Print out the object-group network names a number of times equal to the content of the object-group with <br /> in between
    def html_net_names(self, obj):
        return '<td>' + '<br />'.join([str(x) for x in obj]) + '</td>'               


######################################  LET THE PARSING BEGIN  ######################################
# Create a variable for the file name
here = os.path.dirname(os.path.abspath(__file__))
config_txt = os.path.join(here, 'config.txt')
acl_txt = os.path.join(here, 'acl.txt')

# Open the file
config_infile = open(config_txt, 'r')
config_lines = config_infile.readlines()

# lines is a list with each item representing a line of the file
for line in config_lines:
    re_match_peering_int = re_peering_int.search(line)
    # Only care for lines starting with "access-group"
    if line.startswith(AG):
        # Create Regex Groups acl_name and acl_int für real ACLs (and not VPN stuff)
        re_match_aclgrp = re_aclgrp.match(line)
        add_values(access_grps_n_interf, re_match_aclgrp.group('acl_name').strip(), re_match_aclgrp.group('acl_int').strip())
        acls_used_set.add(re_match_aclgrp.group('acl_name').strip())
    elif re_match_peering_int:
        add_values(crypto_int, re_match_peering_int.group('crypto_map').strip(), re_match_peering_int.group('interface').strip())

# Parse config and fill dictionaries
for line in config_lines:
    if re_ippool.match(line):
        ippools_unused.add(re_ippool.match(line).group('ippool').strip())
    if re_objnet.match(line):
        obj_net = True
        # ignore Nat and who knows what else
        if re_objnet.match(line).group('obj_name').strip() in network_objects:
            pass
        else:
            newobj(network_objects, re_objnet.match(line).group('obj_name').strip())
            newobj_name(network_objects_used, re_objnet.match(line).group('obj_name').strip())
    elif re_subnet.match(line):
        re_match_subnet = re_subnet.match(line)
        curobj[curname] = (cidr(re_match_subnet.group('ip'), re_match_subnet.group('mask').strip()))
        curobj_name[curname_name] = ('-')
    elif re_host.match(line):
        re_match_host = re_host.match(line)
        curobj[curname] = (re_match_host.group('ip') + "/32")
        curobj_name[curname_name] = ('-')
    elif re_fqdn.match(line) and obj_net:
        re_match_fqdn = re_fqdn.match(line)
        curobj[curname] = 'fqdn: ' + re_match_fqdn.group('fqdn').strip()
        curobj_name[curname_name] = ('-')
    elif re_netgrp.match(line):
        if re_netgrp.match(line).group('net_grp').strip() in network_groups:
            pass
        else:
            newobj(network_groups, re_netgrp.match(line).group('net_grp').strip())
            newobj_name(network_groups_folded, re_netgrp.match(line).group('net_grp').strip())
    elif re_netobj_host.match(line):
        add_values(curobj, curname, cidr(re_netobj_host.match(line).group('ip'), '255.255.255.255'))
        add_values(curobj_name, curname_name, '-')
    elif re_netobj_obj.match(line):
        add_values(curobj, curname, 'net-object ' + re_netobj_obj.match(line).group('obj_name').strip())
        add_values(curobj_name, curname_name, 'net-object ' + re_netobj_obj.match(line).group('obj_name').strip())
    elif re_netobj.match(line):
        add_values(curobj, curname, cidr(re_netobj.match(line).group('ip'), re_netobj.match(line).group('mask').strip()))
        add_values(curobj_name, curname_name, '-')
    elif re_srvgrp.match(line):
        if re_srvgrp.match(line).group('srv_grp').strip() in service_groups:
            pass
        else:
            newobj(service_groups, re_srvgrp.match(line).group('srv_grp').strip())
            newobj_name(service_groups_used, re_srvgrp.match(line).group('srv_grp').strip())
    elif re_grpobj.match(line):
        add_values(curobj, curname, 'object-group ' + re_grpobj.match(line).group('obj_name').strip())
        add_values(curobj_name, curname_name, 'object-group ' + re_grpobj.match(line).group('obj_name').strip())
    elif re_srvobj.match(line):
        add_values(curobj, curname, re_srvobj.match(line).group('proto') + ':' + re_srvobj.match(line).group('service').strip())
        add_values(curobj_name, curname_name, '-')
    elif re_srvgrp_proto.match(line):
        if re_srvgrp_proto.match(line).group('srv_grp').strip() in service_groups:
            pass
        else:
            newobj(service_groups, re_srvgrp_proto.match(line).group('srv_grp').strip())
            newobj_name(service_groups_used, re_srvgrp_proto.match(line).group('srv_grp').strip())
            curproto = re_srvgrp_proto.match(line).group('proto').strip()
    elif re_portobj.match(line):
        add_values(curobj, curname, curproto + ':' + re_portobj.match(line).group('service').strip())
        add_values(curobj_name, curname_name, '-')
    elif re_srvobj_ip.match(line):
        add_values(curobj, curname, re_srvobj_ip.match(line).group('proto').strip())
        add_values(curobj_name, curname_name, '-')
    elif re_isacl.match(line):
        re_match_aclname = re_aclname.match(line)
        acls_all_set.add(re_match_aclname.group('acl_name').strip())
        acl_check.add(re_match_aclname.group('acl_name').strip())
    elif line.startswith('crypto map'):
        obj_net = False
        if line.startswith('crypto map'):
            re_match_pfs = re_pfs.search(line)
            re_match_pfs_wo = re_pfs_wo.search(line)
            re_match_peer = re_peer.search(line)
            re_match_sec_ass_sec = re_sec_ass_sec.search(line)
            re_match_sec_ass_kil = re_sec_ass_kil.search(line)
            re_match_proposal = re_proposal.search(line)
            if re_ipsec.search(line):
                re_match_ipsec = re_ipsec.search(line)
                cur_ipsec = re_match_ipsec.group('ipsec_name').strip()
                cur_num = re_match_ipsec.group('map_number').strip()
                add_values(ipsec, re_match_ipsec.group('ipsec_name').strip(), re_match_ipsec.group('crypto_map').strip())
                add_values(ipsec, re_match_ipsec.group('ipsec_name').strip(), 'Map Number: ' + re_match_ipsec.group('map_number').strip())
                add_values(ipsec_dict, re_match_ipsec.group('ipsec_name').strip(), re_match_ipsec.group('crypto_map').strip())
            elif re_match_pfs_wo:
                add_values(ipsec, cur_ipsec, 'PFS: Default DH Group')
            elif re_match_pfs and cur_num == re_match_pfs.group('map_number').strip():
                add_values(ipsec, cur_ipsec, 'PFS: DH ' + re_match_pfs.group('dh_group').strip())
            elif re_match_peer and cur_num == re_match_peer.group('map_number').strip():
                add_values(ipsec, cur_ipsec, 'Peer: ' + re_match_peer.group('peer_ip').strip())
                peers_set.add(re_match_peer.group('peer_ip').strip())
            elif re_match_proposal and cur_num == re_match_proposal.group('map_number').strip():
                add_values(ipsec, cur_ipsec, re_match_proposal.group('ikev').strip())
                add_values(ipsec, cur_ipsec, 'Phase 2: ' + re_match_proposal.group('proposal_grp').strip())
            elif re_match_sec_ass_sec and cur_num == re_match_sec_ass_sec.group('map_number').strip():
                add_values(ipsec, cur_ipsec, 'lifetime ' + re_match_sec_ass_sec.group('number').strip() + ' ' + re_match_sec_ass_sec.group('seconds').strip())
            elif re_match_sec_ass_kil and cur_num == re_match_sec_ass_kil.group('map_number').strip():
                add_values(ipsec, cur_ipsec, 'lifetime ' + re_match_sec_ass_kil.group('number').strip() + ' ' + re_match_sec_ass_kil.group('kilobytes').strip())
            elif re_match_cnumber.match(line):
                    if re_peering_int.match(line):
                        pass
                    elif re_match_dynmapnumber.match(line):
                        pass
                    else:
                        crypto_map_nr_unused.add(re_match_cnumber.match(line).group('map_number').strip())
    elif line.startswith('crypto ipsec ikev1 transform-set'):
        re_match_ikev1_prop = re_ikev1_prop.search(line)
        cur_transformset = re_match_ikev1_prop.group('Phase_2_name')
        add_values(transformsets, cur_transformset, re_match_ikev1_prop.group('proposals').strip())
    elif line.startswith('crypto ipsec ikev2 ipsec-proposal'):
        start_ikev2_prop = True
        start_ikev2_pol = False
        start_ikev1_pol = False
        re_match_ikev2_prop = re_ikev2_prop.match(line)
        cur_ipsec_proposal = re_match_ikev2_prop.group('Phase_2_name').strip()
    elif start_ikev2_prop and re_ikev2_encr_prop.match(line):
        re_match_ikev2_encr_prop = re_ikev2_encr_prop.match(line)
        add_values(ikev2_proposals, cur_ipsec_proposal, 'encryption: ' + re_match_ikev2_encr_prop.group('ikev2_encryption').strip())
    elif start_ikev2_prop and re_ikev2_inte_prop.match(line):
        re_match_ikev2_inte_prop = re_ikev2_inte_prop.match(line)
        add_values(ikev2_proposals, cur_ipsec_proposal, 'integrity: ' + re_match_ikev2_inte_prop.group('ikev2_integrity').strip())
    elif line.startswith('crypto ikev1 policy'):
        start_ikev1_pol = True
        start_ikev2_prop = False
        start_ikev2_pol = False
        re_match_ikev1_pol = re_ikev1_pol.match(line)
        cur_ike_pol = 'ikev1 policy ' + re_match_ikev1_pol.group('priority').strip()
    elif start_ikev1_pol and re_ikev1_auth.match(line):
        re_match_ikev1_auth = re_ikev1_auth.match(line)
        add_values(ikev1_pols, cur_ike_pol, 'authentication: ' + re_match_ikev1_auth.group('auth').strip())
    elif start_ikev1_pol and re_ikev1_enc.match(line):
        re_match_ikev1_enc = re_ikev1_enc.match(line)
        add_values(ikev1_pols, cur_ike_pol, 'encryption: ' + re_match_ikev1_enc.group('enc').strip())
    elif start_ikev1_pol and re_ikev1_hash.match(line):
        re_match_ikev1_hash = re_ikev1_hash.match(line)
        add_values(ikev1_pols, cur_ike_pol, 'hash: ' + re_match_ikev1_hash.group('hash').strip())
    elif start_ikev1_pol and re_ikev1_grp.match(line):
        re_match_ikev1_grp = re_ikev1_grp.match(line)
        add_values(ikev1_pols, cur_ike_pol, 'dh group ' + re_match_ikev1_grp.group('group').strip())
    elif start_ikev1_pol and re_ikev1_life.match(line):
        re_match_ikev1_life = re_ikev1_life.match(line)
        add_values(ikev1_pols, cur_ike_pol, 'lifetime: ' + re_match_ikev1_life.group('life').strip())
    elif line.startswith('crypto ikev2 policy'):
        start_ikev1_pol = False
        start_ikev2_prop = False
        start_ikev2_pol = True
        re_match_ikev2_pol = re_ikev2_pol.match(line)
        cur_ike_pol = 'ikev2 policy ' + re_match_ikev2_pol.group('priority').strip()
    elif start_ikev2_pol and re_ikev2_enc.match(line):
        re_match_ikev2_enc = re_ikev2_enc.match(line)
        add_values(ikev2_pols, cur_ike_pol, 'encryption: ' + re_match_ikev2_enc.group('enc').strip())
    elif start_ikev2_pol and re_ikev2_hash.match(line):
        re_match_ikev2_hash = re_ikev2_hash.match(line)
        add_values(ikev2_pols, cur_ike_pol, 'integrity ' + re_match_ikev2_hash.group('int').strip())
    elif start_ikev2_pol and re_ikev2_grp.match(line):
        re_match_ikev2_grp = re_ikev2_grp.match(line)
        add_values(ikev2_pols, cur_ike_pol, 'dh group ' + re_match_ikev2_grp.group('group').strip())
    elif start_ikev2_pol and re_ikev2_life.match(line):
        re_match_ikev2_life = re_ikev2_life.match(line)
        add_values(ikev2_pols, cur_ike_pol, 'lifetime ' + re_match_ikev2_life.group('life').strip())
    elif start_ikev2_pol and re_ikev2_prf.match(line):
        re_match_ikev2_prf = re_ikev2_prf.match(line)
        add_values(ikev2_pols, cur_ike_pol, 'prf ' + re_match_ikev2_prf.group('prf').strip())
    elif line.startswith('webvpn'):
        start_ikev1_pol = False
        start_ikev2_prop = False
        start_ikev2_pol = False
        obj_net = False
    elif line.startswith(' enable'):
        re_match_webvpn_interface = re_webvpn_interface.match(line)
        webvpn_set.append('webvpn-interface ' + re_match_webvpn_interface.group('interface').strip())
    elif line.startswith(' anyconnect enable'):
        webvpn_set.append('anyconnect enabled')
    elif line.startswith(' tunnel-group-list enable'):
        webvpn_set.append('list_drop_down enabled')
    elif line.startswith('ip local pool'):
        re_match_ip_pools = re_ip_pools.match(line)
        add_values(local_ip_pools, re_match_ip_pools.group('poolname').strip(), re_match_ip_pools.group('ip_range').strip())
    elif re_grp_pol_att.match(line):
        grp_pol = True
        re_match_grp_pol_att = re_grp_pol_att.match(line)
        cur_grp_pol = re_match_grp_pol_att.group('group_name').strip()
    elif re_grp_pol_idle.match(line) and grp_pol:
        re_match_grp_pol_idle = re_grp_pol_idle.match(line)
        add_values(group_policy, cur_grp_pol, 'Idle Timeout: ' + re_match_grp_pol_idle.group('seconds').strip())
    elif re_grp_pol_split.match(line) and grp_pol:
        add_values(group_policy, cur_grp_pol, 'Split-Tunneling: Tunnelspecified')
    elif re_grp_pol_split_acl.match(line) and grp_pol:
        re_match_grp_pol_split_acl = re_grp_pol_split_acl.match(line)
        add_values(group_policy, cur_grp_pol, 'Split_Tunnel_Dst: ' + re_match_grp_pol_split_acl.group('ACL').strip())
        anycon_pol_tunnel_acl.add(re_match_grp_pol_split_acl.group('ACL').strip() + ' ' + cur_grp_pol)
    elif re_grp_pol_pool.match(line) and grp_pol:
        re_match_grp_pol_pool = re_grp_pol_pool.match(line)
        add_values(group_policy, cur_grp_pol, 'Address-Pool: ' + re_match_grp_pol_pool.group('address_pool').strip())
    elif re_user_acl.match(line) and grp_pol:
        re_match_user_acl = re_user_acl.match(line)
        add_values(group_policy, cur_grp_pol, 'Access-List: ' + re_match_user_acl.group('ACL').strip())
    elif re_user_name.match(line):
        grp_pol = False
        any_user = True
        re_match_user_name = re_user_name.match(line)
        cur_usr = re_match_user_name.group('username').strip()
    elif re_service_type_remote.match(line):
        add_values(anyconnect_user, cur_usr, 'service-type remote-access')
    elif re_user_acl.match(line) and any_user:
        re_match_user_acl = re_user_acl.match(line)
        add_values(anyconnect_user, cur_usr, 'Access-List: ' + re_match_user_acl.group('ACL').strip())
    elif re_user_grplock.match(line) and any_user:
        re_match_user_grplock = re_user_grplock.match(line)
        add_values(anyconnect_user, cur_usr, 'Locked_to_Group: ' + re_match_user_grplock.group('group').strip())
    elif re_tgrp_type.match(line):
        any_user = False
        trgp = True
        re_match_tgrp_type = re_tgrp_type.match(line)
        cur_tgrp = re_match_tgrp_type.group('tgrp_name').strip()
        cur_type = re_match_tgrp_type.group('tgrp_type').strip()
        add_values(tunnel_group, cur_tgrp, 'type: ' + re_match_tgrp_type.group('tgrp_type').strip())
    elif re_tgrp_general_attributes.match(line) and trgp:
        re_match_tgrp_general_attributes = re_tgrp_general_attributes.match(line)
        cur_tgrp = re_match_tgrp_general_attributes.group('tgrp_name').strip()
    elif re_tgrp_key.match(line) and trgp and cur_type == 'ipsec-l2l':
        add_values(tunnel_group, cur_tgrp, 'Pre-Shared-Key: ikev1')
    elif re_tgrp_v2_key.match(line) and trgp and cur_type == 'ipsec-l2l':
        add_values(tunnel_group, cur_tgrp, 'Pre-Shared-Key: ikev2')
    elif re_tgrp_webvpn_attributes.match(line) and trgp:
        re_match_tgrp_webvpn_attributes = re_tgrp_webvpn_attributes.match(line)
        cur_tgrp = re_match_tgrp_webvpn_attributes.group('tgrp_name').strip()
    elif re_trgp_grpalias_enable.match(line) and trgp:
        re_match_trgp_grpalias_enable = re_trgp_grpalias_enable.match(line)
        add_values(tunnel_group, cur_tgrp, 'Group alias: ' + re_match_trgp_grpalias_enable.group('alias_name').strip())
    elif re_tgrp_addr_pool.match(line) and trgp:
        re_match_tgrp_addr_pool = re_tgrp_addr_pool.match(line)
        add_values(tunnel_group, cur_tgrp, 'Address Pool: ' + re_match_tgrp_addr_pool.group('addr_pool').strip())
    elif re_dflttgrp_general_attributes.match(line) and trgp:
        re_match_dflttgrp_general_attributes = re_dflttgrp_general_attributes.match(line)
        add_values(tunnel_group, cur_tgrp, 'Default Group: ' + re_match_dflttgrp_general_attributes.group('dflt_grp_pol_name').strip())
    elif re_phase_1.match(line):
        re_match_phase_1 = re_phase_1.match(line)
        add_values(phase1_int_ike, re_match_phase_1.group('interface').strip(), re_match_phase_1.group('ikev').strip())

######################################  Processing in progress probably  ######################################
# Collect all Tunnel-Groups that have a Group-Alias defined, that are defined as a group-lock-value for an anyconnect user or that have an ipsec peer defined
for group in tunnel_group:
    tunnel_grp_set.add(group)
    if [alias for alias in tunnel_group[group] if 'type: ipsec-l2l' in alias] and group in peers_set:
        used_tgroups.add(group)                                                                  
        used_tgroups_ipsec.add(group)
    elif [alias for alias in tunnel_group[group] if 'type: ipsec-l2l' in alias] and group not in peers_set:
        unused_tgroups.add(group)
    elif [alias for alias in tunnel_group[group] if 'type: remote-access' in alias]:
        if [alias for alias in tunnel_group[group] if 'Group alias:' in alias]:
            used_tgroups.add(group)
            used_tgroups_remote.add(group)
        for user in anyconnect_user:
            if [user for user in anyconnect_user[user] if 'Locked_to_Group:' in user]:
                used_tgroups.add(''.join([grp.split(' ')[1] for grp in anyconnect_user[user] if 'Locked_to_Group:' in grp]))
                used_tgroups_remote.add(''.join([grp.split(' ')[1] for grp in anyconnect_user[user] if 'Locked_to_Group:' in grp]))
        for tgrp in tunnel_grp_set:
            if tgrp not in used_tgroups:
                unused_tgroups.add(tgrp)
# Add Group-Policies that are Default Policies for a Tunnel-Group (used or unused) to grp_pol_all
for pol in group_policy.keys():
    for tgrp in tunnel_group.keys():
        if [grp_pol.split(' ')[2] for grp_pol in tunnel_group[tgrp] if 'Default' in grp_pol]:
            grp_pol_all.add(pol)
        else:
            pass
# Divide all policies between used and "to check" depending on wether they are a default-policy for a used tunnel-group or not
for pol in grp_pol_all:
    for tgrp in used_tgroups_remote:
        if ''.join([grp_pol.split(' ')[2] for grp_pol in tunnel_group[tgrp] if 'Default' in grp_pol]) == pol:
            grp_pol_used.add(pol)
        else:
            grp_pol_check.add(pol)
# Remove used Group-Policies from grp_pol_check
for pol in grp_pol_used:
        grp_pol_check.remove(pol)
# Split the Group-Policy / Access-list pair into "need to be checked" and "used" depending on wether the group-policy is in use
for pol_acl in anycon_pol_tunnel_acl:
    if pol_acl.split(' ')[1] in grp_pol_check:
        pol_acl_check_set.add(pol_acl)
    else: pol_acl_used_set.add(pol_acl)
# Add Crypto-Map ACLs to acls_used_set and the corresponding Crypto Number to crypto_map_nr_used if Crypto-Map has a Peer. Otherwise add Number to unused.
for acl in ipsec.keys():
    if [peer for peer in ipsec[acl] if 'Peer:' in peer]:
            acls_used_set.add(acl)
            crypto_map_nr_used.add(''.join([number.split(' ')[2] for number in ipsec[acl] if 'Map Number:' in number]))
    else:
        crypto_map_nr_unused.add(''.join([number.split(' ')[2] for number in ipsec[acl] if 'Map Number:' in number]))
# Assign an Interface to each Enrcyption Domain
for key, value in ipsec.items():
    interface = value[0]
    add_values(ipsec_encr_int, key, ''.join(crypto_int[interface]))
# Parse used and unused tunnel_groups
for ippool in ippools_used:
    ippools_unused.remove(ippool)
# Remove used Crypto Numbers from unused set
for number in crypto_map_nr_used:
    if number in crypto_map_nr_unused:
        crypto_map_nr_unused.remove(number)
    else:
        pass
#
for key in ipsec.keys():
    if 'ikev1' in ipsec[key]:
        for value in ipsec[key]:
            if 'Phase' in value.split(' ', 2)[0]:
                tset = value.split(' ', 2)[2]
                if tset in transformsets.keys():
                    for offering in str(transformsets[tset][0]).split(' '):
                        ikev1_offerings.add(offering)
# Create List of all Interfaces that have Anyconnect enabled
for item in webvpn_set:
    if 'webvpn-interface' in item.split(' '):
        webvpn_ints.append(item.split(' ')[1])
# Add IP-Pools that are bound to a Group-Policy to ippools_used
for policy_name in grp_pol_used:
    for ippool in [addr.split(' ')[1] for addr in group_policy[policy_name] if 'Address-Pool:' in addr]:
        ippools_used.add(ippool)
# Add used and unused IPsec Names/Crypto Nr.s and usernames
for line in config_lines:
    if re_isacl.match(line) and re_aclname.match(line).group('acl_name') in ipsec:
        newacl = re_aclname.match(line).group('acl_name').strip()
        if [peer for peer in ipsec[newacl] if 'Peer:' in peer]:
            acls_used_set.add(newacl)
            crypto_map_nr_used.add(''.join([number.split(' ')[2] for number in ipsec[newacl] if 'Map Number:' in number]))
        else:
            crypto_map_nr_unused.add(''.join([number.split(' ')[2] for number in ipsec[newacl] if 'Map Number:' in number]))
    elif re_isacl.match(line) and re_aclname.match(line).group('acl_name').strip() in [acl.split(' ')[0] for acl in pol_acl_used_set]:
            newacl = re_aclname.match(line).group('acl_name').strip()
            acls_used_set.add(newacl)
    elif re_user_name.match(line):
        re_match_re_user_name = re_user_name.match(line)
        new_user = re_match_re_user_name.group('username').strip()
        if not user_name == new_user:
            user_name = new_user
            if user_name in anyconnect_user:
                if ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]) in anyconnect_user[user_name] and ''.join([acl for acl in anyconnect_user[user_name] if 'Access-List:' in acl]) in anyconnect_user[user_name]:
                    grp_pol_key = ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]).split(' ')[1]
                    for ippool in [pool.split(' ')[1] for pool in group_policy[grp_pol_key] if 'Address-Pool:' in pool]:
                        ippools_used.add(ippool)
                    usr_acl = ''.join([acl.split(' ')[1] for acl in anyconnect_user[user_name] if 'Access-List:' in acl])
                    acls_used_set.add(usr_acl)
                    acls_users_used.add(usr_acl)
                elif ''.join([acl for acl in anyconnect_user[user_name] if 'Access-List:' in acl]) in anyconnect_user[user_name] and ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]) not in anyconnect_user[user_name]:
                    usr_acl = ''.join([acl.split(' ')[1] for acl in anyconnect_user[user_name] if 'Access-List:' in acl])
                    acls_used_set.add(usr_acl)
                    acls_users_used.add(usr_acl)
                elif ''.join([acl for acl in anyconnect_user[user_name] if 'Access-List:' in acl]) not in anyconnect_user[user_name] and ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]) in anyconnect_user[user_name]:
                    grp_pol_key = ''.join([grp_lock for grp_lock in anyconnect_user[user_name] if 'Locked_to_Group:' in grp_lock]).split(' ')[1]
                    for ippool in [pool.split(' ')[1] for pool in group_policy[grp_pol_key] if 'Address-Pool:' in pool]:
                        ippools_used.add(ippool)
            else:
                anyconnect_check.add(user_name)
# Parse all objects and object-group for usage
for line in config_lines:
    if re_objnet.match(line):
        objects_all.add(re_objnet.match(line).group('obj_name').strip())
    elif re_objser.match(line):
        objects_all.add(re_objser.match(line).group('obj_name').strip())
    elif re_netgrp.match(line):
        cur_grp = re_netgrp.match(line).group('net_grp').strip()
        if re_netgrp.match(line).group('net_grp').strip() in obj_grps_all:
            pass
        else:
            add_values(obj_grps_all, cur_grp, None)
    elif re_netobj_obj.match(line):
        add_values(obj_grps_all, cur_grp, re_netobj_obj.match(line).group('obj_name').strip())
    elif re_srvgrp.match(line):
        cur_grp = re_srvgrp.match(line).group('srv_grp').strip()
        if re_srvgrp.match(line).group('srv_grp').strip() in obj_grps_all:
            pass
        else:
            add_values(obj_grps_all, cur_grp, None)
    elif re_srvgrp_obj.match(line):
        add_values(obj_grps_all, cur_grp, re_srvgrp_obj.match(line).group('obj_name').strip())
    elif re_grpobj.match(line):
        add_values(obj_grps_all, cur_grp, re_grpobj.match(line).group('obj_name').strip())
    # Parse only used ACLs
    elif re_aclname.search(line) and re_aclname.search(line).group('acl_name').strip() in acls_used_set:
        if re_obj.search(line):
            for object in re.findall('object\s(?P<obj>\S+)', line):
                objects_used.add(object)
            for grp_object in re.findall('object-group\s(?P<obj_grp>\S+)', line):
                obj_grps_used.add(grp_object)
    # Parse only unused ACLs
    elif re_aclname.search(line) and re_aclname.search(line).group('acl_name').strip() not in acls_used_set:
        if re_obj.search(line):
            for object in re.findall('object\s(?P<obj>\S+)', line):
                objects_unused.add(object)
            for grp_object in re.findall('object-group\s(?P<obj_grp>\S+)', line):
                obj_grps_unused.add(grp_object)
    else:
        pass
for object in objects_used:
    if object in objects_unused:
        objects_unused.remove(object)
    else:
        pass
for object in obj_grps_used:
    if object in obj_grps_unused:
        obj_grps_unused.remove(object)
    else:
        pass
for object in network_objects.keys():
    if len(network_objects[object]) == 0:
        objects_unused.add(object)
    else:
        pass
for object in network_groups.keys():
    if len(network_groups[object]) == 0:
        obj_grps_unused.add(object)
    else:
        pass

# Remove used ACLs from acl_check
for acl in acls_all_set:
    if acl in acls_used_set and acl in acl_check:
        acl_check.remove(acl)
            
# Unfold all network-groups to the BOOOOONE (Penis Joke)
unfold(network_groups)
# Unfold all Service-groups to the BOOOOONE (Second Penis Joke)
unfold(service_groups)
# Unfold all network-groups to the Undergarment (1750s Penis Joke)
unfold_folded(network_groups_folded)
# Unfold all Service-groups to the Undergarment (Second 1750s Penis Joke)
unfold_folded(service_groups_used)

###################################################### Where it all comes together (No porn pun intended) ######################################################
original_stdout = sys.stdout
with open('Config_Parse.html', 'w') as html_file:
    # Change the standard output to the file we created.
    sys.stdout = html_file
    # Parse ACLs that are actually in use
    html_hdr('Access-Lists bound to an Interface')
    print('Only Access-Lists that are bound to an Interface are listed here. Please check Hit-Counters to see if specific lines are used!')
    for line in config_lines:
        # Find and display all ACLs that are bound to an Interface
        if re_isacl.match(line) and re_aclname.match(line).group('acl_name').strip() in access_grps_n_interf:
            newacl = re_aclname.match(line).group('acl_name').strip()
            if not curacl == newacl:
                curacl = newacl
                html_tbl_ftr()
                if len(access_grps_n_interf[curacl]) == 1:
                    html_tbl_hdr(curacl, ''.join(access_grps_n_interf[curacl]))
                else:
                    html_tbl_hdr(curacl, '/'.join(access_grps_n_interf[curacl]))
                rulecnt = 1
            r = Rule(rulecnt, line)
            r.html()
            rulecnt += 1
    html_tbl_ftr()
    # Add Header for used Site-To-Site Tunnels
    html_hdr('Site-to-Site IPSec-VPNs')
    print('Only l2l-Tunnel that have a Peer entry are listed here')
    #start new loop for IPSec-Encryption Domains
    for line in config_lines:
        if re_isacl.match(line) and re_aclname.match(line).group('acl_name') in ipsec:
            header = 0
            newacl = re_aclname.match(line).group('acl_name').strip()
            if [peer for peer in ipsec[newacl] if 'Peer:' in peer]:
                if not curacl == newacl:
                    curacl = newacl
                    html_tbl_ftr()
                    html_tbl_hdr_ipsec_2(curacl, ' '.join(ipsec_encr_int[curacl]))
                    html_ipsec_phase2_ike_tbl(curacl)
                    html_tbl_hdr_ipsec()
                    rulecnt = 1
                r = Rule(rulecnt, line)
                r.html()
                rulecnt += 1
            else:
                pass
        if (line.startswith('logging') or line.startswith('mtu')) and header == 0:
            html_tbl_ftr()
            html_hdr('Anyconnect User and Settings')
            print('Lists all remote-access users and their corresponding settings')
            html_webvpn_hdr()
            html_webvpn_tbl_header()
            header += 1
        if re_user_name.match(line):
            re_match_re_user_name = re_user_name.match(line)
            new_user = re_match_re_user_name.group('username').strip()
            if not cur_usr == new_user:
                cur_usr = new_user
                hmtl_webvpn_tbl_bdy(cur_usr)

with open('Config_Parse.html', 'a') as html_file:
    # Change the standard output to the file we created.
    sys.stdout = html_file
    # Parse ACLs that are actually in use
    html_tbl_ftr()
    html_tbl_acl_hdr()
    for line in config_lines:
        if re_isacl.match(line) and re_aclname.match(line).group('acl_name').strip() in acls_users_used:
            newacl = re_aclname.match(line).group('acl_name').strip()
            if not curacl == newacl:
                curacl = newacl
                rulecnt = 1
            r = Rule(rulecnt, line)
            r.html_filter()
            rulecnt += 1
    html_tbl_ftr()
    html_tbl_tgrp_hdr()
    hmtl_tbl_tgrp_bdy()
    html_tbl_ftr()
    html_tbl_pol_hdr()
    hmtl_policy_tbl_bdy()
    html_tbl_ftr()
    for line in config_lines:
        if re_isacl.match(line) and re_aclname.match(line).group('acl_name').strip() in [acl.split(' ')[0] for acl in pol_acl_used_set]:
            newacl = re_aclname.match(line).group('acl_name').strip()
            cur_route = '/'.join([acl.split(' ')[1] for acl in pol_acl_used_set if newacl in acl.split(' ')])
            if not curacl == newacl:
                curacl = newacl
                html_tbl_ftr()
                html_tbl_tgp_hdr(curacl, cur_route)
                rulecnt = 1
            r = Rule(rulecnt, line)
            r.html()
            rulecnt += 1
    #Parse all config problems I could think of
    html_tbl_ftr()
    html_hdr('Please check the following Configurations')
    html_tbl_ftr()
    acl_check_tbl()
    for line in config_lines:
        if re_isacl.match(line) and re_aclname.match(line).group('acl_name').strip() in acl_check:
            newacl = re_aclname.match(line).group('acl_name').strip()
            if not curacl == newacl:
                curacl = newacl
                rulecnt = 1
            r = Rule(rulecnt, line)
            r.html_check()
            rulecnt += 1
    html_tbl_ftr()
    ipsec_check_tbl()
    html_tbl_ftr()
    anyconnect_users_check()
    html_tbl_ftr()
    html_tbl_tgrp_check_hdr()
    hmtl_tbl_tgr_check_bdy()
    html_tbl_ftr()
    html_tbl_pol_check_hdr()
    hmtl_policy_check_tbl_bdy()
    html_tbl_ftr()
    html_tbl_tgp_check_hdr()
    for line in config_lines:
        if re_isacl.match(line) and re_aclname.match(line).group('acl_name').strip() in [acl.split(' ')[0] for acl in pol_acl_check_set]:
            newacl = re_aclname.match(line).group('acl_name').strip()
            cur_route = '/'.join([acl.split(' ')[1] for acl in pol_acl_check_set if newacl in acl.split(' ')])
            if not curacl == newacl and len(cur_route):
                curacl = newacl
                html_tbl_ftr()
                html_tbl_tgp_check_bdy(curacl, cur_route)
    html_tbl_ftr()
    html_ippools_check_hdr()
    hmtl_ippools_check_bdy()
    html_tbl_ftr()
    html_grp_obj_check_hdr()
    hmtl_obj_check_bdy()
    html_tbl_ftr()
    hmtl_obj_grp_check_bdy()


sys.stdout = original_stdout

########################### ToDos ########################
# 1. NAT ebenfalls parsen
# 2. Hit-Counter aus ACL.txt mit aufnehmen in ACLs
print(pol_acl_used_set)