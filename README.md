# CCNA-Security-Answerbank
Answer Bank for CCNA Security exam

339q Combined from EKE – PassLeader – Egyptguy -- Securitytut

Number: 210-260
Passing Score: 860
Time Limit: 110 min
File Version: 3.2

03 AUGUST 2017

Sources:
+ EKE 210-260.examcollection.securitytut.com.249q + ASDM sim + 20 newq 03-aug-2017
+ Egypt guy PDF ducument and hand written questions
+ PassLeader New Cisco Exam Dumps forum link http://www.ciscobraindump.com/?s=210-260
+ http://www.securitytut.com/ccna-security-210-260/share-your-ccna-security-experience-2/ pg. 149–167
+ Left in all original explanations and comments
+ Placed questions w/diagrams in a separate ducument (they make the file to large for my VCE program)
+ Removed duplicate quesitons and renumbered (based on the EKE version above)

Q1	
Which two services define cloud networks? (Choose two.)

A. Infrastructure as a Service
B. Platform as a Service
C. Security as a Service
D. Compute as a Service
E. Tenancy as a Service

Answer: AB

Explanation/Reference:
BD
The NIST's definition of cloud computing defines the service models as follows:[2] + Software as a Service (SaaS). The capability provided to the consumer is to use the provider's applications running on a cloud infrastructure. The applications are accessible from various client devices through either a thin client interface, such as a web browser (e.g., web-based email), or a program interface. The consumer does not manage or control the underlying cloud infrastructure including network, servers, operating systems, storage, or even individual application capabilities, with the possible exception of limited user-specific application configuration settings.
+ Platform as a Service (PaaS). The capability provided to the consumer is to deploy onto the cloud infrastructure consumer-created or acquired applications created using programming languages, libraries, services, and tools supported by the provider. The consumer does not manage or control the underlying cloud infrastructure including network, servers, operating systems, or storage, but has control over the deployed applications and possibly configuration settings for the application-hosting environment.
+ Infrastructure as a Service (IaaS). The capability provided to the consumer is to provision processing, storage, networks, and other fundamental computing resources where the consumer is able to deploy and run arbitrary software, which can include operating systems and applications. The consumer does not manage or control the underlying cloud infrastructure but has control over operating systems, storage, and deployed applications; and possibly limited control of select networking components (e.g., host firewalls).
Source: https://en.wikipedia.org/wiki/Cloud_computing#Service_models

Q2	
In which two situations should you use out-of-band management? (Choose two.)

A. when a network device fails to forward packets
B. when you require ROMMON access
C. when management applications need concurrent access to the device
D. when you require administrator access from multiple locations
E. when the control plane fails to respond

Answer: AB

Explanation/Reference:
Brad
Confidence level: 90%

 OOB management is used for devices at the headquarters and is accomplished by connecting dedicated management ports or spare Ethernet ports on devices directly to the dedicated OOB management network hosting the management and monitoring applications and services. The OOB management network can be either implemented as a collection of dedicated hardware or based on VLAN isolation.

Source: http://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Security/SAFE_RG/SAFE_rg/chap9.html

Q3	
In which three ways does the TACACS protocol differ from RADIUS? (Choose three.)

A. TACACS uses TCP to communicate with the NAS.
B. TACACS can encrypt the entire packet that is sent to the NAS.
C. TACACS supports per-command authorization.
D. TACACS authenticates and authorizes simultaneously, causing fewer packets to be transmitted.
E. TACACS uses UDP to communicate with the NAS.
F. TACACS encrypts only the password field in an authentication packet.

Answer: ABC

Explanation/Reference:
BD
Source: Cisco Official Certification Guide, Table 3-2 TACACS+ Versus RADIUS, p.40

Q4	
According to Cisco best practices, which three protocols should the default ACL allow on an access port to enable wired BYOD devices to supply valid credentials and connect to the network? (Choose three.)

A. BOOTP
B. TFTP
C. DNS
D. MAB
E. HTTP
F. 802.1x

Answer: ABC

Explanation/Reference:
BD
ACLs are the primary method through which policy enforcement is done at access layer switches for wired devices within the campus.
ACL-DEFAULT--This ACL is configured on the access layer switch and used as a default ACL on the port. Its purpose is to prevent un-authorized access.
An example of a default ACL on a campus access layer switch is shown below:
Extended IP access list ACL-DEFAULT
10 permit udp any eq bootpc any eq bootps log (2604 matches) 20 permit udp any host 10.230.1.45 eq domain
30 permit icmp any any
40 permit udp any any eq tftp
50 deny ip any any log (40 matches)
As seen from the output above, ACL-DEFAULT allows DHCP, DNS, ICMP, and TFTP traffic and denies everything else.
Source: http://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Borderless_Networks/Unified_Access/ BYOD_Design_Guide/BYOD_Wired.html
MAB is an access control technique that Cisco provides and it is called MAC Authentication Bypass.

Q5	
Which two next-generation encryption algorithms does Cisco recommend? (Choose two.)

A. AES
B. 3DES
C. DES
D. MD5
E. DH-1024
F. SHA-384

Answer: AF

Explanation/Reference:
BD
The Suite B next-generation encryption (NGE) includes algorithms for authenticated encryption, digital signatures, key establishment, and cryptographic hashing, as listed here:
+ Elliptic Curve Cryptography (ECC) replaces RSA signatures with the ECDSA algorithm + AES in the Galois/Counter Mode (GCM) of operation
+ ECC Digital Signature Algorithm
+ SHA-256, SHA-384, and SHA-512
Source: Cisco Official Certification Guide, Next-Generation Encryption Protocols, p.97

Q6	
Which three ESP fields can be encrypted during transmission? (Choose three.)

A. Security Parameter Index
B. Sequence Number
C. MAC Address
D. Padding
E. Pad Length
F. Next Header

Answer: DEF

Explanation/Reference:
BD
The packet begins with two 4-byte fields (Security Parameters Index (SPI) and Sequence Number). Following these fields is the Payload Data, which has substructure that depends on the choice of encryption algorithm and mode, and on the use of TFC padding, which is examined in more detail later. Following the Payload Data are Padding and Pad Length fields, and the Next Header field. The optional Integrity Check Value (ICV) field completes the packet.
Source: https://tools.ietf.org/html/rfc4303#page-14

Q7	
What are two default Cisco IOS privilege levels? (Choose two.)

A. 0
B. 1
C. 5
D. 7
E. 10
F. 15

Answer: BF

Explanation/Reference:
BD
By default, the Cisco IOS software command-line interface (CLI) has two levels of access to commands: user EXEC mode (level 1) and privileged EXEC mode (level 15).
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/configuration/guide/fsecur_c/scfpass.html

Q8	
Which two authentication types does OSPF support? (Choose two.)

A. Plain text
B. MD5
C. HMAC
D. AES 256
E. SHA-1
F. DES

Answer: AB

Explanation/Reference:
BD
These are the three different types of authentication supported by OSPF + Null Authentication--This is also called Type 0 and it means no authentication information is included in the packet header. It is the default.
+ Plain Text Authentication--This is also called Type 1 and it uses simple clear-text passwords.
+ MD5 Authentication--This is also called Type 2 and it uses MD5 cryptographic passwords.
Source: http://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13697-25.html

Q9	
Which two features do CoPP and CPPr use to protect the control plane? (Choose two.)

A. QoS
B. traffic classification
C. access lists
D. policy maps
E. class maps
F. Cisco Express Forwarding

Answer: AB

Explanation/Reference:
BD
For example, you can specify that management traffic, such as SSH/HTTPS/SSL and so on, can be ratelimited (policed) down to a specific level or dropped completely.
Another way to think of this is as applying quality of service (QoS) to the valid management traffic and policing to the bogus management traffic.
Source: Cisco Official Certification Guide, Table 10-3 Three Ways to Secure the Control Plane, p.269

Q10	
Which two statements about stateless firewalls are true? (Choose two.)

A. They compare the 5-tuple of each incoming packet against configurable rules.
B. They cannot track connections.
C. They are designed to work most efficiently with stateless protocols such as HTTP or HTTPS.
D. Cisco IOS cannot implement them because the platform is stateful by nature.
E. The Cisco ASA is implicitly stateless because it blocks all traffic by default.

Answer: AB

Explanation/Reference:
BD
In stateless inspection, the firewall inspects a packet to determine the 5-tuple--source and destination IP addresses and ports, and protocol--information contained in the packet. This static information is then compared against configurable rules to determine whether to allow or drop the packet.
In stateless inspection the firewall examines each packet individually, it is unaware of the packets that have passed through before it, and has no way of knowing if any given packet is part of an existing connection, is trying to establish a new connection, or is a rogue packet.
Source: http://www.cisco.com/c/en/us/td/docs/wireless/asr_5000/19-0/XMART/PSF/19-PSF-Admin/19-PSF- Admin_chapter_01.html

Q11	
Which three statements about host-based IPS are true? (Choose three.)

A. It can view encrypted files.
B. It can have more restrictive policies than network-based IPS.
C. It can generate alerts based on behavior at the desktop level.
D. It can be deployed at the perimeter.
E. It uses signature-based policies.
F. It works with deployed firewalls.

Answer: ABC

Explanation/Reference:

One reference found to F

BD
If the network traffic stream is encrypted, HIPS has access to the traffic in unencrypted form.
HIPS can combine the best features of antivirus, behavioral analysis, signature filters, network firewalls, and application firewalls in one package.
Host-based IPS operates by detecting attacks that occur on a host on which it is installed. HIPS works by intercepting operating system and application calls, securing the operating system and application configurations, validating incoming service requests, and analyzing local log files for after-the-fact suspicious activity.
Source: http://www.ciscopress.com/articles/article.asp?p=1336425&seqNum=3

Q12	
What three actions are limitations when running IPS in promiscuous mode? (Choose three.)

A. deny attacker
B. deny packet
C. modify packet
D. request block connection
E. request block host
F. reset TCP connection

Answer: ABC

Explanation/Reference:
BD
In promiscuous mode, packets do not flow through the sensor. The disadvantage of operating in promiscuous mode, however, is the sensor cannot stop malicious traffic from reaching its intended target for certain types of attacks, such as atomic attacks (single-packet attacks). The response actions implemented by promiscuous sensor devices are post-event responses and often require assistance from other networking devices, for example, routers and firewalls, to respond to an attack.
Source: http://www.cisco.com/c/en/us/td/docs/security/ips/7-0/configuration/guide/cli/cliguide7/ cli_interfaces.html

Q13	
When an IPS detects an attack, which action can the IPS take to prevent the attack from spreading?

A. Deny the connection inline.
B. Perform a Layer 6 reset.
C. Deploy an antimalware system.
D. Enable bypass mode.

Answer: A

Explanation/Reference:
BD
Deny connection inline: This action terminates the packet that triggered the action and future packets that are part of the same TCP connection. The attacker could open up a new TCP session (using different port numbers), which could still be permitted through the inline IPS.
Available only if the sensor is configured as an IPS.
Source: Cisco Official Certification Guide, Table 17-4 Possible Sensor Responses to Detected Attacks, p.465

Q14	
What is an advantage of implementing a Trusted Platform Module for disk encryption?

A. It provides hardware authentication.
B. It allows the hard disk to be transferred to another device without requiring re-encryption.dis
C. It supports a more complex encryption algorithm than other disk-encryption technologies.
D. It can protect against single points of failure.

Answer: A

Explanation/Reference:
BD
Trusted Platform Module (TPM) is an international standard for a secure cryptoprocessor, which is a dedicated microcontroller designed to secure hardware by integrating cryptographic keys into devices.
Software can use a Trusted Platform Module to authenticate hardware devices. Since each TPM chip has a unique and secret RSA key burned in as it is produced, it is capable of performing platform authentication.
Source: https://en.wikipedia.org/wiki/Trusted_Platform_Module#Disk_encryption

Q15	
What is the purpose of the Integrity component of the CIA triad?

A. to ensure that only authorized parties can modify data
B. to determine whether data is relevant
C. to create a process for accessing data
D. to ensure that only authorized parties can view data

Answer: A

Explanation/Reference:
BD
Integrity for data means that changes made to data are done only by authorized individuals/systems. Corruption of data is a failure to maintain data integrity.
Source: Cisco Official Certification Guide, Confidentiality, Integrity, and Availability, p.6
Q16	
In a security context, which action can you take to address compliance?

A. Implement rules to prevent a vulnerability.
B. Correct or counteract a vulnerability.
C. Reduce the severity of a vulnerability.
D. Follow directions from the security appliance manufacturer to remediate a vulnerability.

Answer: A

Explanation/Reference:
BD
In general, compliance means conforming to a rule, such as a specification, policy, standard or law.
Source: https://en.wikipedia.org/wiki/Regulatory_compliance

Q17	
Which type of secure connectivity does an extranet provide?

A. other company networks to your company network
B. remote branch offices to your company network
C. your company network to the Internet
D. new networks to your company network

Answer: A

Explanation/Reference:
BD
What is an Extranet? In the simplest terms possible, an extranet is a type of network that crosses organizational boundaries, giving outsiders access to information and resources stored inside the organization's internal network (Loshin, p. 14).
Source: https://www.sans.org/reading-room/whitepapers/firewalls/securing-extranet-connections-816

Q18	
Which tool can an attacker use to attempt a DDoS attack?

A. botnet
B. Trojan horse
C. virus
D. adware

Answer: A

Explanation/Reference:
BD
Denial-of-service (DoS) attack and distributed denial-of-service (DDoS) attack. An example is using a botnet to attack a target system.
Source: Cisco Official Certification Guide, Table 1-6 Additional Attack Methods, p.16

Q19	
What type of security support is provided by the Open Web Application Security Project?

A. Education about common Web site vulnerabilities.
B. A Web site security framework.
C. A security discussion forum for Web site developers.
D. Scoring of common vulnerabilities and exposures.

Answer: A

Explanation/Reference:
BD
The Open Web Application Security Project (OWASP) is a worldwide not-for-profit charitable organization focused on improving the security of software. Our mission is to make software security visible, so that individuals and organizations are able to make informed decisions . OWASP is in a unique position to provide impartial, practical information about AppSec to individuals, corporations, universities, government agencies and other organizations worldwide.
Source: https://www.owasp.org/index.php/Main_Page

Q20	
What type of attack was the Stuxnet virus?

A. cyber warfare
B. hacktivism
C. botnet
D. social engineering

Answer: A

Explanation/Reference:
BD
Stuxnet is a computer worm that targets industrial control systems that are used to monitor and control large scale industrial facilities like power plants, dams, waste processing systems and similar operations. It allows the attackers to take control of these systems without the operators knowing. This is the first attack we've seen that allows hackers to manipulate real-world equipment, which makes it very dangerous.
Source: https://us.norton.com/stuxnet

Q21	
What type of algorithm uses the same key to encrypt and decrypt data?

A. a symmetric algorithm
B. an asymmetric algorithm
C. a Public Key Infrastructure algorithm
D. an IP security algorithm

Answer: A

Explanation/Reference:
BD
A symmetric encryption algorithm, also known as a symmetrical cipher, uses the same key to encrypt the data and decrypt the data.
Source: Cisco Official Certification Guide, p.93

Q22	
Refer to the exhibit
########################

R1#show snmp
Chassis: FTX123456789
0 SNPM packets input
  6 Bad SNMP version errors
  3 Unknown community name
  9 Illegal operation for community name supplied
  4 Encoding errors
  2 Number of requested variables
  0 Number of altered variables
  98 Get-request PDUs
  12 Get-next PDUs 
  2 Set-request PDUs
  0 Input queue packet drops (Maximum queue size 1000)
0 SNMP packets output
  0 Too big errors (Maximum packet size 1500)
  0 No such name erorrs
  0 Bad value errors
  0 General errors
  31 Response PDUs
  1 Trap PDUs

#######################

How many times was a read-only string used to attempt a write operation?

A. 9
B. 6
C. 4
D. 3
E. 2

Answer: A

Explanation/Reference:
BD
To check the status of Simple Network Management Protocol (SNMP) communications, use the show snmp command in user EXEC or privileged EXEC mode.
Illegal operation for community name supplied: Number of packets requesting an operation not allowed for that community
Source: http://www.cisco.com/c/en/us/td/docs/ios/netmgmt/command

Explanation/Reference/nm_book/nm_16.html

Q23	
Refer to the exhibit
####################

R1>show clock detail
.22:22:35:123 UTC Tue Feb 26 2013
Time source NTP

####################

Which statement about the device time is true?

A. The time is authoritative, but the NTP process has lost contact with its servers.
B. The time is authoritative because the clock is in sync.
C. The clock is out of sync.
D. NTP is configured incorrectly.
E. The time is not authoritative.

Answer: A

Explanation/Reference:
Brad

A

Confidence level: 100%

Remember: The [.] at the beginning of the time tells us the NTP process has last contact with its servers. We know the time is authoritative because there would be a [*] at the beginning if not.
 
Q24	
How does the Cisco ASA use Active Directory to authorize VPN users?

A. It queries the Active Directory server for a specific attribute for the specified user.
B. It sends the username and password to retrieve an ACCEPT or REJECT message from the Active Directory server.
C. It downloads and stores the Active Directory database to query for future authorization requests.
D. It redirects requests to the Active Directory server defined for the VPN group.

Answer: A

Explanation/Reference:
BD
?
When ASA needs to authenticate a user to the configured LDAP server, it first tries to login using the login DN provided. After successful login to the LDAP server, ASA sends a search query for the username provided by the VPN user. This search query is created based on the naming attribute provided in the configuration. LDAP replies to the query with the complete DN of the user. At this stage ASA sends a second login attempt to the LDAP server. In this attempt, ASA tries to login to the LDAP server using the VPN user's full DN and password provided by the user. A successful login to the LDAP server will indicate that the credentials provided by the VPN user are correct and the tunnel negotiation will move to the Phase 2.
Source: http://www.networkworld.com/article/2228531/cisco-subnet/using-your-active-directory-for-vpn- authentication-on-asa.html

Q25	
Which statement about Cisco ACS authentication and authorization is true?

A. ACS servers can be clustered to provide scalability.
B. ACS can query multiple Active Directory domains.
C. ACS uses TACACS to proxy other authentication servers.
D. ACS can use only one authorization profile to allow or deny requests.

Answer: A

Explanation/Reference:
BD
ACS can join one AD domain. If your Active Directory structure has multi-domain forest or is divided into multiple forests, ensure that trust relationships exist between the domain to which ACS is connected and the other domains that have user and machine information to which you need access. So B is not correct.
Source: http://www.cisco.com/c/en/us/td/docs/net_mgmt/cisco_secure_access_control_system/5-8/ACS- ADIntegration/guide/Active_Directory_Integration_in_ACS_5-8.pdf + You can define multiple authorization profiles as a network access policy result. In this way, you maintain a smaller number of authorization profiles, because you can use the authorization profiles in combination as rule results, rather than maintaining all the combinations themselves in individual profiles. So D. is not correct + ACS 5.1 can function both as a RADIUS and RADIUS proxy server. When it acts as a proxy server, ACS receives authentication and accounting requests from the NAS and forwards the requests to the external RADIUS server. So C. is nor correct.
Source: http://www.cisco.com/c/en/us/td/docs/net_mgmt/cisco_secure_access_control_system/5-1/user/guide/ acsuserguide/policy_mod.html

Q26	
Refer to the exhibit
####################

Authentication event fail action next-method
Authentication event no-response action authorize vlan 101
Authentication order mab dot1x web auth
Authentication priority dot1x mab
Authentication port-control auto
Dot1x pas authenticator

####################

If a supplicant supplies incorrect credentials for all authentication methods configured on the switch, how will the switch respond?

A. The supplicant will fail to advance beyond the webauth method.
B. The switch will cycle through the configured authentication methods indefinitely.
C. The authentication attempt will time out and the switch will place the port into the unauthorized state.
D. The authentication attempt will time out and the switch will place the port into VLAN 101.

Answer: A

Explanation/Reference:
BD
Flexible authentication (FlexAuth) is a set of features that allows IT administrators to configure the sequence and priority of IEEE 802.1X, MAC authentication bypass (MAB), and switch-based web authentication (local WebAuth).
Case 2: Order MAB Dot1x and Priority Dot1x MAB
If you change the order so that MAB comes before IEEE 802.1X authentication and change the default priority so that IEEE 802.1X authentication precedes MAB, then every device in the network will still be subject to MAB, but devices that pass MAB can subsequently go through IEEE 802.1X authentication.
Special consideration must be paid to what happens if a device fails IEEE 802.1X authentication after successful MAB. First, the device will have temporary network access between the time MAB succeeds and IEEE 802.1X authentication fails. What happens next depends on the configured event-fail behavior.
If next-method is configured and a third authentication method (such as WebAuth) is not enabled, then the switch will return to the first method (MAB) after the held period. MAB will succeed, and the device will again have temporary access until and unless the supplicant tries to authenticate again.
If next-method failure handling and local WebAuth are both configured after IEEE 802.1X authentication fails, local WebAuth ignores EAPoL-Start commands from the supplicant.

MAB MAB Pass Port Authorized by MAB  EAPoL-Start Received  IEEE 802.1x
MAB MAB Fail IEEE 802.1x
(config-if)#authentication order mab dot1x
(config-if)#authentication priority dot1x mab

Source: http://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/identity-based-networking-service/ application_note_c27-573287.html

Q27	
Which EAP method uses Protected Access Credentials?

A. EAP-FAST
B. EAP-TLS
C. EAP-PEAP
D. EAP-GTC

Answer: A

Explanation/Reference:
BD
Flexible Authentication via Secure Tunneling (EAP-FAST) is a protocol proposal by Cisco Systems as a replacement for LEAP. The protocol was designed to address the weaknesses of LEAP while preserving the "lightweight" implementation. Use of server certificates is optional in EAP-FAST. EAP-FAST uses a Protected Access Credential (PAC) to establish a TLS tunnel in which client credentials are verified.
Source: https://en.wikipedia.org/wiki/Extensible_Authentication_Protocol

 

Q28	
What is one requirement for locking a wired or wireless device from ISE?

A. The ISE agent must be installed on the device.
B. The device must be connected to the network when the lock command is executed.
C. The user must approve the locking action.
D. The organization must implement an acceptable use policy allowing device locking.

Answer: A

Explanation/Reference:
BD
Agents are applications that reside on client machines logging into the Cisco ISE network. Agents can be persistent (like the AnyConnect, Cisco NAC Agent for Windows and Mac OS X) and remain on the client machine after installation, even when the client is not logged into the network. Agents can also be temporal (like the Cisco NAC Web Agent), removing themselves from the client machine after the login session has terminated.
Source: http://www.cisco.com/c/en/us/td/docs/security/ise/2-0/admin_guide/b_ise_admin_guide_20/ b_ise_admin_guide_20_chapter_010101.html

 

Q29	
What VPN feature allows traffic to exit the security appliance through the same interface it entered?

A. Hair-pinning
B. NAT
C. NAT traversal
D. split tunneling

Answer: A

Explanation/Reference:
BD
In network computing, hairpinning (or NAT loopback) describes a communication between two hosts behind the same NAT device using their mapped endpoint. Because not all NAT devices support this communication configuration, applications must be aware of it.
Hairpinning is where a machine on the LAN is able to access another machine on the LAN via the external IP address of the LAN/router (with port forwarding set up on the router to direct requests to the appropriate machine on the LAN).
Source: https://en.wikipedia.org/wiki/Hairpinning

 

Q30	
What VPN feature allows Internet traffic and local LAN/WAN traffic to use the same network connection?

A. split tunneling
B. hairpinning
C. tunnel mode
D. transparent mode

Answer: A

Explanation/Reference:
BD
Split tunneling is a computer networking concept which allows a mobile user to access dissimilar security domains like a public network (e.g., the Internet) and a local LAN or WAN at the same time, using the same or different network connections. This connection state is usually facilitated through the simultaneous use of, a Local Area Network (LAN) Network Interface Card (NIC), radio NIC, Wireless Local Area Network (WLAN) NIC, and VPN client software application without the benefit of access control.
Source: https://en.wikipedia.org/wiki/Split_tunneling

Q31	
Refer to the exhibit
#####################

Crypto ikev1 policy 1
Encryption aes
Hash md5
Authentication pre-share
Group 2
Lifetime 14400

####################

What is the effect of the given command sequence?

A. It configures IKE Phase 1.
B. It configures a site-to-site VPN tunnel.
C. It configures a crypto policy with a key size of 14400.
D. It configures IPSec Phase 2.

Answer: A

Explanation/Reference:
BD
Configure the IPsec phase1 with the 5 parameters HAGLE (Hashing-Authentication-Group-Lifetime-Encryption)

 

Q32	
Refer to the exhibit.
#####################

Crypto map mymap 20 match address 201
Access-list 201 permit ip 10.10.10.0 255.255.255.0 10.100.100.0 255.255.255.0

####################

What is the effect of the given command sequence?

A. It defines IPSec policy for traffic sourced from 10.10.10.0/24 with a destination of 10.100.100.0/24.
B. It defines IPSec policy for traffic sourced from 10.100.100.0/24 with a destination of 10.10.10.0/24.
C. It defines IKE policy for traffic sourced from 10.10.10.0/24 with a destination of 10.100.100.0/24.
D. It defines IKE policy for traffic sourced from 10.100.100.0/24 with a destination of 10.10.10.0/24.

Answer: A

Explanation/Reference:
BD
A crypto ACL is a case for an extended ACL where we specify the source and destination address of the networks to be encrypted.

Q33	
Refer to the exhibit.
####################
Dst		src		state		conn-id		slot
10.10.10.2	10.1.1.5	QM_IDLE	1		0

####################

While troubleshooting site-to-site VPN, you issued the show crypto isakmp sa command. What does the given output show?

A. IPSec Phase 1 is established between 10.10.10.2 and 10.1.1.5.
B. IPSec Phase 2 is established between 10.10.10.2 and 10.1.1.5.
C. IPSec Phase 1 is down due to a QM_IDLE state.
D. IPSec Phase 2 is down due to a QM_IDLE state.

Answer: A

Explanation/Reference:
BD
This is the output of the #show crypto isakmp sa command. This command shows the Internet Security Association Management Protocol (ISAKMP) security associations (SAs) built between peers - IPsec Phase1.
The "established" clue comes from the state parameter QM_IDLE - this is what we want to see.
More on this
http://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/5409-ipsec-debug- 00.html

Q34	
Refer to the exhibit.
####################

Current_peer: 10.1.1.5
   Permit, flags={origin_is_acl,}
  #pkts encaps: 1205,  #pkts encrypt: 1025,  #pkts digest 1205
  #pkts decaps: 1168,  #pkts decrypt: 1168,  #pkts verify 1168
  #pkts compressed: 0,  #pkts decompressed: 0
  #pkts not ocmpressed: 0,  #pkts compr. Failed: 0,
  #pkts decompress failed: 0, #send errors 0, #recv errors 0
   Local crypto endpt.: 10.1.1.1, report ctypto endpt.: 10.1.1.5

####################

While troubleshooting site-to-site VPN, you issued the show crypto ipsec sa command. What does the given output show?

A. IPSec Phase 2 is established between 10.1.1.1 and 10.1.1.5.
B. ISAKMP security associations are established between 10.1.1.5 and 10.1.1.1.
C. IKE version 2 security associations are established between 10.1.1.1 and 10.1.1.5.
D. IPSec Phase 2 is down due to a mismatch between encrypted and decrypted packets.

Answer: A

Explanation/Reference:
BD
This command shows IPsec SAs built between peers - IPsec Phase2. The encrypted tunnel is build between 10.1.1.5 and 10.1.1.1 (the router from which we issued the command).

Q35	
Refer to the exhibit.
####################

Username HelpDesk privilege 9 password 0 helpdesk
Username Monitor privilege 9 password 0 watcher
Username Admin password checkme
Username Admin privilege 6 autocommand show running
Privilege exec level 6 configure terminal

####################

The Admin user is unable to enter configuration mode on a device with the given configuration. What change can you make to the configuration to correct the problem?

A. Remove the autocommand keyword and arguments from the Username Admin privilege line.
B. Change the Privilege exec level value to 15.
C. Remove the two Username Admin lines.
D. Remove the Privilege exec line.

Answer: A

Explanation/Reference:
BD
autocommand: (Optional) Causes the specified command to be issued automatically after the user logs in.
When the command is complete, the session is terminated. Because the command can be any length and can contain embedded spaces, commands using the autocommand keyword must be the last option on the line.
So after successfully logs in the Admin user sees the running configuration and immediately after is disconnected by the router. So removing the command lets keeps him connected.
Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-xe-3se-3850-cr-book/sec-s1-xe- 3se-3850-cr-book_chapter_0110.html

Q36	
After reloading a router, you issue the dir command to verify the installation and observe that the image file appears to be missing. For what reason could the image file fail to appear in the dir output?

A. The secure boot-image command is configured.
B. The secure boot-config command is configured.
C. The confreg 0x24 command is configured.
D. The reload command was issued from ROMMON.

Answer: A

Explanation/Reference:
BD
#secure boot-image
This command enables or disables the securing of the running Cisco IOS image. Because this command has the effect of "hiding" the running image, the image file will not be included in any directory listing of the disk.
Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr- s1.html#wp3328121947

 

Q37	
What is the effect of the send-lifetime local 23:59:00 31 December 2013 infinite command?

A. It configures the device to begin transmitting the authentication key to other devices at 00:00:00 local time on January 1, 2014 and continue using the key indefinitely.
B. It configures the device to begin transmitting the authentication key to other devices at 23:59:00 local time on December 31, 2013 and continue using the key indefinitely.
C. It configures the device to begin accepting the authentication key from other devices immediately and stop accepting the key at 23:59:00 local time on December 31, 2013.
D. It configures the device to generate a new authentication key and transmit it to other devices at 23:59:00 local time on December 31, 2013.
E. It configures the device to begin accepting the authentication key from other devices at 23:59:00 local time on December 31, 2013 and continue accepting the key indefinitely.
F. It configures the device to begin accepting the authentication key from other devices at 00:00:00 local time on January 1, 2014 and continue accepting the key indefinitely.

Answer: B

Explanation/Reference:
BD
To send the valid key and to authenticate information from the local host to the peer, use the send-lifetime command in keychain-key configuration mode.
send-lifetime start-time [ duration duration value | infinite | end-time ] start-time: Start time, in hh:mm:ss day month year format, in which the key becomes valid. The range is from
0:0:0 to 23:59:59.
infinite: (Optional) Specifies that the key never expires once it becomes valid.
Source: http://www.cisco.com/c/en/us/td/docs/routers/crs/software/crs_r4-2/security/command
Explanation/Reference/ b_syssec_cr42crs/b_syssec_cr41crs_chapter_0100.html#wp2198915138

 

Q38	
What type of packet creates and performs network operations on a network device?

A. control plane packets
B. data plane packets
C. management plane packets
D. services plane packets

Answer: A

Explanation/Reference:
BD
Control plane: This includes protocols and traffic that the network devices use on their own without direct interaction from an administrator. An example is a routing protocol.
Source: Cisco Official Certification Guide, The Network Foundation Protection Framework, p.264

 

Q39	
An attacker installs a rogue switch that sends superior BPDUs on your network. What is a possible result of this activity?

A. The switch could offer fake DHCP addresses.
B. The switch could become the root bridge.
C. The switch could be allowed to join the VTP domain.
D. The switch could become a transparent bridge.

Answer: B

Explanation/Reference:
BD
If a switch receives an inferior BPDU, nothing changes. Receiving a superior BPDU will kick off a reconvergence of the STP topology. So the rogue switch may become a root bridge.
Source: http://www.networkpcworld.com/what-are-inferior-and-superior-bpdus-of-stp/

 

Q40	
In what type of attack does an attacker virtually change a device's burned-in address in an attempt to circumvent access lists and mask the device's true identity?

A. gratuitous ARP
B. ARP poisoning
C. IP spoofing
D. MAC spoofing

Answer: D

Explanation/Reference:
BD
A device's burned-in address is its MAC address. So by changing it to something else may trick hosts on the network into sending packets to it.

 

Q41	
What command can you use to verify the binding table status?

A. "show ip dhcp snooping binding"
B. "show ip dhcp pool"
C. "show ip dhcp source binding"
D. "show ip dhcp snooping"
E. "show ip dhcp snooping database"
F. "show ip dhcp snooping statistics"

Answer: A

Explanation/Reference:
Brad

Confidence level: 80%

Note: I researched this question at the following link:
http://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/12-2_58_se/command/ reference/2960cr/cli2.html

If not E is not the correct answer, then the answer is A. However, I'm pretty sure it is E based on these two quotes:
"Use the show ip dhcp snooping binding command in EXEC mode to display the DHCP snooping binding database and configuration information for all interfaces on a switch." "Use the show ip dhcp snooping database command in EXEC mode to display the status of the DHCP snooping binding database agent.

BD

@Answer on securitytut.com made a valid comment on the fact that it's not asking about the database agent, as Brad's reference, but on the status (not statistics) of the binding table

On CCNP R&S TShoot 300-135 Official Guide, page 267 it says ...

Example 7-26 Verifying DHCP Snooping Bindings

SW1# show ip dhcp snooping binding

MacAddress IpAddress Lease(sec) Type VLAN Interface

------------ --------­ ------- --------- --- --------­

08:00:27:5D:06:D6 10.1.1.10 67720 dhcp-snooping 10 FastEthernet0/1

Total number of bindings: 1

So, what is DHCP Snooping bindings and what is the status of binding table? Aren't they the same. An if so it clearly says "verify".

Q42	
If a switch receives a superior BPDU and goes directly into a blocked state, what mechanism must be in use?

A. STP root guard
B. EtherChannel guard
C. loop guard
D. STP BPDU guard

Answer: A

Explanation/Reference:
Brad

 A

Confidence level: 100%

Remember: The phrase "only superior BPDUs" is the key to the correct answer. BPDU guard will block a port if *ANY* BPDU is received.

BD

Root guard allows the device to participate in STP as long as the device does not try to become the root. If root guard blocks the port, subsequent recovery is automatic. Recovery occurs as soon as the offending device ceases to send superior BPDUs.

Source: http://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/10588-74.html

Q43	
Which statement about a PVLAN isolated port configured on a switch is true?

A. The isolated port can communicate only with the promiscuous port.
B. The isolated port can communicate with other isolated ports and the promiscuous port.
C. The isolated port can communicate only with community ports.
D. The isolated port can communicate only with other isolated ports.

Answer: A

Explanation/Reference:
BD
Isolated -- An isolated port is a host port that belongs to an isolated secondary VLAN. This port has complete isolation from other ports within the same private VLAN domain, except that it can communicate with associated promiscuous ports. Private VLANs block all traffic to isolated ports except traffic from promiscuous ports. Traffic received from an isolated port is forwarded only to promiscuous ports. You can have more than one isolated port in a specified isolated VLAN. Each port is completely isolated from all other ports in the isolated VLAN.
Source: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/ CLIConfigurationGuide/PrivateVLANs.html

 

Q44	
If you change the native VLAN on the trunk port to an unused VLAN, what happens if an attacker attempts a double-tagging attack?

A. The trunk port would go into an error-disabled state.
B. A VLAN hopping attack would be successful.
C. A VLAN hopping attack would be prevented.
D. The attacked VLAN will be pruned.

Answer: C

Explanation/Reference:
BD
VLAN hopping is a computer security exploit, a method of attacking networked resources on a virtual LAN (VLAN). The basic concept behind all VLAN hopping attacks is for an attacking host on a VLAN to gain access to traffic on other VLANs that would normally not be accessible. There are two primary methods of VLAN hopping: switch spoofing and double tagging.
Double Tagging can only be exploited when switches use "Native VLANs". Double Tagging can be mitigated by either one of the following actions:
+ Simply do not put any hosts on VLAN 1 (The default VLAN)
+ Change the native VLAN on all trunk ports to an unused VLAN ID Source: https://en.wikipedia.org/wiki/VLAN_hopping

 

Q45	
What is a reason for an organization to deploy a personal firewall?

A. To protect endpoints such as desktops from malicious activity.
B. To protect one virtual network segment from another.
C. To determine whether a host meets minimum security posture requirements.
D. To create a separate, non-persistent virtual environment that can be destroyed after a session.
E. To protect the network from DoS and syn-flood attacks.

Answer: A

Explanation/Reference:
BD
The term personal firewall typically applies to basic software that can control Layer 3 and Layer 4 access to client machines. HIPS provides several features that offer more robust security than a traditional personal firewall, such as host intrusion prevention and protection against spyware, viruses, worms, Trojans, and other types of malware.
Source: Cisco Official Certification Guide, Personal Firewalls and Host Intrusion Prevention Systems , p.499

 

Q46	
Which statement about personal firewalls is true?

A. They can protect a system by denying probing requests.
B. They are resilient against kernel attacks.
C. They can protect email messages and private documents in a similar way to a VPN.
D. They can protect the network against attacks.

Answer: A

Explanation/Reference:
BD
Features
+ Block or alert the user about all unauthorized inbound or outbound connection attempts + Allows the user to control which programs can and cannot access the local network and/or Internet and provide the user with information about an application that makes a connection attempt + Hide the computer from port scans by not responding to unsolicited network traffic + Monitor applications that are listening for incoming connections + Monitor and regulate all incoming and outgoing Internet users + Prevent unwanted network traffic from locally installed applications + Provide information about the destination server with which an application is attempting to communicate + Track recent incoming events, outgoing events, and intrusion events to see who has accessed or tried to access your computer.
+ Personal Firewall blocks and prevents hacking attempt or attack from hackers Source: https://en.wikipedia.org/wiki/Personal_firewall

 
Q47	
Refer to the exhibit.

#####################
 
UDP outside 209.165.201.225:53 inside 10.0.0.10:52464, idle 0:00:01, bytes 266, flags –

#####################

What type of firewall would use the given configuration line?

A. a stateful firewall
B. a personal firewall
C. a proxy firewall
D. an application firewall
E. a stateless firewall

Answer: A

Explanation/Reference:
BD
The output is from "show conn" command on an ASA. This is another example output I've simulated ciscoasa# show conn
20 in use, 21 most used
UDP OUTSIDE 172.16.0.100:53 INSIDE 10.10.10.2:59655, idle 0:00:06, bytes 39, flags -

Q48	
What is the only permitted operation for processing multicast traffic on zone-based firewalls?

A. Only control plane policing can protect the control plane against multicast traffic.
B. Stateful inspection of multicast traffic is supported only for the self-zone.
C. Stateful inspection for multicast traffic is supported only between the self-zone and the internal zone.
D. Stateful inspection of multicast traffic is supported only for the internal zone.

Answer: A

Explanation/Reference:
BD
Neither Cisco IOS ZFW or Classic Firewall include stateful inspection support for multicast traffic.
So the only choice is A.
Source: http://www.cisco.com/c/en/us/support/docs/security/ios-firewall/98628-zone-design-guide.html

 

Q49	
How does a zone-based firewall implementation handle traffic between interfaces in the same zone?

A. Traffic between two interfaces in the same zone is allowed by default.
B. Traffic between interfaces in the same zone is blocked unless you configure the same-security permit command.
C. Traffic between interfaces in the same zone is always blocked.
D. Traffic between interfaces in the same zone is blocked unless you apply a service policy to the zone pair.

Answer: A

Explanation/Reference:
BD
For interfaces that are members of the same zone, all traffic is permitted by default.
Source: Cisco Official Certification Guide, Zones and Why We Need Pairs of Them, p.380

 

Q50	
Which two statements about Telnet access to the ASA are true? (Choose two).

A. You may VPN to the lowest security interface to telnet to an inside interface.
B. You must configure an AAA server to enable Telnet.
C. You can access all interfaces on an ASA using Telnet.
D. You must use the command virtual telnet to enable Telnet.
E. Best practice is to disable Telnet and use SSH.

Answer: AE

Explanation/Reference:
BD
The ASA allows Telnet and SSH connections to the ASA for management purposes. You cannot use Telnet to the lowest security interface unless you use Telnet inside an IPSec tunnel.
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa82/configuration/guide/config/ access_management.html#wp1054101

 

Q51	
Which statement about communication over failover interfaces is true?

A. All information that is sent over the failover and stateful failover interfaces is sent as clear text by default.
B. All information that is sent over the failover interface is sent as clear text, but the stateful failover link is encrypted by default.
C. All information that is sent over the failover and stateful failover interfaces is encrypted by default.
D. User names, passwords, and preshared keys are encrypted by default when they are sent over the failover and stateful failover interfaces, but other information is sent as clear text.

Answer: A

Explanation/Reference:
BD
All information sent over the failover and Stateful Failover links is sent in clear text unless you secure the communication with a failover key. If the security appliance is used to terminate VPN tunnels, this information includes any usernames, passwords and preshared keys used for establishing the tunnels. Transmitting this sensitive data in clear text could pose a significant security risk. We recommend securing the failover communication with a failover key if you are using the security appliance to terminate VPN tunnels.
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa80/configuration/guide/conf_gd/failover.html

 

Q52	
If a packet matches more than one class map in an individual feature type's policy map, how does the ASA handle the packet?

A. The ASA will apply the actions from only the first matching class map it finds for the feature type.
B. The ASA will apply the actions from only the most specific matching class map it finds for the feature type.
C. The ASA will apply the actions from all matching class maps it finds for the feature type.
D. The ASA will apply the actions from only the last matching class map it finds for the feature type.

Answer: A

Explanation/Reference:
BD
I suppose this could be an explanation. Not 100% confident about this. The explanation refers to an interface, but the question doesn't specify that.
See the following information for how a packet matches class maps in a policy map for a given interface:
1. A packet can match only one class map in the policy map for each feature type.
2. When the packet matches a class map for a feature type, the ASA does not attempt to match it to any subsequent class maps for that feature type.
3. If the packet matches a subsequent class map for a different feature type, however, then the ASA also applies the actions for the subsequent class map, if supported. See the "Incompatibility of Certain Feature Actions" section for more information about unsupported combinations.
If a packet matches a class map for connection limits, and also matches a class map for an application inspection, then both actions are applied.
If a packet matches a class map for HTTP inspection, but also matches another class map that includes HTTP inspection, then the second class map actions are not applied.
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa84/configuration/guide/asa_84_cli_config/ mpf_service_policy.html

 

Q53	
For what reason would you configure multiple security contexts on the ASA firewall?

A. To separate different departments and business units.
B. To enable the use of VRFs on routers that are adjacently connected.
C. To provide redundancy and high availability within the organization.
D. To enable the use of multicast routing and QoS through the firewall.

Answer: A

Explanation/Reference:
BD
You can partition a single ASA into multiple virtual devices, known as security contexts. Each context is an independent device, with its own security policy, interfaces, and administrators. Multiple contexts are similar to having multiple standalone devices.
Common Uses for Security Contexts
+ You are a service provider and want to sell security services to many customers. By enabling multiple security contexts on the ASA, you can implement a cost-effective, space-saving solution that keeps all customer traffic separate and secure, and also eases configuration.
+ You are a large enterprise or a college campus and want to keep departments completely separate.
+ You are an enterprise that wants to provide distinct security policies to different departments.
+ You have any network that requires more than one ASA.
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa84/configuration/guide/asa_84_cli_config/ mode_contexts.html

 

Q54	
What is an advantage of placing an IPS on the inside of a network?

A. It can provide higher throughput.
B. It receives traffic that has already been filtered.
C. It receives every inbound packet.
D. It can provide greater security.

Answer: B

Explanation/Reference:
BD
Firewalls are generally designed to be on the network perimeter and can handle dropping a lot of the non- legitimate traffic (attacks, scans etc.) very quickly at the ingress interface, often in hardware.
An IDS/IPS is, generally speaking, doing more deep packet inspections and that is a much more computationally expensive undertaking. For that reason, we prefer to filter what gets to it with the firewall line of defense before engaging the IDS/IPS to analyze the traffic flow.
In an even more protected environment, we would also put a first line of defense in ACLs on an edge router between the firewall and the public network(s).
Source: https://supportforums.cisco.com/discussion/12428821/correct-placement-idsips-network-architecture

 

Q55	
What is the FirePOWER impact flag used for?

A. A value that indicates the potential severity of an attack.
B. A value that the administrator assigns to each signature.
C. A value that sets the priority of a signature.
D. A value that measures the application awareness.

Answer: A

Explanation/Reference:
BD
Impact Flag: Choose the impact level assigned to the intrusion event .
Because no operating system information is available for hosts added to the network map from NetFlow data, the system cannot assign Vulnerable (impact level 1: red) impact levels for intrusion events involving those hosts. In such cases, use the host input feature to manually set the operating system identity for the hosts.
Source: http://www.cisco.com/c/en/us/td/docs/security/firepower/60/configuration/guide/fpmc-config-guide-v60/ Correlation_Policies.html
Impact
The impact level in this field indicates the correlation between intrusion data, network discovery data, and vulnerability information.
Impact Flag
See Impact.
Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower- module-user-guide-v541/ViewingEvents.html

 

Q56	
Which FirePOWER preprocessor engine is used to prevent SYN attacks?

A. Rate-Based Prevention
B. Portscan Detection
C. IP Defragmentation
D. Inline Normalization

Answer: A

Explanation/Reference:
Brad

 A

Confidence level: 0%

Note: Never bothered to research this question.

BD

Rate-based attack prevention identifies abnormal traffic patterns and attempts to minimize the impact of that traffic on legitimate requests. Rate-based attacks usually have one of the following characteristics:
+ any traffic containing excessive incomplete connections to hosts on the network, indicating a SYN flood attack
+ any traffic containing excessive complete connections to hosts on the network, indicating a TCP/IP connection flood attack
+ excessive rule matches in traffic going to a particular destination IP address or addresses or coming from a particular source IP address or addresses.
+ excessive matches for a particular rule across all traffic.

Preventing SYN Attacks

The SYN attack prevention option helps you protect your network hosts against SYN floods. You can protect individual hosts or whole networks based on the number of packets seen over a period of time. If your device is deployed passively, you can generate events. If your device is placed inline, you can also drop the malicious packets. After the timeout period elapses, if the rate condition has stopped, the event generation and packet dropping stops.

Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower- module-user-guide-v541/Intrusion-Threat-Detection.html

Q57	
Which Sourcefire logging action should you choose to record the most detail about a connection?

A. Enable logging at the end of the session.
B. Enable logging at the beginning of the session.
C. Enable alerts via SNMP to log events off-box.
D. Enable eStreamer to log events off-box.

Answer: A

Explanation/Reference:
BD
FirePOWER (former Sourcefire)
Logging the Beginning And End of Connections
When the system detects a connection, in most cases you can log it at its beginning and its end.
For a single non-blocked connection, the end-of-connection event contains all of the information in the beginning-of-connection event, as well as information gathered over the duration of the session.
Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower- module-user-guide-v541/AC-Connection-Logging.html#15726

 

Q58	
What can the SMTP preprocessor in FirePOWER normalize?

A. It can extract and decode email attachments in client to server traffic.
B. It can look up the email sender.
C. It compares known threats to the email sender.
D. It can forward the SMTP traffic to an email filter server.
E. It uses the Traffic Anomaly Detector.

Answer: A

Explanation/Reference:
BD
Decoding SMTP Traffic
The SMTP preprocessor instructs the rules engine to normalize SMTP commands. The preprocessor can also extract and decode email attachments in client-to-server traffic and, depending on the software version, extract email file names, addresses, and header data to provide context when displaying intrusion events triggered by SMTP traffic.
Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower- module-user-guide-v541/NAP-App-Layer.html#85623

 

Q59	
You want to allow all of your company's users to access the Internet without allowing other Web servers to collect the IP addresses of individual users.
What two solutions can you use? (Choose two).

A. Configure a proxy server to hide users' local IP addresses.
B. Assign unique IP addresses to all users.
C. Assign the same IP address to all users.
D. Install a Web content filter to hide users' local IP addresses.
E. Configure a firewall to use Port Address Translation.

Answer: AE

Explanation/Reference:
BD
In computer networks, a proxy server is a server (a computer system or an application) that acts as an intermediary for requests from clients seeking resources from other servers.[1] A client connects to the proxy server, requesting some service, such as a file, connection, web page, or other resource available from a different server and the proxy server evaluates the request as a way to simplify and control its complexity.
Proxies were invented to add structure and encapsulation to distributed systems.[2] Today, most proxies are web proxies, facilitating access to content on the World Wide Web and providing anonymity.
Source: https://en.wikipedia.org/wiki/Proxy_server
Port Address Translation (PAT) is a subset of NAT, and it is still swapping out the source IP address as traffic goes through the NAT/PAT device, except with PAT everyone does not get their own unique translated address. Instead, the PAT device keeps track of individual sessions based on port numbers and other unique identifiers, and then forwards all packets using a single source IP address, which is shared. This is often referred to as NAT with overload; we are hiding multiple IP addresses on a single global address.
Source: Cisco Official Certification Guide, Port Address Translation, p.368

 

Q60	
You have implemented a Sourcefire IPS and configured it to block certain addresses utilizing Security Intelligence IP Address Reputation. A user calls and is not able to access a certain IP address. What action can you take to allow the user access to the IP address?

A. Create a custom blacklist to allow traffic
B. Create a whitelist and add the appropriate IP address to allow traffic
C. Create a user-based access control rule to allow the traffic
D. Create a network-based access control rule to allow the traffic
E. Create a rule to bypass inspection to allow the traffic

Answer: B

Explanation/Reference:
Brad

 B

Confidence level: 100%

Remember: Blacklists are created to block traffic, not allow

BD

Using Security Intelligence Whitelists

In addition to a blacklist, each access control policy has an associated whitelist, which you can also populate with Security Intelligence objects. A policy's whitelist overrides its blacklist. That is, the system evaluates traffic with a whitelisted source or destination IP address using access control rules, even if the IP address is also blacklisted. In general, use the whitelist if a blacklist is still useful, but is too broad in scope and incorrectly blocks traffic that you want to inspect.

Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/user-guide/FireSIGHT-System-UserGuide- v5401/AC-Secint-Blacklisting.pdf

Q61	
A specific URL has been identified as containing malware. What action can you take to block users from accidentally visiting the URL and becoming infected with malware.

A. Enable URL filtering on the perimeter firewall and add the URLs you want to allow to the router's local URL list
B. Enable URL filtering on the perimeter router and add the URLs you want to allow to the firewall's local URL list
C. Create a blacklist that contains the URL you want to block and activate the blacklist on the perimeter router
D. Enable URL filtering on the perimeter router and add the URLs you want to block to the router's local URL list
E. Create a whitelist that contains the URLs you want to allow and activate the whitelist on the perimeter router 

Answer: D

Explanation/Reference:
Brad

 D

Confidence level: 100%

Remember: A and B are not correct answers because you cannot use a router's URL list to filter URLs on a firewall, and vice versa. E is not correct because whitelists are used to allow websites, not block, and that is not what the question is asking for.

BD

URL Filtering

URL filtering allows you to control access to Internet websites by permitting or denying access to specific websites based on information contained in an URL list. You can maintain a local URL list on the router. If the Cisco IOS image on the router supports URL filtering but does not support Zone-based Policy Firewall (ZPF), you can maintain one local URL list on the router to add or edit an URLs. Enter a full domain name or a partial domain name and choose whether to Permit or Deny requests for this URL.

Source: http://www.cisco.com/c/en/us/td/docs/routers/access/cisco_router_and_security_device_manager/24/ software/user/guide/URLftr.html#wp999509

Q62	
When is the best time to perform an antivirus signature update?

A. Every time a new update is available.
B. When the local scanner has detected a new virus.
C. When a new virus is discovered in the wild.
D. When the system detects a browser hook.

Answer: A

Explanation/Reference:
BD
Obvious answer
More reading here
Source: http://www.techrepublic.com/article/four-steps-to-keeping-current-with-antivirus-signature-updates/

 

Q63	
Which statement about application blocking is true?

A. It blocks access to specific programs.
B. It blocks access to files with specific extensions.
C. It blocks access to specific network addresses.
D. It blocks access to specific network services.

Answer: A

Explanation/Reference:
BD
How do you block unknown applications on Cisco Web Security Appliance If Application Visibility Controls (AVC) are enabled (Under GUI > Security Services > Web Reputation and Anti- Malware), then we can block access based on application types like Proxies, File Sharing, Internet utilities.
We can do this under Web Security Manager > Access Policies > 'Applications' column <for the required access policy>.
Source: http://www.cisco.com/c/en/us/support/docs/security/web-security-appliance/118486-technote-wsa- 00.html

 

Q64	
What features can protect the data plane? (Choose three.)

A. policing
B. ACLs
C. IPS
D. antispoofing
E. QoS
F. DHCP-snooping

Answer: BDF

Explanation/Reference:
BD
+ Block unwanted traffic at the router. If your corporate policy does not allow TFTP traffic, just implement ACLs that deny traffic that is not allowed.
+ Reduce spoofing attacks. For example, you can filter (deny) packets trying to enter your network (from the outside) that claim to have a source IP address that is from your internal network.
+ Dynamic Host Configuration Protocol (DHCP) snooping to prevent a rogue DHCP server from handing out incorrect default gateway information and to protect a DHCP server from a starvation attack Source: Cisco Official Certification Guide, Best Practices for Protecting the Data Plane , p.271

 

Q65	
How many crypto map sets can you apply to a router interface?

A. 3
B. 2
C. 4
D. 1

Answer: D

Explanation/Reference:
BD
You must assign a crypto map set to an interface before that interface can provide IPSec services. Only one crypto map set can be assigned to an interface. If multiple crypto map entries have the same map-name but a different seq-num, they are considered to be part of the same set and will all be applied to the interface.
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/command

Explanation/Reference/srfipsec.html#wp1018126

 

Q66	
What is the transition order of STP states on a Layer 2 switch interface?

A. listening, learning, blocking, forwarding, disabled
B. listening, blocking, learning, forwarding, disabled
C. blocking, listening, learning, forwarding, disabled
D. forwarding, listening, learning, blocking, disabled

Answer: C

Explanation/Reference:
BD
STP switch port states:
+ Blocking - A port that would cause a switching loop if it were active. No user data is sent or received over a blocking port, but it may go into forwarding mode if the other links in use fail and the spanning tree algorithm determines the port may transition to the forwarding state. BPDU data is still received in blocking state.
Prevents the use of looped paths.
+ Listening - The switch processes BPDUs and awaits possible new information that would cause it to return to the blocking state. It does not populate the MAC address table and it does not forward frames.
+ Learning - While the port does not yet forward frames it does learn source addresses from frames received and adds them to the filtering database (switching database). It populates the MAC address table, but does not forward frames.
+ Forwarding - A port receiving and sending data, normal operation. STP still monitors incoming BPDUs that would indicate it should return to the blocking state to prevent a loop.
+ Disabled - Not strictly part of STP, a network administrator can manually disable a port Source: https://en.wikipedia.org/wiki/Spanning_Tree_Protocol

 

Q67	
Which sensor mode can deny attackers inline?

A. IPS
B. fail-close
C. IDS
D. fail-open

Answer: A

Explanation/Reference:
BD
Deny attacker inline: This action denies packets from the source IP address of the attacker for a configurable duration of time, after which the deny action can be dynamically removed.
Available only if the sensor is configured as an IPS.
Source: Cisco Official Certification Guide, Table 17-4 Possible Sensor Responses to Detected Attacks , p.465

 

Q68	
Which options are filtering options used to display SDEE message types? (Choose two.)

A. stop
B. none
C. error
D. all

Answer: CD

Explanation/Reference:
BD
SDEE Messages
+ All -- SDEE error, status, and alert messages are shown.
+ Error -- Only SDEE error messages are shown.
+ Status -- Only SDEE status messages are shown.
+ Alerts -- Only SDEE alert messages are shown.
Source: http://www.cisco.com/c/en/us/td/docs/routers/access/cisco_router_and_security_device_manager/24/ software/user/guide/IPS.html#wp1083698

 

Q69	
When a company puts a security policy in place, what is the effect on the company's business?

A. Minimizing risk
B. Minimizing total cost of ownership
C. Minimizing liability
D. Maximizing compliance

Answer: A

Explanation/Reference:
BD
The first step in protecting a business network is creating a security policy. A security policy is a formal, published document that defines roles, responsibilities, acceptable use, and key security practices for a company. It is a required component of a complete security framework, and it should be used to guide investment in security defenses.
Source: http://www.cisco.com/warp/public/cc/so/neso/sqso/secsol/setdm_wp.htm

 

Q70	
Which wildcard mask is associated with a subnet mask of /27?

A. 0.0.0.31
B. 0.0.0.27
C. 0.0.0.224
D. 0.0.0.255

Answer: A

Explanation/Reference:
BD
Slash Netmask Wildcard Mask
/27 255.255.255.224 0.0.0.31
Further reading
Source: https://en.wikipedia.org/wiki/Wildcard_mask

 

Q71	
Which statements about reflexive access lists are true? (Choose three.)

A. Reflexive access lists create a permanent ACE
B. Reflexive access lists approximate session filtering using the established keyword
C. Reflexive access lists can be attached to standard named IP ACLs
D. Reflexive access lists support UDP sessions
E. Reflexive access lists can be attached to extended named IP ACLs
F. Reflexive access lists support TCP sessions

Answer: DEF

Explanation/Reference:
BD
To define a reflexive access list, you use an entry in an extended named IP access list. This entry must use the reflect keyword.
A reflexive access list is triggered when a new IP upper-layer session (such as TCP or UDP) is initiated from inside your network, with a packet traveling to the external network.
Moreover, the previous method of using the established keyword was available only for the TCP upper- layer protocol. So, for the other upper-layer protocols (such as UDP, ICMP, and so forth), you would have to either permit all incoming traffic or define all possible permissible source/destination host/port address pairs for each protocol. (Besides being an unmanageable task, this could exhaust NVRAM space.) Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/configuration/guide/fsecur_c/ scfreflx.html#54908

 

Q72	
Which actions can a promiscuous IPS take to mitigate an attack? (Choose three.)

A. Reset the TCP connection
B. Request connection blocking
C. Deny packets
D. Modify packets
E. Request host blocking
F. Deny frames

Answer: ABE

Explanation/Reference:
Brad

 

A, B and E
Confidence level: 100%

Note: Be aware that there is a reverse version of this question, worded such as "What actions are limited when running IPS in promiscuous mode?".

BD

Promiscuous Mode Event Actions
+ Request block host: This event action will send an ARC request to block the host for a specified time frame, preventing any further communication. This is a severe action that is most appropriate when there is minimal chance of a false alarm or spoofing.
+ Request block connection: This action will send an ARC response to block the specific connection. This action is appropriate when there is potential for false alarms or spoofing. + Reset TCP connection: This action is TCP specific, and in instances where the attack requires several TCP packets, this can be a successful action.

Source: http://www.cisco.com/c/en/us/about/security-center/ips-mitigation.html#7

Q73	
Which command will configure a Cisco ASA firewall to authenticate users when they enter the enable syntax using the local database with no fallback method?

A. "aaa authentication enable console LOCAL SERVER_GROUP"
B. "aaa authentication enable console SERVER_GROUP LOCAL"
C. "aaa authentication enable console LOCAL"
D. "aaa authentication enable console local"

Answer: C

Explanation/Reference:
Brad

C

Confidence level: 100%

Remember: The local database must be referenced in all capital letters when AAA is in use. If lower case letters are used, the ASA will look for an AAA server group called "local".

Q74	
Which Cisco Security Manager application collects information about device status and uses it to generate notifications and alerts?

A. FlexConfig
B. Device Manager
C. Report Manager
D. Health and Performance Monitor

Answer: D

Explanation/Reference:
BD
Health and Performance Monitor (HPM) ­ Monitors and displays key health, performance and VPN data for ASA and IPS devices in your network. This information includes critical and non-critical issues, such as memory usage, interface status, dropped packets, tunnel status, and so on. You also can categorize devices for normal or priority monitoring, and set different alert rules for the priority devices.
Source: http://www.cisco.com/c/en/us/td/docs/security/security_management/cisco_security_manager/ security_manager/4-4/user/guide/CSMUserGuide_wrapper/HPMchap.pdf

 

Q75	
Which accounting notices are used to send a failed authentication attempt record to a AAA server? (Choose two.)

A. Stop
B. Stop-record
C. Stop-only
D. Start-stop

Answer: CD

Explanation/Reference:
Brad

C and D – agrees with egypt guy so this is what I have changed it to.
Confidence level: 50%

Note: This is a widely debated question and my research did not turn up a concrete answer. Some users on the securitytut forums have said that A is a correct answer.

BD

aaa accounting { auth-proxy | system | network | exec | connection | commands level | dot1x } { default | list- name | guarantee-first } [ vrf vrf-name ] { start-stop | stop-only | none } [broadcast] { radius | group group-name } + stop-only: Sends a stop accounting record for all cases including authentication failures regardless of whether the aaa accounting send stop-record authentication failure command is configured. + stop-record: Generates stop records for a specified event.

For minimal accounting, include the stop-only keyword to send a "stop" accounting record for all cases including authentication failures. For more accounting, you can include the start-stop keyword, so that RADIUS or TACACS+ sends a "start" accounting notice at the beginning of the requested process and a "stop" accounting notice at the end of the process.

Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-a1.html

On securitytut. com you can find a full description of the simulation test I did.



Q76	
Which command is needed to enable SSH support on a Cisco Router?

A. crypto key lock rsa
B. crypto key generate rsa
C. crypto key zeroize rsa
D. crypto key unlock rsa

Answer: B

Explanation/Reference:
BD
There are four steps required to enable SSH support on a Cisco IOS router:
+ Configure the hostname command.
+ Configure the DNS domain.
+ Generate the SSH key to be used.
+ Enable SSH transport support for the virtual type terminal (vtys).
!--- Step 1: Configure the hostname if you have not previously done so.
hostname carter
!--- The aaa new-model command causes the local username and password on the router !--- to be used in the absence of other AAA statements.
aaa new-model
username cisco password 0 cisco
!--- Step 2: Configure the DNS domain of the router.
ip domain-name rtp.cisco.com
!--- Step 3: Generate an SSH key to be used with SSH.
crypto key generate rsa
ip ssh time-out 60
ip ssh authentication-retries 2
!--- Step 4: By default the vtys' transport is Telnet. In this case, !--- Telnet is disabled and only SSH is supported.
line vty 0 4
transport input SSH
Source: http://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/4145- ssh.html#settingupaniosrouterasssh

 

Q77	
Which protocol provides security to Secure Copy?

A. IPsec
B. SSH
C. HTTPS
D. ESP

Answer: B

Explanation/Reference:
BD
The SCP is a network protocol, based on the BSD RCP protocol,[3] which supports file transfers between hosts on a network. SCP uses Secure Shell (SSH) for data transfer and uses the same mechanisms for authentication, thereby ensuring the authenticity and confidentiality of the data in transit.
Source: https://en.wikipedia.org/wiki/Secure_copy

 

Q78	
A clientless SSL VPN user who is connecting on a Windows Vista computer is missing the menu option for Remote Desktop Protocol on the portal web page. Which action should you take to begin troubleshooting?

A. Ensure that the RDP plug-in is installed on the VPN gateway
B. Ensure that the RDP2 plug-in is installed on the VPN gateway
C. Reboot the VPN gateway
D. Instruct the user to reconnect to the VPN gateway

Answer: B

Explanation/Reference:
Brad

 B

Confidence level: 100%

Note: This question has been verified by posters on securitytut who scored perfect scores on the exam. While it is fact that the newest version of the RDP plug-in is compatible with RDP2, this question specifically asks about Windows Vista. This is one of those "choose the best answer" scenarios.

BD

+ RDP plug-in: This is the original plug-in created that contains both the Java and ActiveX Client. + RDP2 plug-in: Due to changes within the RDP protocol, the Proper Java RDP Client was updated in order to support Microsoft Windows 2003 Terminal Servers and Windows Vista Terminal Servers.

Source: http://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation- firewalls/113600-technote-product-00.html

Q79	
Which security zone is automatically defined by the system?

A. The source zone
B. The self zone
C. The destination zone
D. The inside zone

Answer: B

Explanation/Reference:
BD
A zone is a logical area where devices with similar trust levels reside. For example, we could define a DMZ for devices in the DMZ in an organization. A zone is created by the administrator, and then interfaces can be assigned to zones. A zone can have one or more interfaces assigned to it. Any given interface can belong to only a single zone. There is a default zone, called the self zone, which is a logical zone.
Source: Cisco Official Certification Guide, Zones and Why We Need Pairs of Them, p.380

 

Q80	
What are purposes of the Internet Key Exchange in an IPsec VPN? (Choose two.)

A. The Internet Key Exchange protocol establishes security associations
B. The Internet Key Exchange protocol provides data confidentiality
C. The Internet Key Exchange protocol provides replay detection
D. The Internet Key Exchange protocol is responsible for mutual authentication 

Answer: AD

Explanation/Reference:
BD
IPsec uses the Internet Key Exchange (IKE) protocol to negotiate and establish secured site-to-site or remote access virtual private network (VPN) tunnels. IKE is a framework provided by the Internet Security Association and Key Management Protocol (ISAKMP) and parts of two other key management protocols, namely Oakley and Secure Key Exchange Mechanism (SKEME).
In IKE Phase 1 IPsec peers negotiate and authenticate each other. In Phase 2 they negotiate keying materials and algorithms for the encryption of the data being transferred over the IPsec tunnel.
Source: Cisco Official Certification Guide, The Internet Key Exchange (IKE) Protocol, p.123

 

Q81	
Which address block is reserved for locally assigned unique local addresses?

A. 2002::/16
B. 2001::/32
C. FD00::/8
D. FB00::/8

Answer: C

Explanation/Reference:
Brad

 C

Confidence level: 100%
Remember: Locally assigned IPv6 addresses begin at FC00

BD

The address block fc00::/7 is divided into two /8 groups:
+ The block fc00::/8 has not been defined yet. It has been proposed to be managed by an allocation authority, but this has not gained acceptance in the IETF
+ The block fd00::/8 is defined for /48 prefixes, formed by setting the 40 least-significant bits of the prefix to a randomly generated bit string

Prefixes in the fd00::/8 range have similar properties as those of the IPv4 private address ranges:
+ They are not allocated by an address registry and may be used in networks by anyone without outside involvement.
+ They are not guaranteed to be globally unique.
+ Reverse Domain Name System (DNS) entries (under ip6.arpa) for fd00::/8 ULAs cannot be delegated in the global DNS.

Source: https://en.wikipedia.org/wiki/Unique_local_address

Q82	
What is a possible reason for the error message?

Router(config)#aaa server?% Unrecognized command

A. The command syntax requires a space after the word "server"
B. The command is invalid on the target device
C. The router is already running the latest operating system
D. The router is a new device on which the aaa new-model command must be applied before continuing 

Answer: D

Explanation/Reference:
BD
Before you can use any of the services AAA network security services provide, you must enable AAA.
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/configuration/guide/fsecur_c/scfaaa.html

 

Q83	
Which statements about smart tunnels on a Cisco firewall are true? (Choose two.)

A. Smart tunnels can be used by clients that do not have administrator privileges
B. Smart tunnels require the client to have the application installed locally
C. Smart tunnels offer better performance than port forwarding
D. Smart tunnels support all operating systems

Answer: AC

Explanation/Reference:
Brad
A and C
Confidence level: 90%

Note: Some dumps list B as a correct choice however, Smart tunnels are clientless, which is why I am pretty sure B is an incorrect answer.

BD

Smart Tunnel is an advanced feature of Clientless SSL VPN that provides seamless and highly secure remote access for native client-server applications.
Clientless SSL VPN with Smart Tunnel is the preferred solution for allowing access from non-corporate assets as it does not require the administrative rights.
Port forwarding is the legacy technology for supporting TCP based applications over a Clientless SSL VPN connection. Unlike port forwarding, Smart Tunnel simplifies the user experience by not requiring the user connection of the local application to the local port.

Source: http://www.cisco.com/c/dam/en/us/solutions/collateral/enterprise/design-zone-security/tunnel.pdf

Q84	
If the native VLAN on a trunk is different on each end of the link, what is a potential consequence?

A. The interface on both switches may shut down
B. STP loops may occur
C. The switch with the higher native VLAN may shut down
D. The interface with the lower native VLAN may shut down

Answer: B

Explanation/Reference:
BD
Source: https://learningnetwork.cisco.com/docs/DOC-25797
http://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/24063-pvid-inconsistency- 24063.html

 

Q85	
Which option describes information that must be considered when you apply an access list to a physical interface?

A. Protocol used for filtering
B. Direction of the access class
C. Direction of the access group
D. Direction of the access list

Answer: C

Explanation/Reference:
BD
Applying an Access List to an Interface
#interface type number
#ip access-group {access-list-number | access-list-name} { in | out} Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-3s/sec-data-acl-xe-3s- book/sec-create-ip-apply.html

 

Q86	
Which source port does IKE use when NAT has been detected between two VPN gateways?

A. TCP 4500
B. TCP 500
C. UDP 4500
D. UDP 500

Answer: C

Explanation/Reference:
BD
The IKE protocol uses UDP packets, usually on port 500
NAT traversal: The encapsulation of IKE and ESP in UDP port 4500 enables these protocols to pass through a device or firewall performing NAT
Source: https://en.wikipedia.org/wiki/Internet_Key_Exchange

 

Q87	
Which of the following are features of IPsec transport mode? (Choose three.)

A. IPsec transport mode is used between gateways
B. IPsec transport mode is used between end stations
C. IPsec transport mode supports multicast
D. IPsec transport mode supports unicast
E. IPsec transport mode encrypts only the payload
F. IPsec transport mode encrypts the entire packet

Answer: BDE

Explanation/Reference:
Brad

 

 B, D and E
Confidence level: 100%

Note: Be aware that there is a reverse version of this question, worded such as "Which of the following are features of IPsec tunnel mode?".

BD

+ IPSec Transport mode is used for end-to-end communications, for example, for communication between a client and a server or between a workstation and a gateway (if the gateway is being treated as a host). A good example would be an encrypted Telnet or Remote Desktop session from a workstation to a server. + IPsec supports two encryption modes: Transport mode and Tunnel mode. Transport mode encrypts only the data portion (payload) of each packet and leaves the packet header untouched. Transport mode is applicable to either gateway or host implementations, and provides protection for upper layer protocols as well as selected IP header fields.

Source: http://www.firewall.cx/networking-topics/protocols/870-ipsec-modes.html http://www.cisco.com/c/en/us/td/docs/net_mgmt/vpn_solutions_center/2-0/ip_security/provisioning/guide/ IPsecPG1.html

Generic Routing Encapsulation (GRE) is often deployed with IPsec for several reasons, including the following:
+ IPsec Direct Encapsulation supports unicast IP only. If network layer protocols other than IP are to be supported, an IP encapsulation method must be chosen so that those protocols can be transported in IP packets.
+ IPmc is not supported with IPsec Direct Encapsulation. IPsec was created to be a security protocol between two and only two devices, so a service such as multicast is problematic. An IPsec peer encrypts a packet so that only one other IPsec peer can successfully perform the de-encryption. IPmc is not compatible with this mode of operation.

Source: https://www.cisco.com/application/pdf/en/us/guest/netsol/ns171/c649/ ccmigration_09186a008074f26a.pdf

Q88	
Which command causes a Layer 2 switch interface to operate as a Layer 3 interface?

A. no switchport nonnegotiate
B. switchport
C. no switchport mode dynamic auto
D. no switchport

Answer: D

Explanation/Reference:
BD
The no switchport command makes the interface Layer 3 capable.
Source: http://www.cisco.com/c/en/us/support/docs/lan-switching/inter-vlan-routing/41860-howto-L3- intervlanrouting.html

 

Q89	
Which TACACS+ server-authentication protocols are supported on Cisco ASA firewalls? (Choose three.)

A. EAP
B. ASCII
C. PAP
D. PEAP
E. MS-CHAPv1
F. MS-CHAPv2

Answer: BCE

Explanation/Reference:
BD
The ASA supports TACACS+ server authentication with the following protocols: ASCII, PAP, CHAP, and MS- CHAPv1.
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa91/configuration/general/asa_91_general_config/ aaa_tacacs.pdf

 

Q90	
Which type of IPS can identify worms that are propagating in a network?

A. Policy-based IPS
B. Anomaly-based IPS
C. Reputation-based IPS
D. Signature-based IPS

Answer: B

Explanation/Reference:
BD
An example of anomaly-based IPS/IDS is creating a baseline of how many TCP sender requests are generated on average each minute that do not get a response. This is an example of a half-opened session. If a system creates a baseline of this (and for this discussion, let's pretend the baseline is an average of 30 half- opened sessions per minute), and then notices the half-opened sessions have increased to more than 100 per minute, and then acts based on that and generates an alert or begins to deny packets, this is an example of anomaly-based IPS/IDS. The Cisco IPS/IDS appliances have this ability (called anomaly detection), and it is used to identify worms that may be propagating through the network.
Source: Cisco Official Certification Guide, Anomaly-Based IPS/IDS, p.464

 

Q91	
Which command verifies phase 1 of an IPsec VPN on a Cisco router?

A. show crypto map
B. show crypto ipsec sa
C. show crypto isakmp sa
D. show crypto engine connection active

Answer: C

Explanation/Reference:
Brad
Confidence level: 100%

Remember: Commands using the term "isakmp" refer to IKE phase 1. Commands using "ipsec" refer to phase 2.

BD

A show crypto isakmp sa command shows the ISAKMP SA to be in MM_NO_STATE. This also means that main mode has failed.

Dst		src 		state 		  conn-id 	slot
10.1.1.2 	10.1.1.1 	MM_NO_STATE  1 		0

Verify that the phase 1 policy is on both peers, and ensure that all the attributes match.

Source: http://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/5409-ipsec- debug-00.html#isakmp_sa

Q92	
What is the purpose of a honeypot IPS?

A. To create customized policies
B. To detect unknown attacks
C. To normalize streams
D. To collect information about attacks

Answer: D

Explanation/Reference:
BD
Honeypot systems use a dummy server to attract attacks. The purpose of the honeypot approach is to distract attacks away from real network devices. By staging different types of vulnerabilities in the honeypot server, you can analyze incoming types of attacks and malicious traffic patterns.
Source: http://www.ciscopress.com/articles/article.asp?p=1336425

 

Q93	
Which type of firewall can act on the behalf of the end device?

A. Stateful packet
B. Application
C. Packet
D. Proxy

Answer: D

Explanation/Reference:
BD
Application firewalls, as indicated by the name, work at Layer 7, or the application layer of the OSI model.
These devices act on behalf of a client (aka proxy) for requested services.
Because application/proxy firewalls act on behalf of a client, they provide an additional "buffer" from port scans, application attacks, and so on. For example, if an attacker found a vulnerability in an application, the attacker would have to compromise the application/proxy firewall before attacking devices behind the firewall. The application/proxy firewall can also be patched quickly in the event that a vulnerability is discovered. The same may not hold true for patching all the internal devices.
Source: http://www.networkworld.com/article/2255950/lan-wan/chapter-1--types-of-firewalls.html

 

Q94	
Which syslog severity level is level number 7?

A. Warning
B. Informational
C. Notification
D. Debugging

Answer: D

Explanation/Reference:
Brad

 D

Confidence level: 100%

Remember: There is a mnemonic device for remembering the order of the eight syslog levels:

"Every Awesome Cisco Engineer Will Need Icecream Daily"

0 - Emergency
1 - Alert
2 - Critical
3 - Error
4 - Warning
5 - Notification
6 - Informational
7 - Debugging

Q95	
By which kind of threat is the victim tricked into entering username and password information at a disguised website?

A. Spoofing
B. Malware
C. Spam
D. Phishing

Answer: D

Explanation/Reference:
BD
Phishing presents a link that looks like a valid trusted resource to a user. When the user clicks it, the user is prompted to disclose confidential information such as usernames/passwords.
Source: Cisco Official Certification Guide, Table 1-5 Attack Methods, p.13

 

Q96	
Which type of mirroring does SPAN technology perform?

A. Remote mirroring over Layer 2
B. Remote mirroring over Layer 3
C. Local mirroring over Layer 2
D. Local mirroring over Layer 3

Answer: C

Explanation/Reference:
BD
You can analyze network traffic passing through ports or VLANs by using SPAN or RSPAN to send a copy of the traffic to another port on the switch or on another switch that has been connected to a network analyzer or other monitoring or security device.
Local SPAN supports a SPAN session entirely within one switch; all source ports or source VLANs and destination ports are in the same switch or switch stack.
Each local SPAN session or RSPAN destination session must have a destination port (also called a monitoring port) that receives a copy of traffic from the source ports or VLANs and sends the SPAN packets to the user, usually a network analyzer:
+ If ingress traffic forwarding is enabled for a network security device, the destination port forwards traffic at Layer 2.
Source: http://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/12-2_55_se/ configuration/guide/scg_2960/swspan.html

 

Q97	
Which tasks is the session management path responsible for? (Choose three.)

A. Verifying IP checksums
B. Performing route lookup
C. Performing session lookup
D. Allocating NAT translations
E. Checking TCP sequence numbers
F. Checking packets against the access list

Answer: BDF

Explanation/Reference:
BD
The ASA has to check the packet against access lists and perform other tasks to determine if the packet is allowed or denied. To perform this check, the first packet of the session goes through the " session management path," and depending on the type of traffic, it might also pass through the "control plane path." The session management path is responsible for the following tasks:
+ Performing the access list checks
+ Performing route lookups
+ Allocating NAT translations (xlates)
+ Establishing sessions in the "fast path"
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa82/configuration/guide/config/intro.html

 

Q98	
Which network device does NTP authenticate?

A. Only the time source
B. Only the client device
C. The firewall and the client device
D. The client device and the time source

Answer: A

Explanation/Reference:
BD
You can configure the device to authenticate the time sources to which the local clock is synchronized. When you enable NTP authentication, the device synchronizes to a time source only if the source carries one of the authentication keys specified by the ntp trusted-key command. The device drops any packets that fail the authentication check and prevents them from updating the local clock. NTP authentication is disabled by default.
Source: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/sw/5_x/nx-os/system_management/ configuration/guide/sm_nx_os_cg/sm_3ntp.html#wp1100303%0A

 

Q99	
Which Cisco product can help mitigate web-based attacks within a network?

A. Adaptive Security Appliance
B. Email Security Appliance
C. Identity Security Appliance
D. Web Security Appliance

Answer: D

Explanation/Reference:
Brad

 D

Confidence level: 0%

Note: Never bothered to research this question.

BD

Web-based threats continue to rise. To protect your network you need a solution that prevents them. Cisco Advanced Malware Protection (AMP) for Web Security goes beyond the basics in threat detection, URL filtering, and application control. It provides continuous file analysis, retrospective security, and sandboxing to help your security team catch even the stealthiest threats.

Source: http://www.cisco.com/c/en/us/products/security/advanced-malware-protection/amp-for-web- security.html


Q100	
Which statement correctly describes the function of a private VLAN?

A. A private VLAN partitions the Layer 2 broadcast domain of a VLAN into subdomains
B. A private VLAN partitions the Layer 3 broadcast domain of a VLAN into subdomains
C. A private VLAN enables the creation of multiple VLANs using one broadcast domain
D. A private VLAN combines the Layer 2 broadcast domains of many VLANs into one major broadcast domain 

Answer: A

Explanation/Reference:
BD
Private VLAN divides a VLAN (Primary) into sub-VLANs (Secondary) while keeping existing IP subnet and layer 3 configuration. A regular VLAN is a single broadcast domain, while private VLAN partitions one broadcast domain into multiple smaller broadcast subdomains.
Source: https://en.wikipedia.org/wiki/Private_VLAN

 

Q101	
What hash type does Cisco use to validate the integrity of downloaded images?

A. Sha1
B. Sha2
C. MD5
D. Md1

Answer: C

Explanation/Reference:
BD
The MD5 File Validation feature, added in Cisco IOS Software Releases 12.2(4)T and 12.0(22)S, allows network administrators to calculate the MD5 hash of a Cisco IOS software image file that is loaded on a device.
It also allows administrators to verify the calculated MD5 hash against that provided by the user. Once the MD5 hash value of the installed Cisco IOS image is determined, it can also be compared with the MD5 hash provided by Cisco to verify the integrity of the image file.
verify /md5 filesystem:filename [md5-hash]
Source: http://www.cisco.com/c/en/us/about/security-center/ios-image-verification.html#11

 

Q102	
Which Cisco feature can help mitigate spoofing attacks by verifying symmetry of the traffic path?

A. Unidirectional Link Detection
B. Unicast Reverse Path Forwarding
C. TrustSec
D. IP Source Guard

Answer: B

Explanation/Reference:
BD
Unicast Reverse Path Forwarding (uRPF) can mitigate spoofed IP packets. When this feature is enabled on an interface, as packets enter that interface the router spends an extra moment considering the source address of the packet. It then considers its own routing table, and if the routing table does not agree that the interface that just received this packet is also the best egress interface to use for forwarding to the source address of the packet, it then denies the packet.
This is a good way to limit IP spoofing.
Source: Cisco Official Certification Guide, Table 10-4 Protecting the Data Plane, p.270

 

Q103	
What is the most common Cisco Discovery Protocol version 1 attack?

A. Denial of Service
B. MAC-address spoofing
C. CAM-table overflow
D. VLAN hopping

Answer: A

Explanation/Reference:
BD
CDP contains information about the network device, such as the software version, IP address, platform, capabilities, and the native VLAN. When this information is available to an attacker computer, the attacker from that computer can use it to find exploits to attack your network, usually in the form of a Denial of Service (DoS) attack.
Source: https://howdoesinternetwork.com/2011/cdp-attack

 

Q104	
What is the Cisco preferred countermeasure to mitigate CAM overflows?

A. Port security
B. Root guard
C. IP source guard
D. Dynamic port security

Answer: D

Explanation/Reference:
Brad

 D

Confidence level: 75%

Note: According to multiple links, port security is used to mitigate CAM overflow attacks. However, I found the following statement on a Cisco page: "A more administratively scalable solution is the implementation of dynamic port security at the switch". Because of this, I believe the verbiage "Cisco preferred" would point to answer D.

Brad's source link (maybe): http://www.cisco.com/c/en/us/support/docs/switches/catalyst-3750-series- switches/72846-layer2-secftrs-catl3fixed.html

BD
User @Answer on securitytut.com considers A. as the correct answer.

Q105	
Which option is the most effective placement of an IPS device within the infrastructure?

A. Inline, behind the internet router and firewall
B. Inline, before the internet router and firewall
C. Promiscuously, after the Internet router and before the firewall
D. Promiscuously, before the Internet router and the firewall

Answer: A

Explanation/Reference:
BD
Firewalls are generally designed to be on the network perimeter and can handle dropping a lot of the non- legitimate traffic (attacks, scans etc.) very quickly at the ingress interface, often in hardware.
An IDS/IPS is, generally speaking, doing more deep packet inspections and that is a much more computationally expensive undertaking. For that reason, we prefer to filter what gets to it with the firewall line of defense before engaging the IDS/IPS to analyze the traffic flow.
Source: https://supportforums.cisco.com/discussion/12428821/correct-placement-idsips-network-architecture

 

Q106	
If a router configuration includes the line aaa authentication login default group tacacs+ enable, which events will occur when the TACACS+ server returns an error? (Choose two.)

A. Authentication attempts to the router will be denied
B. The user will be prompted to authenticate using the enable password
C. Authentication will use the router's local database
D. Authentication attempts will be sent to the TACACS+ server

Answer: BD

Explanation/Reference:
Brad

B and C
Confidence level: 60%

Notes: This is a widely debated question. See below:

- D is known incorrect. The router will eventually attempt to communicate with the TACACS server again, but not immediately.

- We know B is correct based on the command line

- Cisco devices store the enable password locally, and default behavior is for Cisco devices to fallback to local authentication when a TACACS/Radius server is down or returns an error. This is why I choose answer C.

- A user on the securitytut forums said that they labbed this scenario up and that A is a correct answer, not C. I have no way of verifying whether that user made a mistake or not, so I am sticking with the answer my research turned up.

BD

Two things I need to say. One, local database has nothing to do with enable secret/password as it is literally created using username/password command combinations. Second there is no fallback safety failover with aaa if you specify exact methods. Those exact methods are the only methods used, nothing else.

On the previous post I pasted an output for the authentication process with TACACS+ and enable. At a point there was a timeout message which resulted in switching to the second authentication method, ENABLE. "Use the timeout integer argument to specify the period of time (in seconds) the router will wait for a response from the daemon before it times out and declares an error."
As a reference I used http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/configuration/guide/fsecur_c/ scftplus.html

What concerns me is ,,If an ERROR response is received, the network access server will typically try to use an alternative method for authenticating the user." It doesn't specifically say ,,The router retries to connect with the TACACS+".

Q107	
Which alert protocol is used with Cisco IPS Manager Express to support up to 10 sensors?

A. SDEE
B. Syslog
C. SNMP
D. CSM

Answer: A

Explanation/Reference:
BD
IPS produces various types of events including intrusion alerts and status events. IPS communicates events to clients such as management applications using the proprietary RDEP2. We have also developed an IPS- industry leading protocol, SDEE, which is a product-independent standard for communicating security device events. SDEE is an enhancement to the current version of RDEP2 that adds extensibility features that are needed for communicating events generated by various types of security devices.
Source: http://www.cisco.com/c/en/us/td/docs/security/ips/6-1/configuration/guide/ime/imeguide/ ime_system_architecture.html

 

Q108	
When a switch has multiple links connected to a downstream switch, what is the first step that STP takes to prevent loops?

A. STP elects the root bridge
B. STP selects the root port
C. STP selects the designated port
D. STP blocks one of the ports

Answer: A

Explanation/Reference:
BD
First when the switches are powered on all the ports are in Blocking state (20 sec), during this time the + Root Bridge is elected by exchanging BPDUs
+ The other switches will elect their Root ports
+ Every network segment will choosee their Designated port
Source: https://learningnetwork.cisco.com/thread/7677

 

Q109	
Which components does HMAC use to determine the authenticity and integrity of a message? (Choose two.)

A. The password
B. The hash
C. The key
D. The transform set

Answer: BC

Explanation/Reference:
BD
In cryptography, a keyed-hash message authentication code (HMAC) is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and the authentication of a message.
Source: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code

 

Q110	
What is the default timeout interval during which a router waits for responses from a TACACS server before declaring a timeout failure?

A. 5 seconds
B. 10 seconds
C. 15 seconds
D. 20 seconds

Answer: A

Explanation/Reference:
BD
To set the interval for which the server waits for a server host to reply, use the tacacs-server timeout command in global configuration mode. To restore the default, use the no form of this command.
If the command is not configured, the timeout interval is 5.
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/command

Explanation/Reference/srftacs.html

 

Q111	
Which RADIUS server authentication protocols are supported on Cisco ASA firewalls? (Choose three.)

A. EAP
B. ASCII
C. PAP
D. PEAP
E. MS-CHAPv1
F. MS-CHAPv2

Answer: CEF

Explanation/Reference:
BD
The ASA supports the following authentication methods with RADIUS servers:
+ PAP -- For all connection types.
+ CHAP and MS-CHAPv1 -- For L2TP-over-IPsec connections.
+ MS-CHAPv2 - For L2TP-over-IPsec connections
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa91/asdm71/general/asdm_71_general_config/ aaa_radius.pdf
There is an alternate version of this question that replaces RADIUS with TACACS. In that case, B is correct and F is not.

 

Q112	
Which command initializes a lawful intercept view?

A. username cisco1 view lawful-intercept password cisco
B. parser view cisco li-view
C. li-view cisco user cisco1 password cisco
D. parser view li-view inclusive

Answer: C

Explanation/Reference:
BD
Like a CLI view, a lawful intercept view restricts access to specified commands and configuration information.
Specifically, a lawful intercept view allows a user to secure access to lawful intercept commands that are held within the TAP-MIB, which is a special set of simple network management protocol (SNMP) commands that store information about calls and users.
#li-view li-password user username password password
Source: http://www.cisco.com/en/US/docs/ios/12_3t/12_3t7/feature/guide/gtclivws.html

Before you initialize a lawful intercept view, ensure that the privilege level is set to 15 via the privilege command.
SUMMARY STEPS
1. enable view
2. configure terminal
3. li-view li-password user username password password
4. username lawful-intercept [name] [privilege privilege-level| view view-name] password password
5. parser view view-name
6. secret 5 encrypted-password
7. name new-name

 

Q113	
Which countermeasures can mitigate ARP spoofing attacks? (Choose two.)

A. Port security
B. DHCP snooping
C. IP source guard
D. Dynamic ARP inspection

Answer: BD

Explanation/Reference:
BD
+ ARP spoofing attacks and ARP cache poisoning can occur because ARP allows a gratuitous reply from a host even if an ARP request was not received.
+ DAI is a security feature that validates ARP packets in a network. DAI intercepts, logs, and discards ARP packets with invalid IP-to-MAC address bindings. This capability protects the network from some man-in-the- middle attacks.
+ DAI determines the validity of an ARP packet based on valid IP-to-MAC address bindings stored in a trusted database, the DHCP snooping binding database.
Source: Cisco Official Certification Guide, Dynamic ARP Inspection, p.254

 

Q114	
Which of the following statements about access lists are true? (Choose three.)

A. Extended access lists should be placed as near as possible to the destination
B. Extended access lists should be placed as near as possible to the source
C. Standard access lists should be placed as near as possible to the destination
D. Standard access lists should be placed as near as possible to the source
E. Standard access lists filter on the source address
F. Standard access lists filter on the destination address

Answer: BCE

Explanation/Reference:
BD
Source: http://www.ciscopress.com/articles/article.asp?p=1697887

Standard ACL
1) Able Restrict, deny & filter packets by Host Ip or subnet only.
2) Best Practice is put Std. ACL restriction near from Source Host/Subnet (Interface-In-bound).
3) No Protocol based restriction. (Only HOST IP).
Extended ACL
1) More flexible then Standard ACL.
2) You can filter packets by Host/Subnet as well as Protocol/TCPPort/UDPPort.
3) Best Practice is put restriction near form Destination Host/Subnet. (Interface-Outbound)

 

Q115	
Which statement about extended access lists is true?

A. Extended access lists perform filtering that is based on source and destination and are most effective when applied to the destination
B. Extended access lists perform filtering that is based on source and destination and are most effective when applied to the source
C. Extended access lists perform filtering that is based on destination and are most effective when applied to the source
D. Extended access lists perform filtering that is based on source and are most effective when applied to the destination

Answer: B

Explanation/Reference:
BD
Source: http://www.ciscopress.com/articles/article.asp?p=1697887

Standard ACL
1) Able Restrict, deny & filter packets by Host Ip or subnet only.
2) Best Practice is put Std. ACL restriction near from Source Host/Subnet (Interface-In-bound).
3) No Protocol based restriction. (Only HOST IP).
Extended ACL
1) More flexible then Standard ACL.
2) You can filter packets by Host/Subnet as well as Protocol/TCPPort/UDPPort.
3) Best Practice is put restriction near form Destination Host/Subnet. (Interface-Outbound)
 

Q116	
Which security measures can protect the control plane of a Cisco router? (Choose two.)

A. CPPr
B. Parser views
C. Access control lists
D. Port security
E. CoPP

Answer: AE

Explanation/Reference:
BD
Three Ways to Secure the Control Plane
+ Control plane policing (CoPP): You can configure this as a filter for any traffic destined to an IP address on the router itself.
+ Control plane protection (CPPr): This allows for a more detailed classification of traffic (more than CoPP) that is going to use the CPU for handling.
+ Routing protocol authentication

For example, you could decide and configure the router to believe that SSH is acceptable at 100 packets per second, syslog is acceptable at 200 packets per second, and so on. Traffic that exceeds the thresholds can be safely dropped if it is not from one of your specific management stations.
You can specify all those details in the policy.
You learn more about control plane security in Chapter 13, “Securing Routing Protocols and the Control Plane.”
Selective Packet Discard (SPD) provides the ability to Although not necessarily a security feature, prioritize certain types of packets (for example, routing protocol packets and Layer 2 keepalive messages, route processor [RP]). SPD provides priority of critical control plane traffic which are received by the over traffic that is less important or, worse yet, is being sent maliciously to starve the CPU of resources required for the RP.

Source: Cisco Official Certification Guide, Table 10-3 Three Ways to Secure the Control Plane , p.269

 

Q117	
In which stage of an attack does the attacker discover devices on a target network?

A. Reconnaissance
B. Covering tracks
C. Gaining access
D. Maintaining access

Answer: A

Explanation/Reference:
BD
Reconnaissance: This is the discovery process used to find information about the network. It could include scans of the network to find out which IP addresses respond, and further scans to see which ports on the devices at these IP addresses are open. This is usually the first step taken, to discover what is on the network and to determine potential vulnerabilities.
Source: Cisco Official Certification Guide, Table 1-5 Attack Methods, p.13

 

Q118	
Which protocols use encryption to protect the confidentiality of data transmitted between two parties? (Choose two.)

A. FTP
B. SSH
C. Telnet
D. AAA
E. HTTPS
F. HTTP

Answer: BE

Explanation/Reference:
BD
+ Secure Shell (SSH) provides the same functionality as Telnet, in that it gives you a CLI to a router or switch; unlike Telnet, however, SSH encrypts all the packets that are used in the session.
+ For graphical user interface (GUI) management tools such as CCP, use HTTPS rather than HTTP because, like SSH, it encrypts the session, which provides confidentiality for the packets in that session.
Source: Cisco Official Certification Guide, Encrypted Management Protocols, p.287

 

Q119	
What are the primary attack methods of VLAN hopping? (Choose two.)

A. VoIP hopping
B. Switch spoofing
C. CAM-table overflow
D. Double tagging

Answer: BD

Explanation/Reference:
BD
VLAN hopping is a computer security exploit, a method of attacking networked resources on a virtual LAN (VLAN). The basic concept behind all VLAN hopping attacks is for an attacking host on a VLAN to gain access to traffic on other VLANs that would normally not be accessible. There are two primary methods of VLAN hopping: switch spoofing and double tagging.
+ In a switch spoofing attack, an attacking host imitates a trunking switch by speaking the tagging and trunking protocols (e.g. Multiple VLAN Registration Protocol, IEEE 802.1Q, Dynamic Trunking Protocol) used in maintaining a VLAN. Traffic for multiple VLANs is then accessible to the attacking host.
+ In a double tagging attack, an attacking host connected on a 802.1q interface prepends two VLAN tags to packets that it transmits.
Source: https://en.wikipedia.org/wiki/VLAN_hopping

 

Q120	
How can the administrator enable permanent client installation in a Cisco AnyConnect VPN firewall configuration?

A. Issue the command "anyconnect keep-installer" under the group policy or username webvpn mode
B. Issue the command "anyconnect keep-installer installed" in the global configuration
C. Issue the command "anyconnect keep-installer installed" under the group policy or username webvpn mode
D. Issue the command "anyconnect keep-installer installer" under the group policy or username webvpn mode 

Answer: C

Explanation/Reference:
@day-2 on securitytut.com
Dumps, Brad etc.. say the correct answer is " C " !
But as we figured out and also verified here :
http://www.cisco.com/c/en/us/td/docs/security/asa/asa93/configuration/vpn/asa-vpn-cli/vpn-anyconnect.html To enable permanent client installation for a specific group or user, use the anyconnect keep-installer command from group-policy or username webvpn modes:
anyconnect keep-installer installer
The default is that permanent installation of the client is enabled. The client remains on the remote computer at the end of the session. The following example configures the existing group-policy sales to remove the client on the remote computer at the end of the session:
hostname(config)# group-policy sales attributes
hostname(config-group-policy)# webvpn
hostname(config-group-policy)# anyconnect keep-installer installed none So.. the command to enable it is "anyconnect keep-installer installeR" , right ? BUT, to disable the feature of permanent client installation the command is referred as "anyconnect keep- installer installeD none"
Doesn't look good to me but IF we assume that it's not a typo, the correct answer should be " D " , right ?? Take a look on the URL above that says "../asa/asa93/" !!! ASA93 ... keep that in mind please..
I checked every version of cisco configuration guide for the ASA anyconnect remote access VPN.
Every cisco configuration guide beyond v9.3 (9.4, 9.5, 9.6, 9.7 .. latest) doesn't refer the ACTUAL command to enable the feature. Only how to disable it which is the same..
However, on EVERY cisco confifuration guide BEFORE v9.3 (9.2, 9.1 .. and all the way down) the command is referred as :
anyconnect keep-installer installed
which indicates that "C" is the correct answer !
According to other pages i got from a simple google search e.g. : h???s://www.cisco????/c/en/us/support/docs/ security/asa-5500-x-series-next-generation-firewalls/100597-technote-anyconnect-00.??ml in some point it says :
Uninstall Automatically
Problem
The AnyConnect VPN Client uninstalls itself once the connection terminates. The client logs show that keep installed is set to disabled.
Solution
AnyConnect uninstalls itself despite that the keep installed option is selected on the Adaptive Security Device Manager (ASDM). In order to resolve this issue, configure the svc keep-installer installed command under group-policy.
Indicates that none of the answers is correct as "svc keep-installer installed" was valid for v8.3 and below ! Also here : h??ps:?/networklessons.??m/cisco/asa-firewall/cisco-asa-anyconnect-remote-access-vpn/ i'm copying/pasting from the url :
ASA1(config)# group-policy ANYCONNECT_POLICY attributes
ASA1(config-group-policy)# vpn-tunnel-protocol ssl-client ssl-clientless ASA1(config-group-policy)# split-tunnel-policy tunnelspecified ASA1(config-group-policy)# split-tunnel-network-list value SPLIT_TUNNEL ASA1(config-group-policy)# dns-server value 8.8.8.8
ASA1(config-group-policy)# webvpn
ASA1(config-group-webvpn)# anyconnect keep-installer installed Indicates that "C" is correct too.. (but the asa version is not referred..) 
===========
BD
On my virtual ASA version 9.6(2) in my group policy I have
ciscoasa(config)# group-policy GroupPolicy_SecurityTut attributes Entering webvpn
ciscoasa(config-group-policy)# webvpn
And for the anyconnect keep-installer command it only shows me this ciscoasa(config-group-webvpn)# anyconnect keep-installer ?
config-group-webvpn mode commands/options:
installed Keep the install enabler
none Do not keep the install enabler
ciscoasa(config-group-webvpn)# anyconnect keep-installer
So the command should be
ciscoasa(config-group-webvpn)# anyconnect keep-installer installed I guess that sets it straight, right?

 

Q121	
Which type of security control is defense in depth?

A. Threat mitigation
B. Risk analysis
C. Botnet mitigation
D. Overt and covert channels

Answer: A

Explanation/Reference:
BD
Defense in-depth is the key to stopping most, but not all, network and computer related attacks. It's a concept of deploying several layers of defense that mitigate security threats.
Source: http://security2b.blogspot.ro/2006/12/what-is-defense-in-depth-and-why-is-it.html

Q122	
On which Cisco Configuration Professional screen do you enable AAA

A. Authentication Policies
B. Authorization Policies
C. AAA Summary
D. AAA Servers and Groups

Answer: C

Explanation/Reference:
Brad
Confidence level: 0%
Note: Never bothered to research this question. Screenshot of interface shows AAA Summary page with “Enable AAA” button.

Q123	
What are two uses of SIEM software? (Choose two.)

A. Performing automatic network audits
B. Alerting administrators to security events in real time
C. Configuring firewall and IDS devices
D. Scanning emails for suspicious attachments
E. Collecting and archiving syslog data

Answer: BE

Explanation/Reference:
Brad
B and E
Confidence level: 70%
Note: C and D are definitely incorrect, and E is definitely right. I'm not completely sure about A and B.

BD

Security Information Event Management SIEM
+ Log collection of event records from sources throughout the organization provides important forensic tools and helps to address compliance reporting requirements.
+ Normalization maps log messages from different systems into a common data model, enabling the organization to connect and analyze related events, even if they are initially logged in different source formats. + Correlation links logs and events from disparate systems or applications, speeding detection of and reaction to security threats.
+ Aggregation reduces the volume of event data by consolidating duplicate event records. + Reporting presents the correlated, aggregated event data in real-time monitoring and long-term summaries.

Source: http://www.cisco.com/c/dam/en/us/solutions/collateral/enterprise/design-zone-smart-business- architecture/sbaSIEM_deployG.pdf

Q124	
What are the three layers of a hierarchical network design? (Choose three.)

A. access
B. core
C. distribution
D. user
E. server
F. Internet

Answer: ABC

Explanation/Reference:
BD
A typical enterprise hierarchical LAN campus network design includes the following three layers:
+ Access layer: Provides workgroup/user access to the network + Distribution layer: Provides policy-based connectivity and controls the boundary between the access and core layers
+ Core layer: Provides fast transport between distribution switches within the enterprise campus Source: http://www.ciscopress.com/articles/article.asp?p=2202410&seqNum=4

 

Q125	
In which two situations should you use in-band management? (Choose two.)

A. When a network device fails to forward packets
B. When management applications need concurrent access to the device
C. When you require administrator access from multiple locations
D. When you require ROMMON access
E. When the control plane fails to respond

Answer: BC

Explanation/Reference:
Brad

B and C
Confidence level: 90%

Q126	
What are two ways to prevent eavesdropping when you perform device-management tasks? (Choose two.)

A. Use an SSH connection.
B. Use SNMPv3.
C. Use out-of-band management.
D. Use SNMPv2.
E. Use in-band management.

Answer: AB

Explanation/Reference:
BD
Both SSH and SNMPv3 provide security of the packets through encryption

 

Q127	
In which three ways does the RADIUS protocol differ from TACACS? (Choose three.)

A. RADIUS uses UDP to communicate with the NAS.
B. RADIUS encrypts only the password field in an authentication packet.
C. RADIUS authenticates and authorizes simultaneously, causing fewer packets to be transmitted.
D. RADIUS uses TCP to communicate with the NAS.
E. RADIUS can encrypt the entire packet that is sent to the NAS.
F. RADIUS supports per-command authorization.

Answer: ABC

Explanation/Reference:
BD
Source: Cisco Official Certification Guide, Table 3-2 TACACS+ Versus RADIUS, p.40

 

Q128	
Which three statements describe DHCP spoofing attacks? (Choose three.)

A. They can modify traffic in transit.
B. They are used to perform man-in-the-middle attacks.
C. They use ARP poisoning.
D. They can access most network devices.
E. They protect the identity of the attacker by masking the DHCP address.
F. They can physically modify the network gateway.

Answer: ABC

Explanation/Reference:
BD
DHCP spoofing occurs when an attacker attempts to respond to DHCP requests and trying to list themselves (spoofs) as the default gateway or DNS server, hence, initiating a man in the middle attack. With that, it is possible that they can intercept traffic from users before forwarding to the real gateway or perform DoS by flooding the real DHCP server with request to choke ip address resources.
Source: https://learningnetwork.cisco.com/thread/67229
https://learningnetwork.cisco.com/docs/DOC-24355

Also when i took the exam, it asked me for only 2 options. AB is correct

 

Q129	
A data breach has occurred and your company database has been copied. Which security principle has been violated?

A. confidentiality
B. availability
C. access
D. control

Answer: A

Explanation/Reference:
BD
Confidentiality: There are two types of data: data in motion as it moves across the network; and data at rest, when data is sitting on storage media (server, local workstation, in the cloud, and so forth). Confidentiality means that only the authorized individuals/ systems can view sensitive or classified information.
Source: Cisco Official Certification Guide, Confidentiality, Integrity, and Availability, p.6

 

Q130	
In which type of attack does an attacker send an email message that asks the recipient to click a link such as https://www.cisco.net.cc/securelogs?

A. phishing
B. pharming
C. solicitation
D. secure transaction

Answer: A

Explanation/Reference:
BD
Phishing presents a link that looks like a valid trusted resource to a user. When the user clicks it, the user is prompted to disclose confidential information such as usernames/passwords.
Phishing elicits secure information through an e-mail message that appears to come from a legitimate source such as a service provider or financial institution. The e-mail message may ask the user to reply with the sensitive data, or to access a website to update information such as a bank account number.
Source: Cisco Official Certification Guide, Confidentiality, Table 1-5 Attack Methods, p.13; Social Engineering Tactics, p.29

 

Q131	
Your security team has discovered a malicious program that has been harvesting the CEO's email messages and the company's user database for the last 6 months. What type of attack did your team discover? (Choose two)

A. advanced persistent threat
B. targeted malware
C. drive-by spyware
D. social activism

Answer: AB

Explanation/Reference:
BD
An Advanced Persistent Threat (APT) is a prolonged, aimed attack on a specific target with the intention to compromise their system and gain information from or about that target.
The target can be a person, an organization or a business.
Source: https://blog.malwarebytes.com/cybercrime/malware/2016/07/explained-advanced-persistent-threat-apt/ One new malware threat has emerged as a definite concern, namely, targeted malware. Instead of blanketing the Internet with a worm, targeted attacks concentrate on a single high-value target.
Source: http://crissp.poly.edu/wissp08/panel_malware.htm

 

Q132	
Which statement provides the best definition of malware?

A. Malware is unwanted software that is harmful or destructive.
B. Malware is software used by nation states to commit cyber crimes.
C. Malware is a collection of worms, viruses, and Trojan horses that is distributed as a single package.
D. Malware is tools and applications that remove unwanted programs.

Answer: A

Explanation/Reference:
BD
Malware, short for malicious software, is any software used to disrupt computer or mobile operations, gather sensitive information, gain access to private computer systems, or display unwanted advertising.[1] Before the term malware was coined by Yisrael Radai in 1990, malicious software was referred to as computer viruses.
Source: https://en.wikipedia.org/wiki/Malware

 

Q133	
What mechanism does asymmetric cryptography use to secure data?

A. a public/private key pair
B. shared secret keys
C. an RSA nonce
D. an MD5 hash

Answer: A

Explanation/Reference:
BD
Public key cryptography, or asymmetric cryptography, is any cryptographic system that uses pairs of keys:
public keys which may be disseminated widely, and private keys which are known only to the owner. This accomplishes two functions: authentication, which is when the public key is used to verify that a holder of the paired private key sent the message, and encryption, whereby only the holder of the paired private key can decrypt the message encrypted with the public key.
Source: https://en.wikipedia.org/wiki/Public-key_cryptography

Q134	
Refer to the exhibit
####################

209.114.111.1 configured, ipv4, sane, valid, stratum 2 
ref ID 132.163.4.103 , time D7AD124D.9DEFT576 (03:17:33.614 UTC Sun Aug 31 2014) 
our mode client, peer mode server, our poll intvl 64, peer poll intvl 64 
toot delay 46.34 user, root disp 23.52, reach 1, sync dist 268.59 
delay 63.27 msec, offset 7.5817 *sec, dispersion 187.56, jitter 2.07 msec 
precision 2**23, version 4 

204.2.134.164 configured, ipv4, sane, valid, stroll= 
ref ID 241.199.164.101, time D7AD1419.9E8S2728 103:25:13.619 UTC Sun Aug 31 2014) 
our mode client, peer mode server, out poll intvl 64, peer poll intvl 256 
root delay 30.83 msec, toot disp 4.88, reach 1, sync dist 223.80 
delay 28.69 msec, offset 6.4331 met, dispersion 187.55, jitter 1.39 msec 
precision 2**20, version 4 

192.168.10.7 configured, ipv4, oil/floater, sane, valid, stratum 3 
ref ID 108.61.73.243 , time D7ADOD8F.AE79123k (02:57:19.681 UTC Sun Aug 31 2014) 
our mode client, peer node server, our poll intvl 64, peer poll intvl 64 
toot delay 86.45 msec, toot disp 87.82, teach 377, sync dist 134.25 
delay 0.89 msec, offset 19.5087 user, dispersion 1.69, jitter 0.84 msec 
precision 2**32, version 4
####################

With which NTP server has the router synchronized?

A. 192.168.10.7
B. 108.61.73.243
C. 209.114.111.1
D. 132.163.4.103
E. 204.2.134.164
F. 241.199.164.101

Answer: A

Explanation/Reference:
BD
The output presented is generated by the show ntp association detail command. Attributes:
+ configured: This NTP clock source has been configured to be a server. This value can also be dynamic, where the peer/server was dynamically discovered.
+ our_master: The local client is synchronized to this peer
+ valid: The peer/server time is valid. The local client accepts this time if this peer becomes the master.
Source: http://www.cisco.com/c/en/us/support/docs/ip/network-time-protocol-ntp/116161-trouble-ntp-00.html

Q135	
Refer to the exhibit.
####################

tacacs server tacacs1 
   address 1pv4 1.1.1.1
   timeout 20 
   single-connection 
tacacs server tacacs2
   address ipv4 2.2.2.2 
   timeout 20
   single-connection 
tacacs server tacacs3 
   address 1pv4 3.3.3.3 
   timeout 20 
   single-connection

####################

Which statement about the given configuration is true?

A. The single-connection command causes the device to establish one connection for all TACACS transactions.
B. The single-connection command causes the device to process one TACACS request and then move to the next server.
C. The timeout command causes the device to move to the next server after 20 seconds of TACACS inactivity.
D. The router communicates with the NAS on the default port, TCP 1645.

Answer: A

Explanation/Reference:
BD
tacacs-server host host-name [port integer] [timeout integer] [key string] [single-connection] [nat] The single-connection keyword specifies a single connection (only valid with CiscoSecure Release 1.0.1 or later). Rather than have the router open and close a TCP connection to the server each time it must communicate, the single-connection option maintains a single open connection between the router and the server. The single connection is more efficient because it allows the server to handle a higher number of TACACS operations.
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/command

Explanation/Reference/srftacs.html


Q136	
What is the best way to confirm that AAA authentication is working properly?

A. Use the test aaa command.
B. Ping the NAS to confirm connectivity.
C. Use the Cisco-recommended configuration for AAA authentication.
D. Log into and out of the router, and then check the NAS authentication log.

Answer: A

Explanation/Reference:
BD
#test aaa group tacacs+ admin cisco123 legacy - A llow verification of the authentication function working between the AAA client (the router) and the ACS server (the AAA server).
Source: Cisco Official Certification Guide, Table 3-6 Command Reference, p.68

 

Q137	
How does PEAP protect the EAP exchange?

A. It encrypts the exchange using the server certificate.
B. It encrypts the exchange using the client certificate.
C. It validates the server-supplied certificate, and then encrypts the exchange using the client certificate.
D. It validates the client-supplied certificate, and then encrypts the exchange using the server certificate.

Answer: A

Explanation/Reference:
BD
PEAP is similar in design to EAP-TTLS, requiring only a server-side PKI certificate to create a secure TLS tunnel to protect user authentication, and uses server-side public key certificates to authenticate the server. It then creates an encrypted TLS tunnel between the client and the authentication server. In most configurations, the keys for this encryption are transported using the server's public key.
Source: https://en.wikipedia.org/wiki/Protected_Extensible_Authentication_Protocol

 

Q138	
What improvement does EAP-FASTv2 provide over EAP-FAST?

A. It allows multiple credentials to be passed in a single EAP exchange.
B. It supports more secure encryption protocols.
C. It allows faster authentication by using fewer packets.
D. It addresses security vulnerabilities found in the original protocol.

Answer: A

Explanation/Reference:
BD
As an enhancement to EAP-FAST, a differentiation was made to have a User PAC and a Machine PAC. After a successful machine-authentication, ISE will issue a Machine-PAC to the client. Then, when processing a user- authentication, ISE will request the Machine-PAC to prove that the machine was successfully authenticated, too. This is the first time in 802.1X history that multiple credentials have been able to be authenticated within a single EAP transaction, and it is known as "EAP Chaining".
Source: http://www.networkworld.com/article/2223672/access-control/which-eap-types-do-you-need-for-which- identity-projects.html

 

Q139	
How does a device on a network using ISE receive its digital certificate during the new-device registration process?

A. ISE issues a pre-defined certificate from a local database
B. The device requests a new certificate directly from a central CA
C. ISE acts as a SCEP proxy to enable the device to receive a certificate from a central CA server
D. ISE issues a certificate from its internal CA server

Answer: C

Explanation/Reference:
Brad

 C

Confidence level: 0%

Note: Never bothered to research this question.

BD

SCEP Profile Configuration on ISE
Within this design, ISE is acting as a Simple Certificate Enrollment Protocol (SCEP) proxy server, thereby allowing mobile clients to obtain their digital certificates from the CA server. This important feature of ISE allows all endpoints, such as iOS, Android, Windows, and MAC, to obtain digital certificates through the ISE. This feature combined with the initial registration process greatly simplifies the provisioning of digital certificates on endpoints.

Source: http://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Borderless_Networks/Unified_Access/ BYOD_Design_Guide/BYOD_ISE.html

Q140	
When an administrator initiates a device wipe command from the ISE, what is the immediate effect?

A. It requests the administrator to choose between erasing all device data or only managed corporate data.
B. It requests the administrator to enter the device PIN or password before proceeding with the operation.
C. It notifies the device user and proceeds with the erase operation.
D. It immediately erases all data on the device.

Answer: A

Explanation/Reference:
BD
Cisco ISE allows you to wipe or turn on pin lock for a device that is lost. From the MDM Access drop-down list, choose any one of the following options:
+ Full Wipe -- Depending on the MDM vendor, this option either removes the corporate apps or resets the device to the factory settings.
+ Corporate Wipe -- Removes applications that you have configured in the MDM server policies + PIN Lock -- Locks the device
Source: http://www.cisco.com/c/en/us/td/docs/security/ise/1-4/admin_guide/b_ise_admin_guide_14/ b_ise_admin_guide_14_chapter_01001.html#task_820C9C2A1A6647E995CA5AAB01E1CDEF

 

Q141	
What configuration allows AnyConnect to automatically establish a VPN session when a user logs in to the computer?

A. always-on
B. proxy
C. transparent mode
D. Trusted Network Detection

Answer: A

Explanation/Reference:
BD
You can configure AnyConnect to establish a VPN session automatically after the user logs in to a computer. The VPN session remains open until the user logs out of the computer, or the session timer or idle session timer expires. The group policy assigned to the session specifies these timer values. If AnyConnect loses the connection with the ASA, the ASA and the client retain the resources assigned to the session until one of these timers expire. AnyConnect continually attempts to reestablish the connection to reactivate the session if it is still open; otherwise, it continually attempts to establish a new VPN session.
Source: http://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/anyconnect30/administration/ guide/anyconnectadmin30/ac03vpn.pdf

 

Q142	
What security feature allows a private IP address to access the Internet by translating it to a public address?

A. NAT
B. hairpinning
C. Trusted Network Detection
D. Certification Authority

Answer: A

Explanation/Reference:
BD
Now the router itself does not have a problem with IP connectivity to the Internet because the router has a globally reachable IP address (34.0.0.3) in this example. The users are not so fortunate, however, because they are using private IP address space, and that kind of address is not allowed directly on the Internet by the service providers. So, if the users want to access a server on the Internet, they forward their packets to the default gateway, which in this case is R1, and if configured to do so, R1 modifies the IP headers in those packets and swaps out the original source IP addresses with either its own global address or a global address from a pool of global addresses (which R1 is responsible for managing, meaning that if a packet was destined to one of those addresses, the routing to those addresses on the Internet would forward the packets back to R1). These are global addresses assigned by the service provider for R1's use.
Source: Cisco Official Certification Guide, NAT Is About Hiding or Changing the Truth About Source Addresses,
E. 366

 
Q143	
Refer to the exhibit
####################

RI 
Interface GigabitEthernet 0/0 
Ip address 10.20.20.4 255.255.255.0 

crypto iaakmp policy 1 
authentication pre-share 
Lifetime 84600 
crypto Limbo key test67890 address 10.20.20.4 

R2 
Interface Gigabiathernet 0/0 
Ip address 10.20.20.4 255.255.255.0 

crypto isakmp policy 10 
authentication pre-share 
lifetime 84600 
crypto iaakmp key test12345 address 10.30.30.5

####################

You have configured R1 and R2 as shown, but the routers are unable to establish a site-to-site VPN tunnel.
What action can you take to correct the problem?

A. Edit the crypto keys on R1 and R2 to match.
B. Edit the ISAKMP policy sequence numbers on R1 and R2 to match.
C. Set a valid value for the crypto key lifetime on each router.
D. Edit the crypto isakmp key command on each router with the address value of its own interface.

Answer: A

Explanation/Reference:
BD
Five basic items need to be agreed upon between the two VPN devices/gateways (in this case, the two routers) for the IKE Phase 1 tunnel to succeed, as follows:
+ Hash algorithm
+ Encryption algorithm
+ Diffie-Hellman (DH) group
+ Authentication method: sed for verifying the identity of the VPN peer on the other side of the tunnel. Options include a pre-shared key (PSK) used only for the authentication or RSA signatures (which leverage the public keys contained in digital certificates).
+ Lifetime
The PSK used on the routers are different: test67890 and test12345 Source: Cisco Official Certification Guide, The Play by Play for IPsec, p.124

Q144	
Refer to the exhibit
####################

Crypto ipsec transform-set myset esp-md5-hmac esp-aes-256

####################

What is the effect of the given command?

A. It merges authentication and encryption methods to protect traffic that matches an ACL.
B. It configures the network to use a different transform set between peers.
C. It configures encryption for MD5 HMAC.
D. It configures authentication as AES 256.

Answer: A

Explanation/Reference:
BD
A transform set is an acceptable combination of security protocols, algorithms and other settings to apply to IP Security protected traffic. During the IPSec security association negotiation, the peers agree to use a particular transform set when protecting a particular data flow.
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/command

Explanation/Reference/srfipsec.html#wp1017694 To define a transform set -- an acceptable combination of security protocols and algorithms -- use the crypto ipsec transform-set global configuration command.
ESP Encryption Transform
+ esp-aes 256: ESP with the 256-bit AES encryption algorithm.
ESP Authentication Transform
+ esp-md5-hmac: ESP with the MD5 (HMAC variant) authentication algorithm. (No longer recommended) Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr- c3.html#wp2590984165

Q145	
Refer to the exhibit.
####################
Dst		src		state			conn-id		slot
10.10.10.2	10.1.1.5	MM_NO_STATE	1		0

####################

While troubleshooting site-to-site VPN, you issued the show crypto isakmp sa command. What does the given output show?

A. IKE Phase 1 main mode was created on 10.1.1.5, but it failed to negotiate with 10.10.10.2.
B. IKE Phase 1 main mode has successfully negotiated between 10.1.1.5 and 10.10.10.2.
C. IKE Phase 1 aggressive mode was created on 10.1.1.5, but it failed to negotiate with 10.10.10.2.
D. IKE Phase 1 aggressive mode has successfully negotiated between 10.1.1.5 and 10.10.10.2.

Answer: A

Explanation/Reference:
BD
This is the output of the #show crypto isakmp sa command. This command shows the Internet Security Association Management Protocol (ISAKMP) security associations (SAs) built between peers - IPsec Phase1.
MM_NO_STATE means that main mode has failed. QM_IDLE - this is what we want to see.
More on this
http://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/5409-ipsec-debug- 00.html


Q146	
Which statement about IOS privilege levels is true?

A. Each privilege level supports the commands at its own level and all levels below it.
B. Each privilege level supports the commands at its own level and all levels above it.
C. Privilege-level commands are set explicitly for each user.
D. Each privilege level is independent of all other privilege levels.

Answer: A

Explanation/Reference:

 

Q147	
Refer to the exhibit.
#####################

Username Engineer privilege 9 password 0 configure
Username Monitor privilege 8 password 0 vatcher
Username HelpDesk privilege 6 password help
Privilege exec level 6 show running
Privilege exec level 7 show start-up
Privilege exec level 9 configure terminal
Privilege exec level 10 interface

#####################

Which line in this configuration prevents the HelpDesk user from modifying the interface configuration?

A. Privilege exec level 9 configure terminal
B. Privilege exec level 7 show start-up
C. Privilege exec level 10 interface
D. Username HelpDesk privilege 6 password help

Answer: A

Explanation/Reference:
Brad

 A

Confidence level: 100%

Note: I have seen a lot of claims that D is the correct answer, but this is wrong. The only thing command D does is create the user "HelpDesk" with a privilege level of 6, and sets the password for that user to "help".

Command A sets the "configure terminal" command at privilege level 9, which is a higher level than HelpDesk has access to.
Also, some of the dumps say "Privilege exec level 9 show configure terminal" in the config and the answer options. This is not a different version of the question, it is a mistake. The line "show configure terminal" is not a valid command in Cisco IOS.
Q148	
In the router “ospf 200" command, what does the value 200 stand for?

A. process ID
B. area ID
C. administrative distance value
D. ABR ID

Answer: A

Explanation/Reference:
BD
Enabling OSPF
SUMMARY STEPS
1. enable
2. configure terminal
3. router ospf process-id
4. network ip-address wildcard-mask area area-id
5. end
Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/configuration/12-4t/iro-12-4t-book/iro- cfg.html

 

Q149	
Which feature filters CoPP packets?

A. Policy maps
B. Class maps
C. Access control lists
D. Route maps

Answer: C

Explanation/Reference:
Brad

 C

Confidence level: 60%

Note: All the dumps say C is the correct answer. I have never been able to find anything concrete on this, but some people say A is correct.

Q150	
In which type of attack does the attacker attempt to overload the CAM table on a switch so that the switch acts as a hub?

A. MAC spoofing
B. gratuitous ARP
C. MAC flooding
D. DoS

Answer: C

Explanation/Reference:
BD
MAC address flooding is an attack technique used to exploit the memory and hardware limitations in a switch's CAM table.
Source: http://hakipedia.com/index.php/CAM_Table_Overflow


Q151	
Which type of PVLAN port allows a host in the same VLAN to communicate directly with another?

A. community for hosts in the PVLAN
B. promiscuous for hosts in the PVLAN
C. isolated for hosts in the PVLAN
D. span for hosts in the PVLAN

Answer: A

Explanation/Reference:
BD
The types of private VLAN ports are as follows:
+ Promiscuous - The promiscuous port can communicate with all interfaces, including the community and isolated host ports, that belong to those secondary VLANs associated to the promiscuous port and associated with the primary VLAN
+ Isolated - This port has complete isolation from other ports within the same private VLAN domain, except that it can communicate with associated promiscuous ports.
+ Community -- A community port is a host port that belongs to a community secondary VLAN. Community ports communicate with other ports in the same community VLAN and with associated promiscuous ports.
These interfaces are isolated from all other interfaces in other communities and from all isolated ports within the private VLAN domain.
Source: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/ CLIConfigurationGuide/PrivateVLANs.html#42874

 

Q152	
What is a potential drawback to leaving VLAN 1 as the native VLAN?

A. It may be susceptible to a VLAN hopping attack.
B. Gratuitous ARPs might be able to conduct a man-in-the-middle attack.
C. The CAM might be overloaded, effectively turning the switch into a hub.
D. VLAN 1 might be vulnerable to IP address spoofing.

Answer: A

Explanation/Reference:
BD
VLAN hopping is a computer security exploit, a method of attacking networked resources on a virtual LAN (VLAN). The basic concept behind all VLAN hopping attacks is for an attacking host on a VLAN to gain access to traffic on other VLANs that would normally not be accessible. There are two primary methods of VLAN hopping: switch spoofing and double tagging.
+ In a switch spoofing attack, an attacking host imitates a trunking switch by speaking the tagging and trunking protocols (e.g. Multiple VLAN Registration Protocol, IEEE 802.1Q, Dynamic Trunking Protocol) used in maintaining a VLAN. Traffic for multiple VLANs is then accessible to the attacking host.
+ In a double tagging attack, an attacking host connected on a 802.1q interface prepends two VLAN tags to packets that it transmits.
Double Tagging can only be exploited when switches use "Native VLANs". Ports with a specific access VLAN (the native VLAN) don't apply a VLAN tag when sending frames, allowing the attacker's fake VLAN tag to be read by the next switch. Double Tagging can be mitigated by either one of the following actions:
+ Simply do not put any hosts on VLAN 1 (The default VLAN). i.e., assign an access VLAN other than VLAN 1 to every access port
+ Change the native VLAN on all trunk ports to an unused VLAN ID.
+ Explicit tagging of the native VLAN on all trunk ports. Must be configured on all switches in network autonomy.
Source: https://en.wikipedia.org/wiki/VLAN_hopping

 

Q153	
In which three cases does the ASA firewall permit inbound HTTP GET requests during normal operations? (Choose three).

A. When matching ACL entries are configured
B. When the firewall requires strict HTTP inspection
C. When matching NAT entries are configured
D. When the firewall recieves a FIN packet
E. When the firewall requires HTTP inspection
F. When the firewall already has a TCP connection

Answer: ACF

Explanation/Reference:
Brad
Confidence level: 100%

Note: The dumps say the correct answers are A, C, E. This is incorrect. See the following links:

https://supportforums.cisco.com/discussion/11809846/asa-5505-using-nat-allowing-incoming-traffic-https

https://supportforums.cisco.com/discussion/12473551/asa-what-allowing-return-http-traffic

Also, there is a modified version of this question where answers D and F are replaced with "When the firewall receives a SYN packet" and "When the firewall receives a SYN-ACK packet". The a SYN-ACK packet coming back from the web server establishes the TCP connection and allows requests to come through, so this is a correct answer.

Q154	
Which firewall configuration must you perform to allow traffic to flow in both directions between two zones?

A. You must configure two zone pairs, one for each direction.
B. You can configure a single zone pair that allows bidirectional traffic flows for any zone.
C. You can configure a single zone pair that allows bidirectional traffic flows for any zone except the self zone.
D. You can configure a single zone pair that allows bidirectional traffic flows only if the source zone is the less secure zone.

Answer: A

Explanation/Reference:
BD
If you want to allow traffic between two zones, such as between the inside zone (using interfaces facing the inside network) and the outside zone (interfaces facing the Internet or less trusted networks), you must create a policy for traffic between the two zones, and that is where a zone pair comes into play. A zone pair, which is just a configuration on the router, is created identifying traffic sourced from a device in one zone and destined for a device in the second zone. The administrator then associates a set of rules (the policy) for this unidirectional zone pair, such as to inspect the traffic, and then applies that policy to the zone pair.
Source: Cisco Official Certification Guide, Zones and Why We Need Pairs of Them, p.380

 

Q155	
What is a valid implicit permit rule for traffic that is traversing the ASA firewall?

A. Unicast IPv6 traffic from a higher security interface to a lower security interface is permitted in transparent mode only
B. Only BPDUs from a higher security interface to a lower security interface are permitted in routed mode
C. Unicast IPv4 traffic from a higher security interface to a lower security interface is permitted in routed mode only
D. Only BPDUs from a higher security interface to a lower security interface are permitted in transparent mode
E. ARPs in both directions are permitted in transparent mode only

Answer: E

Explanation/Reference:
BD

ARPs are allowed through the transparent firewall in both directions without an ACL. ARP traffic can be controlled by ARP inspection.

It is missing the only word.

More reading here
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa93/configuration/general/asa-general-cli/intro- fw.html

Q156	
Which statement about the communication between interfaces on the same security level is true?

A. Interfaces on the same security level require additional configuration to permit inter-interface communication.
B. Configuring interfaces on the same security level can cause asymmetric routing.
C. All traffic is allowed by default between interfaces on the same security level.
D. You can configure only one interface on an individual security level.

Answer: A

Explanation/Reference:
BD
By default, if two interfaces are both at the exact same security level, traffic is not allowed between those two interfaces.
To permit communication between interfaces with equal security levels, or to allow traffic to enter and exit the same interface, use the same-security-traffic command in global configuration mode.
#same-security-traffic permit {inter-interface | intra-interface} Source: Cisco Official Certification Guide, The Default Flow of Traffic, p.422 http://www.cisco.com/c/en/us/td/docs/security/asa/asa82/command

Explanation/Reference/cmd_ref/s1.html

Q157	
Which IPS mode provides the maximum number of actions?

A. inline
B. promiscuous
C. span
D. failover
E. bypass

Answer: A

Explanation/Reference:
BD
The first option is to put a sensor inline with the traffic, which just means that any traffic going through your network is forced to go in one physical or logical port on the sensor.
Because the sensor is inline with the network, and because it can drop a packet and deny that packet from ever reaching its final destination (because it might cause harm to that destination), the sensor has in fact just prevented that attack from being carried out. That is the concept behind intrusion prevention systems (IPS).
Whenever you hear IPS mentioned, you immediately know that the sensor is inline with the traffic, which makes it possible to prevent the attack from making it further into the network.
Source: Cisco Official Certification Guide, Difference Between IPS and IDS, p.460


Q158	
How can you detect a false negative on an IPS?

A. View the alert on the IPS.
B. Review the IPS log.
C. Review the IPS console.
D. Use a third-party system to perform penetration testing.
E. Use a third-party to audit the next-generation firewall rules.

Answer: D

Explanation/Reference:
BD
A false negative, however, is when there is malicious traffic on the network, and for whatever reason the IPS/ IDS did not trigger an alert, so there is no visual indicator (at least from the IPS/IDS system) that anything negative is going on. In the case of a false negative, you must use some third-party or external system to alert you to the problem at hand, such as syslog messages from a network device.
Source: Cisco Official Certification Guide, Positive/Negative Terminology, p.463

 
Q159	
What is the primary purpose of a defined rule in an IPS?

A. To detect internal attacks
B. To define a set of actions that occur when a specific user logs in to the system
C. To configure an event action that is pre-defined by the system administrator
D. To configure an event action that takes place when a signature is triggered 

Answer: D

Explanation/Reference:
Brad

 D

Confidence level: 80%

Note: I suspect this is one of the questions I answered incorrectly on my exam. I answered C, which is the answer I have in my study guide. However, things I have seen since have led me to believe the correct answer is D.

Q160	
Which Sourcefire secure action should you choose if you want to block only malicious traffic from a particular end-user?

A. Allow with inspection
B. Allow without inspection
C. Block
D. Trust
E. Monitor

Answer: A

Explanation/Reference:
BD
A file policy is a set of configurations that the system uses to perform advanced malware protection and file control, as part of your overall access control configuration.
A file policy, like its parent access control policy, contains rules that determine how the system handles files that match the conditions of each rule. You can configure separate file rules to take different actions for different file types, application protocols, or directions of transfer.
You can associate a single file policy with an access control rule whose action is Allow, Interactive Block, or Interactive Block with reset. The system then uses that file policy to inspect network traffic that meets the conditions of the access control rule.

Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower- module-user-guide-v541/AMP-Config.html

Q161	
How can FirePOWER block malicious email attachments?

A. It forwards email requests to an external signature engine.
B. It scans inbound email messages for known bad URLs.
C. It sends the traffic through a file policy.
D. It sends an alert to the administrator to verify suspicious email messages.

Answer: C

Explanation/Reference:
BD
A file policy is a set of configurations that the system uses to perform advanced malware protection and file control, as part of your overall access control configuration.
A file policy, like its parent access control policy, contains rules that determine how the system handles files that match the conditions of each rule. You can configure separate file rules to take different actions for different file types, application protocols, or directions of transfer.
You can associate a single file policy with an access control rule whose action is Allow, Interactive Block, or Interactive Block with reset. The system then uses that file policy to inspect network traffic that meets the conditions of the access control rule.
Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower- module-user-guide-v541/AMP-Config.html

 

Q162	
You have been tasked with blocking user access to websites that violate company policy, but the sites use dynamic IP addresses. What is the best practice for URL filtering to solve the problem?

A. Enable URL filtering and create a blacklist to block the websites that violate company policy
B. Enable URL filtering and create a whitelist to allow only the websites the company policy allow users to access
C. Enable URL filtering and use URL categorization to allow only the websites the company policy allow users to access
D. Enable URL filtering and use URL categorization to block the websites that violate company policy
E. Enable URL filtering and create a whitelist to block the websites that violate company policy 

Answer: D

Explanation/Reference:
Brad
Confidence level: 100%

Remember: A whitelist does not block URLs, and a blacklist will not always work when a URL uses dynamic IP addresses.

BD

Each website defined in the URL filtering database is assigned one of approximately 60 different URL categories. There are two ways to make use of URL categorization on the firewall:
Block or allow traffic based on URL category --You can create a URL Filtering profile that specifies an action for each URL category and attach the profile to a policy. Traffic that matches the policy would then be subject to the URL filtering settings in the profile. For example, to block all gaming websites you would set the block action for the URL category games in the URL profile and attach it to the security policy rule(s) that allow web access.
See Configure URL Filtering for more information.
Match traffic based on URL category for policy enforcement --If you want a specific policy rule to apply only to web traffic to sites in a specific category, you would add the category as match criteria when you create the policy rule. For example, you could use the URL category streaming-media in a QoS policy to apply bandwidth controls to all websites that are categorized as streaming media. See URL Category as Policy Match Criteria for more information.
By grouping websites into categories, it makes it easy to define actions based on certain types of websites.

Source: https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os/url-filtering/url-categories

Q163	
Which technology can be used to rate data fidelity and to provide an authenticated hash for data?

A. Signature updates
B. File reputation
C. Network blocking
D. File analysis

Answer: B

Explanation/Reference:
Brad

 B

Confidence level: 100%
Note: Most of the dumps indicate A is the correct answer, but answer B has been verified by securitytut users who have received perfect scores.

Q164	
Which type of encryption technology has the broadest platform support to protect operating systems?
A. software
B. hardware
C. middleware
D. file-level

Answer: A

Explanation/Reference:
BD
Much commercial and free software enables you to encrypt files in an end-user workstation or mobile device.
The following are a few examples of free solutions:
+ GPG: GPG also enables you to encrypt files and folders on a Windows, Mac, or Linux system. GPG is free.
+ The built-in MAC OS X Disk Utility: D isk Utility enables you to create secure disk images by encrypting files with AES 128-bit or AES 256-bit encryption.
+ TrueCrypt: A free encryption tool for Windows, Mac, and Linux systems.
+ AxCrypt: A f ree Windows-only file encryption tool.
+ BitLocker: Full disk encryption feature included in several Windows operating systems.
+ Many Linux distributions such as Ubuntu: A llow you to encrypt the home directory of a user with built-in utilities.
+ MAC OS X FileVault: Supports full disk encryption on Mac OS X systems.
The following are a few examples of commercial file encryption software:
+ Symantec Endpoint Encryption
+ PGP Whole Disk Encryption
+ McAfee Endpoint Encryption (SafeBoot)
+ Trend Micro Endpoint Encryption
Source: Cisco Official Certification Guide, Encrypting Endpoint Data at Rest, p.501

 

Q165	
A proxy firewall protects against which type of attack?

A. cross-site scripting attack
B. DDoS attacks
C. port scanning
D. Worm traffic

Answer: A

Explanation/Reference:
Brad

 A

Confidence level: 100%

Note: There has been some debate on this question recently. If you google "proxy protection DDoS", you will find a number of results. However, if you read more carefully you will see that the majority of these refer to proxy servers, not firewalls.

One of the biggest threats from XSS is injection attacks (SQL injection/buffer overflow), and this is one of the types of attacks that proxy firewalls are designed to protect against.

BD

Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007.

Source: https://en.wikipedia.org/wiki/Cross-site_scripting

A proxy firewall is a network security system that protects network resources by filtering messages at the application layer. A proxy firewall may also be called an application firewall or gateway firewall. Proxy firewalls are considered to be the most secure type of firewall because they prevent direct network contact with other systems.

Source: http://searchsecurity.techtarget.com/definition/proxy-firewall



Q166	
What is the benefit of a web application firewall?

A. It blocks known vulnerabilities without patching applications.
B. It simplifies troubleshooting.
C. It accelerates web traffic.
D. It supports all networking protocols.

Answer: A

Explanation/Reference:
BD
A Web Application Firewall (or WAF) filters, monitors, and blocks HTTP traffic to and from a web application. A WAF is differentiated from a regular firewall in that a WAF is able to filter the content of specific web applications while regular firewalls serve as a safety gate between servers. By inspecting HTTP traffic, it can prevent attacks stemming from web application security flaws, such as SQL injection, Cross-Site Scripting (XSS) and security misconfigurations.
Source: https://en.wikipedia.org/wiki/Web_application_firewall

 

Q167	
Which feature of the Cisco Email Security Appliance can mitigate the impact of snowshoe spam and sophisticated phishing attacks?

A. contextual analysis
B. holistic understanding of threats
C. graymail management and filtering
D. signature-based IPS

Answer: A

Explanation/Reference:
BD
Snowshoe spamming is a strategy in which spam is propagated over several domains and IP addresses to weaken reputation metrics and avoid filters. The increasing number of IP addresses makes recognizing and capturing spam difficult, which means that a certain amount of spam reaches their destination email inboxes.
Specialized spam trapping organizations are often hard pressed to identify and trap snowshoe spamming via conventional spam filters.
The strategy of snowshoe spamming is similar to actual snowshoes that distribute the weight of an individual over a wide area to avoid sinking into the snow. Likewise, snowshoe spamming delivers its weight over a wide area to remain clear of filters.
Source: https://www.techopedia.com/definition/1713/snowshoe-spamming Snowshoe spam, as mentioned above, is a growing concern as spammers distribute spam attack origination across a broad range of IP addresses in order to evade IP reputation checks. The newest AsyncOS 9 for ESA enables enhanced anti-spam scanning through contextual analysis and enhanced automation, as well as automatic classification, to provide a stronger defense against snowshoe campaigns and phishing attacks.
Source: http://blogs.cisco.com/security/cisco-email-security-stays-ahead-of-current-threats-by-adding-stronger- snowshoe-spam-defense-amp-enhancements-and-more

 

Q168	
Which NAT type allows only objects or groups to reference an IP address?

A. Static NAT
B. Dynamic NAT
C. Dynamic PAT
D. Identity NAT

Answer: B

Explanation/Reference:
Brad

 B

Confidence level: 100%

Note: A lot of people are claiming that Dynamic PAT is the correct answer. This is also wrong. When using dynamic PAT, you can also configure an inline host address or specify the interface address to be assigned to an IP.

BD

Adding Network Objects for Mapped Addresses
For dynamic NAT, you must use an object or group for the mapped addresses. Other NAT types have the option of using inline addresses, or you can create an object or group according to this section.

* Dynamic NAT:
+ You cannot use an inline address; you must configure a network object or group. + The object or group cannot contain a subnet; the object must define a range; the group can include hosts and ranges.
+ If a mapped network object contains both ranges and host IP addresses, then the ranges are used for dynamic NAT, and then the host IP addresses are used as a PAT fallback.

* Dynamic PAT (Hide):
+ Instead of using an object, you can optionally configure an inline host address or specify the interface address.
+ If you use an object, the object or group cannot contain a subnet; the object must define a host, or for a PAT pool, a range; the group (for a PAT pool) can include hosts and ranges.

* Static NAT or Static NAT with port translation:
+ Instead of using an object, you can configure an inline address or specify the interface address (for static NAT-with-port-translation).
+ If you use an object, the object or group can contain a host, range, or subnet.

* Identity NAT
+ Instead of using an object, you can configure an inline address. + If you use an object, the object must match the real addresses you want to translate.

Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/ nat_objects.html#61711

Q169	
Which feature allows a dynamic PAT pool to select the next address in the PAT pool instead of the next port of an existing address?

A. next IP
B. round robin
C. dynamic rotation
D. NAT address rotation

Answer: B

Explanation/Reference:
BD
The round-robin keyword enables round-robin address allocation for a PAT pool. Without round robin, by default all ports for a PAT address will be allocated before the next PAT address is used. The round-robin method assigns an address/port from each PAT address in the pool before returning to use the first address again, and then the second address, and so on.
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/ nat_objects.html#61711

Q170	
Refer to the exhibit
#####################

Crypto ipsec transform-set myset esp-md5-hmac esp-aes-256

####################

What are two effects of the given command? (Choose two.)

A. It configures authentication to use AES 256.
B. It configures authentication to use MD5 HMAC.
C. It configures authorization use AES 256.
D. It configures encryption to use MD5 HMAC.
E. It configures encryption to use AES 256.

Answer: BE

Explanation/Reference:
BD
To define a transform set -- an acceptable combination of security protocols and algorithms -- use the crypto ipsec transform-set global configuration command.
ESP Encryption Transform
+ esp-aes 256: ESP with the 256-bit AES encryption algorithm.
ESP Authentication Transform
+ esp-md5-hmac: ESP with the MD5 (HMAC variant) authentication algorithm. (No longer recommended) Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr- c3.html#wp2590984165

Q171	
In which three cases does the ASA firewall permit inbound HTTP GET requests during normal operations? (Choose three).

A. when a matching TCP connection is found
B. when the firewall requires strict HTTP inspection
C. when the firewall receives a FIN packet
D. when matching ACL entries are configured
E. when the firewall requires HTTP inspection
F. when matching NAT entries are configured

Answer: ADF

Explanation/Reference:

 

Q172	
Which Auto NAT policies are processed first ?

A. Dynamic with longest prefix
B. Dynamic with shortest prefix
C. Static with longest prefix
D. Static with shortest prefix

Answer: C

Explanation/Reference:
BD
All packets processed by the ASA are evaluated against the NAT table. This evaluation starts at the top (Section 1) and works down until a NAT rule is matched. Once a NAT rule is matched, that NAT rule is applied to the connection and no more NAT policies are checked against the packet.
+ Section 1 - Manual NAT policies: These are processed in the order in which they appear in the configuration.
+ Section 2 - Auto NAT policies: These are processed based on the NAT type (static or dynamic) and the prefix (subnet mask) length in the object.
+ Section 3 - After-auto manual NAT policies: These are processed in the order in which they appear in the configuration.

Source: http://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation- firewalls/116388-technote-nat-00.html



Q173	
Which security term refers to a person, property, or data of value to a company?

A. Risk
B. Asset
C. Threat prevention
D. Mitigation technique

Answer: B

Explanation/Reference:
BD
This is an exact question from the Cisco Official Certification Guide 210-260.
Source: Cisco Official Certification Guide, Table 1-1 "Do I Know This Already?" Section-to-Question Mapping,
E. 3

 

Q174	
What's the technology that you can use to prevent non malicious program to run in the computer that is disconnected from the network?

A. Firewall
B. Software Antivirus
C. Network IPS
D. Host IPS.

Answer: D

Explanation/Reference:

 

Q175	
What command could you implement in the firewall to conceal internal IP address?

A. no source-route
B. no cdp run
C. no broadcast…
D. no proxy-arp

Answer: D

Explanation/Reference:
BD
I believe these are not negating commands.
The Cisco IOS software uses proxy ARP (as defined in RFC 1027) to help hosts with no knowledge of routing determine the media addresses of hosts on other networks or subnets. For example, if the router receives an ARP request for a host that is not on the same interface as the ARP request sender, and if the router has all of its routes to that host through other interfaces, then it generates a proxy ARP reply packet giving its own local data-link address. The host that sent the ARP request then sends its packets to the router, which forwards them to the intended host. Proxy ARP is enabled by default.
Router(config-if)# ip proxy-arp - Enables proxy ARP on the interface.
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/ip/configuration/guide/fipr_c/1cfipadr.html#wp1001233

 

Q176	
Which statement about college campus is true?

A. College campus has geographical position.
B. College campus Hasn`t got internet access.
C. College campus Has multiple subdomains.
D. College campus Has very beautiful girls

Answer: A

Explanation/Reference:

 

Q177	
Which firepower preprocessor block traffic based on IP?

A. Signature-Based
B. Policy-Based
C. Anomaly-Based
D. Reputation-Based

Answer: D

Explanation/Reference:
BD
Access control rules within access control policies exert granular control over network traffic logging and handling. Reputation-based conditions in access control rules allow you to manage which traffic can traverse your network, by contextualizing your network traffic and limiting it where appropriate. Access control rules govern the following types of reputation-based control:
+ Application conditions allow you to perform application control, which controls application traffic based on not only individual applications, but also applications' basic characteristics: type, risk, business relevance, categories, and tags.
+ URL conditions allow you to perform URL filtering, which controls web traffic based on individual websites, as well as websites' system-assigned category and reputation.
The ASA FirePOWER module can perform other types of reputation-based control, but you do not configure these using access control rules. For more information, see:
+ Blacklisting Using Security Intelligence IP Address Reputation explains how to limit traffic based on the reputation of a connection's origin or destination as a first line of defense.
+ Tuning Intrusion Prevention Performance explains how to detect, track, store, analyze, and block the transmission of malware and other types of prohibited files.
Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower- module-user-guide-v541/AC-Rules-App-URL-Reputation.html

 

Q178	
Which command enable ospf authentication on an interface?

A. ip ospf authentication message-digest
B. network 192.168.10.0 0.0.0.255 area 0
C. area 20 authentication message-digest
D. ip ospf message-digest-key 1 md5 CCNA

Answer: A

Explanation/Reference:
BD
This question might be incomplete. Both ip ospf authentication message-digest and area 20 authentication message-digest command enable OSPF authentication through MD5.
Use the ip ospf authentication-key interface command to specify this password. If you enable MD5 authentication with the message-digest keyword, you must configure a password with the ip ospf message- digest-key interface command.
interface GigabitEthernet0/1
ip address 192.168.10.1 255.255.255.0
ip ospf authentication message-digest
ip ospf message-digest-key 1 md5 CCNA
Source: Cisco Official Certification Guide, Implement Routing Update Authentication on OSPF, p.348 To enable authentication for an OSPF area, use the area authentication command in router configuration mode. To remove an authentication specification of an area or a specified area from the configuration, use the no form of this command.
area area-id authentication [message-digest]
no area area-id authentication [message-digest]
Read more here
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/iproute/command

Explanation/Reference/fiprrp_r/1rfospf.html An overall guide:
Source: https://supportforums.cisco.com/document/22961/ospf-authentication

 

Q179	
Which component of CIA triad relate to safe data which is in transit?

A. Confidentiality
B. Integrity
C. Availability
D. Scalability

Answer: B

Explanation/Reference:
BD
Integrity: Integrity for data means that changes made to data are done only by authorized individuals/systems.
Corruption of data is a failure to maintain data integrity.
Source: Cisco Official Certification Guide, Confidentiality, Integrity, and Availability, p.6

 

Q180	
Which command help user1 to use enable,disable,exit&etc commands?

A. catalyst1(config)#username user1 privilege 0 secret us1pass
B. catalyst1(config)#username user1 privilege 1 secret us1pass
C. catalyst1(config)#username user1 privilege 2 secret us1pass
D. catalyst1(config)#username user1 privilege 5 secret us1pass

Answer: A

Explanation/Reference:
BD
To understand this example, it is necessary to understand privilege levels. By default, there are three command levels on the router:
+ privilege level 0 -- Includes the disable, enable, exit, help, and logout commands.
+ privilege level 1 -- Normal level on Telnet; includes all user-level commands at the router> prompt.
+ privilege level 15 -- Includes all enable-level commands at the router# prompt.
Source: http://www.cisco.com/c/en/us/support/docs/security-vpn/terminal-access-controller-access-control- system-tacacs-/23383-showrun.html

 

Q181	
Command ip ospf authentication key 1 is implemented in which level.

A. Interface
B. process
C. global
D. enable

Answer: A

Explanation/Reference:
BD
Use the ip ospf authentication-key interface command to specify this password. If you enable MD5 authentication with the message-digest keyword, you must configure a password with the ip ospf message- digest-key interface command.
interface GigabitEthernet0/1
ip address 192.168.10.1 255.255.255.0
ip ospf authentication message-digest
ip ospf message-digest-key 1 md5 CCNA
Source: Cisco Official Certification Guide, Implement Routing Update Authentication on OSPF, p.348 The OSPFv2 Cryptographic Authentication feature allows you to configure a key chain on the OSPF interface to authenticate OSPFv2 packets by using HMAC-SHA algorithms. You can use an existing key chain that is being used by another protocol, or you can create a key chain specifically for OSPFv2.
If OSPFv2 is configured to use a key chain, all MD5 keys that were previously configured using the ip ospf message-digest-key command are ignored.
Device> enable
Device# configure terminal
Device(config)# interface GigabitEthernet0/0/0
Device (config-if)# ip ospf authentication key-chain sample1 Device (config-if)# end
Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/configuration/xe-3s/iro-xe-3s-book/iro- ospfv2-crypto-authen-xe.html
In both cases OSPF and OSPFv1 the ip ospf authentication is inserted at interface level

 

Q182	
Which line in the following OSPF configuration will not be required for MD5 authentication to work?
####################

interface GigabitEthernet0/1
ip address 192.168.10.1 255.255.255.0
ip ospf authentication message-digest
ip ospf message-digest-key 1 md5 CCNA
!
router ospf 65000
router-id 192.168.10.1
area 20 authentication message-digest
network 10.1.1.0 0.0.0.255 area 10
network 192.168.10.0 0.0.0.255 area 0
!
####################

A. ip ospf authentication message-digest
B. network 192.168.10.0 0.0.0.255 area 0
C. area 20 authentication message-digest
D. ip ospf message-digest-key 1 md5 CCNA

Answer: C

Explanation/Reference:
BD
This is an exact question from the Cisco Official Certification Guide 210-260.
Source: Cisco Official Certification Guide, Table 13-1 "Do I Know This Already?" Section-to-Question Mapping,
E. 342

 

Q183	
Which of the following pairs of statements is true in terms of configuring MD authentication?

A. Interface statements (OSPF, EIGRP) must be configured; use of key chain in OSPF
B. Router process (OSPF, EIGRP) must be configured; key chain in EIGRP
C. Router process or interface statement for OSPF must be configured; key chain in EIGRP
D. Router process (only for OSPF) must be configured; key chain in OSPF 

Answer: C

Explanation/Reference:
BD
This is an exact question from the Cisco Official Certification Guide 210-260.
Source: Cisco Official Certification Guide, Table 13-1 "Do I Know This Already?" Section-to-Question Mapping,
E. 343
SOURCE: http://www.ciscopress.com/store/ccna-security-210-260-official-cert-guide-9781587205668 (Update TAB > Download the errata ) < this is updates for cert guide The correct answer changed from "Router process (only for OSPF) must be configured; key chain in EIGRP" to "Router process or interface statement for OSPF must be configured; key chain in EIGRP"

 

Q184	
Which two NAT types allows only objects or groups to reference an IP address? (choose two)

A. dynamic NAT
B. dynamic PAT
C. static NAT
D. identity NAT

Answer: AC

Explanation/Reference:
BD
Adding Network Objects for Mapped Addresses
For dynamic NAT, you must use an object or group for the mapped addresses. Other NAT types have the option of using inline addresses, or you can create an object or group according to this section.
* Dynamic NAT:
+ You cannot use an inline address; you must configure a network object or group.
+ The object or group cannot contain a subnet; the object must define a range; the group can include hosts and ranges.
+ If a mapped network object contains both ranges and host IP addresses, then the ranges are used for dynamic NAT, and then the host IP addresses are used as a PAT fallback.
* Dynamic PAT (Hide):
+ Instead of using an object, you can optionally configure an inline host address or specify the interface address.
+ If you use an object, the object or group cannot contain a subnet; the object must define a host, or for a PAT pool, a range; the group (for a PAT pool) can include hosts and ranges.
* Static NAT or Static NAT with port translation:
+ Instead of using an object, you can configure an inline address or specify the interface address (for static NAT-with-port-translation).
+ If you use an object, the object or group can contain a host, range, or subnet.
* Identity NAT
+ Instead of using an object, you can configure an inline address.
+ If you use an object, the object must match the real addresses you want to translate.
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/ nat_objects.html#61711
According to this A seems to be the only correct answer. Maybe C is correct because it allows the use of a subnet too.

 

Q185	
What port option in a PVLAN that can communicate with every other port?

A. Promiscuous ports
B. Community ports
C. Ethernet ports
D. Isolate ports

Answer: A

Explanation/Reference:
BD
+ Promiscuous -- A promiscuous port belongs to the primary VLAN. The promiscuous port can communicate with all interfaces, including the community and isolated host ports, that belong to those secondary VLANs associated to the promiscuous port and associated with the primary VLAN.
+ Isolated -- An isolated port is a host port that belongs to an isolated secondary VLAN. This port has complete isolation from other ports within the same private VLAN domain, except that it can communicate with associated promiscuous ports
+ Community -- A community port is a host port that belongs to a community secondary VLAN. Community ports communicate with other ports in the same community VLAN and with associated promiscuous ports Source: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/ CLIConfigurationGuide/PrivateVLANs.html

 

Q186	
Which are two valid TCP connection states (pick 2) is the gist of the question.

A. SYN-RCVD
B. Closed
C. SYN-WAIT
D. RCVD
E. SENT

Answer: AB

Explanation/Reference:
BD
TCP Finite State Machine (FSM) States, Events and Transitions + CLOSED: This is the default state that each connection starts in before the process of establishing it begins.
The state is called "fictional" in the standard.
+ LISTEN
+ SYN-SENT
+ SYN-RECEIVED: The device has both received a SYN (connection request) from its partner and sent its own SYN. It is now waiting for an ACK to its SYN to finish connection setup.
+ ESTABLISHED
+ CLOSE-WAIT
+ LAST-ACK
+ FIN-WAIT-1
+ FIN-WAIT-2
+ CLOSING
+ TIME-WAIT
Source: http://tcpipguide.com/free/t_TCPOperationalOverviewandtheTCPFiniteStateMachineF-2.htm

 

Q187	
Which of the following commands result in a secure bootset? (Choose all that apply.)

A. secure boot-set
B. secure boot-config
C. secure boot-files
D. secure boot-image

Answer: BD

Explanation/Reference:
BD
This is an exact question from the Cisco Official Certification Guide 210-260.
Source: Cisco Official Certification Guide, Table 11-1 "Do I Know This Already?" Section-to-Question Mapping,
E. 276

 

Q188	
What are two well known Security terms? (Choose two)

A. Trojan
B. Phishing
C. Something LC
D. Ransomware

Answer: BD

Explanation/Reference:
BD
The following are the most common types of malicious software:
+ Computer viruses
+ Worms
+ Mailers and mass-mailer worms
+ Logic bombs
+ Trojan horses
+ Back doors
+ Exploits
+ Downloaders
+ Spammers
+ Key loggers
+ Rootkits
+ Ransomware
Source: Cisco Official Certification Guide, Antivirus and Antimalware Solutions, p.498 If the question is asking about software then A and D are correct. But as it asks about security terms that are well known I suppose B and D could be chosen.

 

Q189	
What is example of social engineering

A. Gaining access to a building through an unlocked door.
B. something about inserting a random flash drive.
C. gaining access to server room by posing as IT
D. Watching other user put in username and password (something around there) 

Answer: C

Explanation/Reference:

 

Q190	
Which port should (or would) be open if VPN NAT-T was enabled

A. port 4500 outside interface
B. port 4500 in all interfaces where ipsec uses
C. port 500
D. port 500 outside interface

Answer: B

Explanation/Reference:
BD
NAT traversal: The encapsulation of IKE and ESP in UDP port 4500 enables these protocols to pass through a device or firewall performing NAT.
Source: https://en.wikipedia.org/wiki/Internet_Key_Exchange
Also a good reference
Source: https://supportforums.cisco.com/document/64281/how-does-nat-t-work-ipsec

 

Q191	
Diffie-Hellman key exchange question

A. IKE
B. IPSEC
C. SPAN
D. STP

Answer: A

Explanation/Reference:
BD
Source: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange

 

Q192	
Which filter uses in Web reputation to prevent from web based attackts? (Choose two)

A. outbreak filter
B. buffer overflow filter
C. bayesian overflow filter
D. web reputation
E. exploit filtering

Answer: AE

Explanation/Reference:
BD
wael adel on securitytut.com
"in the EKE answer was AD but when i did some digging
check this out http://www.cisco.com/c/en/us/products/security/web-security-appliance/web_rep_index.html so i guess A E is correct"
======
I suppose given the question that D is correct. As for A all I find is related to Email security through Cisco IronPort
Cisco IronPort Outbreak Filters provide a critical first layer of defense against new outbreaks. With this proven preventive solution, protection begins hours before signatures used by traditional antivirus solutions are in place. Real-world results show an average 14-hour lead time over reactive antivirus solutions.
SenderBase, the world's largest email and web traffic monitoring network, provides real-time protection. The Cisco IronPort SenderBase Network captures data from over 120,000 contributing organizations around the world.
Source: http://www.cisco.com/c/en/us/products/security/email-security-appliance/outbreak_filters_index.html

 

Q193	
What show command can see vpn tunnel establish with traffic passing through.

A. show crypto ipsec sa
B. show crypto session
C. show crypto isakmp sa
D. show crypto ipsec transform-set

Answer: A

Explanation/Reference:
BD
#show crypto ipsec sa - This command shows IPsec SAs built between peers In the output you see
#pkts encaps: 345, #pkts encrypt: 345, #pkts digest 0
#pkts decaps: 366, #pkts decrypt: 366, #pkts verify 0
which means packets are encrypted and decrypted by the IPsec peer.
Source: http://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/5409-ipsec- debug-00.html#ipsec_sa

 

Q194	
Which standard is a hybrid protocol that uses Oakley and Skeme key exchanges in an ISAKMP framework?
A.IPSec
B.SHA
C.DES
D.IKE

Answer: D

Explanation/Reference:
BD
The Oakley Key Determination Protocol is a key-agreement protocol that allows authenticated parties to exchange keying material across an insecure connection using the Diffie­Hellman key exchange algorithm.
The protocol was proposed by Hilarie K. Orman in 1998, and formed the basis for the more widely used Internet key exchange protocol
Source: https://en.wikipedia.org/wiki/Oakley_protocol
IKE (Internet Key Exchange)
A key management protocol standard that is used in conjunction with the IPSec standard. IPSec is an IP security feature that provides robust authentication and encryption of IP packets. IPSec can be configured without IKE, but IKE enhances IPSec by providing additional features, flexibility, and ease of configuration for the IPSec standard. IKE is a hybrid protocol that implements the Oakley key exchange and Skeme key exchange inside of the Internet Security Association and Key Management Protocol (ISAKMP) framework.
ISAKMP, Oakley, and Skeme are security protocols implemented by IKE Source: https://www.symantec.com/security_response/glossary/define.jsp?letter=i&word=ike-internet-key- exchange

 

Q195	
What information does the key length provide in an encryption algorithm?
A. the packet size
B. the number of permutations
C. the hash block size
D. the cipher block size

Answer: B

Explanation/Reference:
BD
In cryptography, an algorithm's key space refers to the set of all possible permutations of a keys.
If a key were eight bits (one byte) long, the keyspace would consist of 28 or 256 possible keys. Advanced Encryption Standard (AES) can use a symmetric key of 256 bits, resulting in a key space containing 2256 (or 1.1579 × 1077) possible keys.
Source: https://en.wikipedia.org/wiki/Key_space_(cryptography)

 

Q196	
Which type of attack is directed against the network directly:

A. Denial of Service
B. phishing
C. trojan horse
D. ...

Answer: A

Explanation/Reference:
BD
Denial of service refers to willful attempts to disrupt legitimate users from getting access to the resources they intend to. Although no complete solution exists, administrators can do specific things to protect the network from a DoS attack and to lessen its effects and prevent a would-be attacker from using a system as a source of an attack directed at other systems. These mitigation techniques include filtering based on bogus source IP addresses trying to come into the networks and vice versa. Unicast reverse path verification is one way to assist with this, as are access lists. Unicast reverse path verification looks at the source IP address as it comes into an interface, and then looks at the routing table. If the source address seen would not be reachable out of the same interface it is coming in on, the packet is considered bad, potentially spoofed, and is dropped.
Source: Cisco Official Certification Guide, Best Practices Common to Both IPv4 and IPv6, p.332

 

Q197	
With which technology do apply integrity, confidentially and authenticate the source

A. IPSec
B. IKE
C. Certificate authority
D. Data encryption standards

Answer: A

Explanation/Reference:
BD
IPsec is a collection of protocols and algorithms used to protect IP packets at Layer 3 (hence the name of IP Security [IPsec]). IPsec provides the core benefits of confidentiality through encryption, data integrity through hashing and HMAC, and authentication using digital signatures or using a pre-shared key (PSK) that is just for the authentication, similar to a password.
Source: Cisco Official Certification Guide, IPsec and SSL, p.97

 

Q198	
With which type of Layer 2 attack can you intercept traffic that is destined for one host?

A. MAC spoofing
B. CAM overflow....
C. ?
D. ?

Answer: A

Explanation/Reference:
BD
Edit: I'm reconsidering the answer for this question to be A. MAC spoofing.
Cisco implemented a technology into IOS called Port Security that mitigates the risk of a Layer 2 CAM overflow attack.
Port Security on a Cisco switch enables you to control how the switch port handles the learning and storing of MAC addresses on a per-interface basis. The main use of this command is to set a limit to the maximum number of concurrent MAC addresses that can be learned and allocated to the individual switch port.
If a machine starts broadcasting multiple MAC addresses in what appears to be a CAM overflow attack, the default action of Port Security is to shut down the switch interface Source: http://www.ciscopress.com/articles/article.asp?p=1681033&seqNum=2

 

Q199	
I had the "nested" question (wording has been different). Two answers ware related to hierarchy:

A. there are only two levels of hierarchy possible
B. the higher level hierarchy becomes the parent for lower one parent
C. inspect something is only possible with in a hierachy...
D. some command question....

Answer: C

Explanation/Reference:

 

Q200	
How would you verify that TACACS+ is working?

A. SSH to the device and login promt appears
B. loging to the device using enable password
C. login to the device using ASC password
D. console the device using some thing

Answer: A

Explanation/Reference:

 

Q201	
What are two challenges faced when deploying host-level IPS? (Choose Two)
A. The deployment must support multiple operating systems.
B. It does not provide protection for offsite computers.
C. It is unable to provide a complete network picture of an attack.
D. It is unable to determine the outcome of every attack that it detects.
E. It is unable to detect fragmentation attacks.

Answer: AC

Explanation/Reference:
BD
Advantages of HIPS: The success or failure of an attack can be readily determined. A network IPS sends an alarm upon the presence of intrusive activity but cannot always ascertain the success or failure of such an attack. HIPS does not have to worry about fragmentation attacks or variable Time to Live (TTL) attacks because the host stack takes care of these issues. If the network traffic stream is encrypted, HIPS has access to the traffic in unencrypted form.
Limitations of HIPS: There are two major drawbacks to HIPS:
+ HIPS does not provide a complete network picture: Because HIPS examines information only at the local host level, HIPS has difficulty constructing an accurate network picture or coordinating the events happening across the entire network.
+ HIPS has a requirement to support multiple operating systems: HIPS needs to run on every system in the network. This requires verifying support for all the different operating systems used in your network.
Source: http://www.ciscopress.com/articles/article.asp?p=1336425&seqNum=3

 

Q202	
Which statement about command authorization and security contexts is true?

A. If command authorization is configured, it must be enabled on all contexts
B. The changeto command invokes a new context session with the credentials of the currently logged-in user
C. AAA settings are applied on a per-context basis
D. The enable_15 user and admins with changeto permissions have different command authorization levels per context

Answer: B

Explanation/Reference:
BD
The capture packet function works on an individual context basis. The ACE traces only the packets that belong to the context where you execute the capture command. You can use the context ID, which is passed with the packet, to isolate packets that belong to a specific context. To trace the packets for a single specific context, use the changeto command and enter the capture command for the new context.
To move from one context on the ACE to another context, use the changeto command Only users authorized in the admin context or configured with the changeto feature can use the changeto command to navigate between the various contexts. Context administrators without the changeto feature, who have access to multiple contexts, must explicitly log in to the other contexts to which they have access.
Source: http://www.cisco.com/c/en/us/td/docs/interfaces_modules/services_modules/ace/vA5_1_0/command/ reference/ACE_cr/execmds.html

* AAA settings are discrete per context, not shared between contexts.
When configuring command authorization, you must configure each context separately.

* New context sessions started with the changeto command always use the default value “enable_15” username as the administrator identity, regardless of what username was used in the previous context session.

to read more, here’s the link
https://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/access_management.html#30969

 

Q203	
What encryption technology has broadest platform support

A. hardware
B. middleware
C. Software
D. File level

Answer: C

Explanation/Reference:

 

Q204	
With which preprocesor do you detect incomplete TCP handshakes

A. ?
B. rate based prevention
C. ?
D. portscan detection

Answer: B

Explanation/Reference:
BD
Rate-based attack prevention identifies abnormal traffic patterns and attempts to minimize the impact of that traffic on legitimate requests. Rate-based attacks usually have one of the following characteristics:
+ any traffic containing excessive incomplete connections to hosts on the network, indicating a SYN flood attack
+ any traffic containing excessive complete connections to hosts on the network, indicating a TCP/IP connection flood attack
+ excessive rule matches in traffic going to a particular destination IP address or addresses or coming from a particular source IP address or addresses.
+ excessive matches for a particular rule across all traffic.
Source: http://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower- module-user-guide-v541/Intrusion-Threat-Detection.html

 

Q205	
Which type of PVLAN port allows a host in the same VLAN to communicate only with promiscuous hosts?

A. Community host in the PVLAN
B. Isolated host in the PVLAN
C. Promiscuous host in the PVLAN
D. Span for host in the PVLAN

Answer: B

Explanation/Reference:
BD
The types of private VLAN ports are as follows:
+ Promiscuous - The promiscuous port can communicate with all interfaces, including the community and isolated host ports, that belong to those secondary VLANs associated to the promiscuous port and associated with the primary VLAN
+ Isolated - This port has complete isolation from other ports within the same private VLAN domain, except that it can communicate with associated promiscuous ports.
+ Community -- A community port is a host port that belongs to a community secondary VLAN. Community ports communicate with other ports in the same community VLAN and with associated promiscuous ports.
These interfaces are isolated from all other interfaces in other communities and from all isolated ports within the private VLAN domain.
Source: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/ CLIConfigurationGuide/PrivateVLANs.html#42874

 

Q206	
Which type of encryption technology has the broadcast platform support?

A. Middleware
B. Hardware
C. Software
D. File-level

Answer: C

Explanation/Reference:

 

Q207	
The first layer of defense which provides real-time preventive solutions against malicious traffic is provided by?

A. Banyan Filters
B. Explicit Filters
C. Outbreak Filters
D. ?

Answer: C

Explanation/Reference:

 

Q208	
SSL certificates are issued by Certificate Authority(CA) are?

A. Trusted root
B. Not trusted
C. ?
D. ?

Answer: A

Explanation/Reference:

 

Q209	
SYN flood attack is a form of ?

A. Reconnaissance attack
B. Denial of Service attack
C. Spoofing attack
D. Man in the middle attack

Answer: B

Explanation/Reference:
BD
A SYN flood is a form of denial-of-service attack in which an attacker sends a succession of SYN requests to a target's system in an attempt to consume enough server resources to make the system unresponsive to legitimate traffic.
Source: https://en.wikipedia.org/wiki/SYN_flood

 

Q210	
The command debug crypto isakmp results in ?

A. Troubleshooting ISAKMP (Phase 1) negotiation problems
B. ?
C. ?
D. ?

Answer: A

Explanation/Reference:
BD
#debug crypto isakmp
This output shows an example of the debug crypto isakmp command.
processing SA payload. message ID = 0
Checking ISAKMP transform against priority 1 policy
encryption 3DES
hash SHA
default group 2
auth pre-share
life type in seconds
life duration (basic) of 240
atts are acceptable. Next payload is 0
processing KE payload. message ID = 0
processing NONCE payload. message ID = 0
processing ID payload. message ID = 0
SKEYID state generated
processing HASH payload. message ID = 0
SA has been authenticated
processing SA payload. message ID = 800032287
Contains the IPsec Phase1 information. You can view the HAGLE (Hash, Authentication, DH Group, Lifetime, Encryption) process in the output.

 

Q211	
Which prevent the company data from modification even when the data is in transit?

A. Confidentiality
B. Integrity
C. Vailability
D. Scalability

Answer: B

Explanation/Reference:
BD
Integrity: Integrity for data means that changes made to data are done only by authorized individuals/systems.
Corruption of data is a failure to maintain data integrity.
Source: Cisco Official Certification Guide, Confidentiality, Integrity, and Availability, p.6

 

Q212	
The stealing of confidential information of a company comes under the scope of:

A. Reconnaissance
B. Spoofing attack
C. Social Engineering
D. Denial of Service

Answer: C

Explanation/Reference:
BD
Social engineering
This is a tough one because it leverages our weakest (very likely) vulnerability in a secure system (data, applications, devices, networks): the user. If the attacker can get the user to reveal information, it is much easier for the attacker than using some other method of reconnaissance. This could be done through e-mail or misdirection of web pages, which results in the user clicking something that leads to the attacker gaining information. Social engineering can also be done in person or over the phone.
Source: Cisco Official Certification Guide, Table 1-5 Attack Methods, p.13

 

Q213	
The Oakley cryptography protocol is compatible with following for managing security?

A. IPSec
B. ISAKMP
C. Port security
D. ?

Answer: B

Explanation/Reference:
BD
IKE (Internet Key Exchange)
A key management protocol standard that is used in conjunction with the IPSec standard. IPSec is an IP security feature that provides robust authentication and encryption of IP packets. IPSec can be configured without IKE, but IKE enhances IPSec by providing additional features, flexibility, and ease of configuration for the IPSec standard. IKE is a hybrid protocol that implements the Oakley key exchange and Skeme key exchange inside of the Internet Security Association and Key Management Protocol (ISAKMP) framework.
ISAKMP, Oakley, and Skeme are security protocols implemented by IKE.
Source: https://www.symantec.com/security_response/glossary/define.jsp?letter=i&word=ike-internet-key- exchange

 

Q214	
Unicast Reverse Path Forwarding definition:

A. Unicast Reverse Path Forwarding (uRPF) can mitigate spoofed IP packets
B. ?
C. ?
D. ?

Answer: A

Explanation/Reference:
BD
Unicast Reverse Path Forwarding
Unicast Reverse Path Forwarding (uRPF) can mitigate spoofed IP packets. When this feature is enabled on an interface, as packets enter that interface the router spends an extra moment considering the source address of the packet. It then considers its own routing table, and if the routing table does not agree that the interface that just received this packet is also the best egress interface to use for forwarding to the source address of the packet, it then denies the packet.
This is a good way to limit IP spoofing.
Source: Cisco Official Certification Guide, Table 10-4 Protecting the Data Plane, p.270

 

Q215	
The NAT traversal definition:

A. ?
B. ?
C. ?
D. ?

Answer:

Explanation/Reference:
BD
NAT-T (NAT Traversal)
If both peers support NAT-T, and if they detect that they are connecting to each other through a Network Address Translation (NAT) device (translation is happening), they may negotiate that they want to put a fake UDP port 4500 header on each IPsec packet (before the ESP header) to survive a NAT device that otherwise may have a problem tracking an ESP session (Layer 4 protocol 50).
Source: Cisco Official Certification Guide, Table 7-2 Protocols That May Be Required for IPsec, p.153 Also a good reference
Source: https://supportforums.cisco.com/document/64281/how-does-nat-t-work-ipsec

 

Q216	
Man-in-the-middle attack definition:

A. Someone or something is between the two devices who believe they are communicating directly with each other.
B. ?
C. ?
D. ?

Answer: A

Explanation/Reference:
BD
Man-in-the-middle attacks: Someone or something is between the two devices who believe they are communicating directly with each other. The "man in the middle" may be eavesdropping or actively changing the data that is being sent between the two parties. You can prevent this by implementing Layer 2 dynamic ARP inspection (DAI) and Spanning Tree Protocol (STP) guards to protect spanning tree. You can implement it at Layer 3 by using routing protocol authentication. Authentication of peers in a VPN is also a method of preventing this type of attack.
Source: Cisco Official Certification Guide, Threats Common to Both IPv4 and IPv6, p.333

 

Q217	
Which privileged level is ... by default? for user exec mode

A. 0
B. 1
C. 2
D. 5
E. 15

Answer: B

Explanation/Reference:
BD
User EXEC mode commands are privilege level 1
Privileged EXEC mode and configuration mode commands are privilege level 15.
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/command

Explanation/Reference/fsecur_r/srfpass.html

 

Q218	
When is "Deny all" policy an exception in Zone Based Firewall

A. traffic traverses 2 interfaces in same zone
B. traffic sources from router via self zone
C. traffic terminates on router via self zone
D. traffic traverses 2 interfaces in different zones
E. traffic terminates on router via self zone

Answer: A

Explanation/Reference:
BD
+ There is a default zone, called the self zone, which is a logical zone. For any packets directed to the router directly (the destination IP represents the packet is for the router), the router automatically considers that traffic to be entering the self zone. In addition, any traffic initiated by the router is considered as leaving the self zone.
By default, any traffic to or from the self zone is allowed, but you can change this policy.
+ For the rest of the administrator-created zones, no traffic is allowed between interfaces in different zones.
+ For interfaces that are members of the same zone, all traffic is permitted by default.
Source: Cisco Official Certification Guide, Zones and Why We Need Pairs of Them, p.380

 

Q219	
What is true about the Cisco Resilient Configuration Feature?

A. Requires additional space to store IOS image file
B. Remote storage required to save IOS image
C. Can be disabled through a remote session
D. Automatically detects image or configuration version missmatch

Answer: D

Explanation/Reference:
BD
The following factors were considered in the design of Cisco IOS Resilient Configuration:
+ The configuration file in the primary bootset is a copy of the running configuration that was in the router when the feature was first enabled.
+ The feature secures the smallest working set of files to preserve persistent storage space. No extra space is required to secure the primary Cisco IOS image file.
+ The feature automatically detects image or configuration version mismatch .
+ Only local storage is used for securing files, eliminating scalability maintenance challenges from storing multiple images and configurations on TFTP servers.
+ The feature can be disabled only through a console session Source: http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/15-mt/sec-usr-cfg-15-mt- book/sec-resil-config.html

 

Q220	
What are the two characteristics of IPS?

A. Can drop traffic
B. Does not add delay to traffic
C. It is cabled directly inline
D. Can`t drop packets on its own

Answer: AC

Explanation/Reference:
BD
+ Position in the network flow: Directly inline with the flow of network traffic and every packet goes through the sensor on its way through the network.
+ Mode: Inline mode
+ The IPS can drop the packet on its own because it is inline. The IPS can also request assistance from another device to block future packets just as the IDS does.
Source: Cisco Official Certification Guide, Table 17-2 IDS Versus IPS, p.461

 

Q221	
What can cause the state table of a stateful firewall to update? (choose two)

A. when connection is created
B. connection timer expired within state table
C. when packet is evaluated against the inbound access list and is ...
D. outbound packets forwarded to inbound interface
E. when rate limiting is applied

Answer: AB

Explanation/Reference:
BD
Stateful inspection monitors incoming and outgoing packets over time, as well as the state of the connection, and stores the data in dynamic state tables. This cumulative data is evaluated, so that filtering decisions would not only be based on administrator-defined rules, but also on context that has been built by previous connections as well as previous packets belonging to the same connection.
Entries are created only for TCP connections or UDP streams that satisfy a defined security policy.
In order to prevent the state table from filling up, sessions will time out if no traffic has passed for a certain period. These stale connections are removed from the state table.
Source: https://en.wikipedia.org/wiki/Stateful_firewall

 

Q222	
What IPSec mode is used to encrypt traffic between client and server vpn endpoints?

A. tunnel
B. Trunk
C. Aggregated
D. Quick
E. Transport

Answer: E

Explanation/Reference:
BD
16.02.2017
@Tullipp on securitytut.com commented:
"the IPSEC Mode question did come up. It has been been very badly worded in the dumps and I knew It cant be right.
The question that comes in the exam is "between client and server vpn endpoints".
So the keyword here is vpn endpoints. Not the end points like its worded in the dumps.
So the answer is transport mode."
+ IPSec Transport mode is used for end-to-end communications, for example, for communication between a client and a server or between a workstation and a gateway (if the gateway is being treated as a host). A good example would be an encrypted Telnet or Remote Desktop session from a workstation to a server.
+ IPsec supports two encryption modes: Transport mode and Tunnel mode. Transport mode encrypts only the data portion (payload) of each packet and leaves the packet header untouched. Transport mode is applicable to either gateway or host implementations, and provides protection for upper layer protocols as well as selected IP header fields.
Source: http://www.firewall.cx/networking-topics/protocols/870-ipsec-modes.html http://www.cisco.com/c/en/us/td/docs/net_mgmt/vpn_solutions_center/2-0/ip_security/provisioning/guide/ IPsecPG1.html
Generic Routing Encapsulation (GRE) is often deployed with IPsec for several reasons, including the following:
+ IPsec Direct Encapsulation supports unicast IP only. If network layer protocols other than IP are to be supported, an IP encapsulation method must be chosen so that those protocols can be transported in IP packets.
+ IPmc is not supported with IPsec Direct Encapsulation. IPsec was created to be a security protocol between two and only two devices, so a service such as multicast is problematic. An IPsec peer encrypts a packet so that only one other IPsec peer can successfully perform the de-encryption. IPmc is not compatible with this mode of operation.
Source: https://www.cisco.com/application/pdf/en/us/guest/netsol/ns171/c649/ ccmigration_09186a008074f26a.pdf

 

Q223	
Which command is used to verify a VPN connection is operational?

A. sh crypto ipsec sa
B. sh crypto isakmp sa
C. debug crypto isakmp
D. sh crypto session

Answer: A

Explanation/Reference:
BD
#show crypto ipsec sa - This command shows IPsec SAs built between peers In the output you see
#pkts encaps: 345, #pkts encrypt: 345, #pkts digest 0
#pkts decaps: 366, #pkts decrypt: 366, #pkts verify 0
which means packets are encrypted and decrypted by the IPsec peer.
Source: http://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/5409-ipsec- debug-00.html#ipsec_sa

 

Q224	
What is the command to authenticate an NTP time source? (something in those lines)


A. #ntp authentication-key 1 md5 141411050D 7
B. #ntp authenticate
C. #ntp trusted-key 1
D. #ntp trusted-key 2

Answer: B

Explanation/Reference:

ntp authentication-key,,,,Defines the authentication keys.
ntp authenticate,,,Enables or disables the NTP authentication feature.
ntp trusted-key #,,, Specifies one or more keys that a time source must provide in its NTP packets in order for the device to synchronize to it

BD
ntp authentication-key 1 md5 141411050D 7
ntp authenticate
ntp trusted-key 1
ntp update-calendar
ntp server 192.168.1.96 key 1 prefer source FastEthernet0/1
Source: Cisco Official Certification Guide, Example 11-15 Using Authentication via Keys with NTPv3, p.314

 

Q225	
How can you allow bidirational traffic? (something in those lines)

A. static NAT
B. dynamic NAT
C. dynamic PAT
D. multi-NAT

Answer: A

Explanation/Reference:
BD
Bidirectional initiation--Static NAT allows connections to be initiated bidirectionally, meaning both to the host and from the host.
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa83/configuration/guide/config/nat_overview.html

 

Q226	
Which option is the default value for the Diffie­Hellman group when configuring a site-to-site VPN on an ASA device?

A. Group 1
B. Group 2
C. Group 7
D. Group 5

Answer: B

Explanation/Reference:

 

Q227	
What two devices are components of the BYOD architecture framework? (Choose two)

A. Identity Service Engine
B. Cisco 3845 Router
C. Wireless Access Points
D. Nexus 7010 Switch
E. Prime Infrastructure

Answer: AE

Explanation/Reference:

Q228	
Which option is the cloud based security service from Cisco that provides URL filtering web browsing content security, and roaming user protection?

A. Cloud web security
B. Cloud web Protection
C. Cloud web Service
D. Cloud advanced malware protection

Answer: A

Explanation/Reference:

Q229	
Which product can be used to provide application layer protection for TCP port 25 traffic?

A. ESA
B. CWS
C. WSA
D. ASA

Answer: A

Explanation/Reference:

Q230	
Which two actions can a zone-based firewall take when looking at traffic? (Choose two)
A. Filter
B. Forward
C. Drop
D. Broadcast
E. Inspect

Answer: CE

Explanation/Reference:

 

Q231	
Which label is given to a person who uses existing computer scripts to hack into computers lacking the expertise to write their own?

A. script kiddy
B. white hat hacker
C. phreaker
D. hacktivist

Answer: A

Explanation/Reference:

 

Q232	
Regarding PVLAN diagram question:

Switch was in VLAN 300
Isolated Host 1 on VLAN 301
Host 2 and Host 4 on VLAN 303 or something (Community PVLAN)

Server is connected to Switch.
All host connects to switch.

A. Host 2 (Host is part of community PVLAN).
B. Other devices on VLAN XXX (VLAN were isolated host is connected, in my case it was Host 1).
C. Server
D. Host 4 (Host is part of community PVLAN)

Answer: C

Explanation/Reference:
JS
Host 3 is not part of anyh PVLAN. It is also connected to switch.
So, Host 3 was not an option otherwise it could also be an answer.

 

Q233	
#nat (inside,outside) dynamic interface
Refer to the above. Which translation technique does this configuration result in?
A. static PAT
B. static NAT
C. dynamic PAT
D. dynamic NAT

Answer: C

Explanation/Reference:
Mr.W
Configuring Dynamic NAT
nat (inside,outside) dynamic my-range-obj
Configuring Dynamic PAT (Hide)
nat (inside,outside) dynamic interface
Source: http://www.cisco.com/c/en/us/td/docs/security/asa/asa83/configuration/guide/config/nat_objects.html

 

Q234	
Which two characteristics of an application layer firewall are true? (Choose two)

A. provides reverse proxy services
B. is immune to URL manipulation
C. provides protection for multiple applications
D. provides stateful firewall functionality
E. has low processor usage

Answer: AC

Explanation/Reference:
Brad
1. supports revers proxy ­ Definitely true
2. is immune to URL manupulation ­ Definitely false
3. supprts multiple application ­ Definitely true
4. provide statefull firewall security
5. saves processing usage.
I'm not sure about the last two.

 

Q235	
Which two functions can SIEM provide? (Choose Two)
A. Correlation between logs and events from multiple systems.
B. event aggregation that allows for reduced log storage requirements.
C. proactive malware analysis to block malicious traffic.
D. dual-factor authentication.
E. centralized firewall management.

Answer: AB

Explanation/Reference:
BD
Security Information Event Management SIEM
+ Log collection of event records from sources throughout the organization provides important forensic tools and helps to address compliance reporting requirements.
+ Normalization maps log messages from different systems into a common data model, enabling the organization to connect and analyze related events, even if they are initially logged in different source formats.
+ Correlation links logs and events from disparate systems or applications, speeding detection of and reaction to security threats.
+ Aggregation reduces the volume of event data by consolidating duplicate event records.
+ Reporting presents the correlated, aggregated event data in real-time monitoring and long-term summaries.
Source: http://www.cisco.com/c/dam/en/us/solutions/collateral/enterprise/design-zone-smart- businessarchitecture/sbaSIEM_deployG.pdf

 

Q236	
Within an 802.1X enabled network with the Auth Fail feature configured, when does a switch port get placed into a restricted VLAN?

A. When user failed to authenticate after certain number of attempts
B. When 802.1X is not globally enabled on the Cisco catalyst switch
C. When AAA new-model is enabled
D. If a connected client does not support 802.1X
E. After a connected client exceeds a specific idle time

Answer: A

Explanation/Reference:

 

Q237	
In which configuration mode do you configure the ip ospf authentication-key 1 command?

A. global
B. priviliged
C. in-line
D. interface

Answer: D

Explanation/Reference:
BD
ip ospf authentication-key is used under interface configuration mode, so it's in interface level, under global configuration mode. If it asks about interface level then choose that.
interface Serial0
ip address 192.16.64.1 255.255.255.0
ip ospf authentication-key c1$c0

 

Q238	
What is the actual IOS privilege level of User Exec mode?

A. 1
B. 0
C. 5
D. 15

Answer: A

Explanation/Reference:
BD
By default, the Cisco IOS software command-line interface (CLI) has two levels of access to commands: user EXEC mode (level 1) and privileged EXEC mode (level 15). However, you can configure additional levels of access to commands, called privilege levels, to meet the needs of your users while protecting the system from unauthorized access. Up to 16 privilege levels can be configured, from level 0, which is the most restricted level, to level 15, which is the least restricted level.
Source: http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/configuration/guide/fsecur_c/scfpass.html

 

Q239	
Which option is a weakness in an information system that an attacker might leverage to gain unauthorized access to the system or its data?

A. hack
B. mitigation
C. risk
D. vulnerability
E. exploit

Answer: D

Explanation/Reference:
BD
vulnerability A flaw or weakness in a system's design or implementation that could be exploited.
Source: CCNA Security 210-260 Official Cert Guide, GLOSSARY, p. 530 20 newq

 

Q240	
Referring to CIA (confidentiality,Integrity and Availability), where would a hash-only make more sense.
A. Data at Rest
B. Data on File
C. ...
D. ...

Answer: A

Explanation/Reference:

Q241	
At which Layer Data Center Operate

A. Data Center
B. ...
C. ...
D. ...

Answer: A

Explanation/Reference:

 

Q242	
How can you stop reconnaissance attack with cdp.

A. disable CDP on ports connected to end points (or Disable CPD on edfe ports)
B. enable dot1x on all ports that are connected to other switches
C. disable CDP on trunk ports
D. enable dynamic ARP inspection on all untrusted ports

Answer: A

Explanation/Reference:

 

Q243	
For Protecting FMC what/which is used.

A. AMP
B. ...
C. ...
D. ...

Answer: A

Explanation/Reference:

 

Q244	
What ips feature that is less secure among than the other option permit a better throughput ?

A. Promiscuous
B. ...
C. ...
D. ...

Answer: A

Explanation/Reference:

 

Q245	
Zone based firewall

A. enable zones first 
B. zones must be made before applying interfaces.
C. ...
D. ...

Answer: AB

Explanation/Reference:

 

Q246	
What is the effect of the ASA command crypto isakmp nat-traversal?
A. It opens port 4500 only on the outside interface.
B. It opens port 500 only on the inside interface.
C. It opens port 500 only on the outside interface.
D. It opens port 4500 on all interfaces that are IPSec enabled.

Answer: D

Explanation/Reference:

 

Q247	
Refer to the exhibit.
####################

local ident (addr/mask/prot/port): …
remote ident (addr/mask/prot/port): …
current_peer: x.x.x.x
#pkts encaps: 7065, #pkts encrypt: 7065, #pkts digest: 7065
#pkts decaps: x (I can’t remember if it was 0),#pkts decrypt: 0, #pkts verify: 0
…..
local crypto endpt.: x.x.x.x remote crypto endpt.: y.y.y.y

####################

While troubleshooting a VPN, you issued the show crypto ipsec sa command. rsaWhy ipsec tunnel is not working.
A. because the ASA can’t receive packets from remote endpoint
B. the peers are not on the same network subnet
C. udp port 500 it’s blocked (or something similar)
D. …

Answer: A

Explanation/Reference:

 

Q248	
What data is transferred during DH for making pub/prive key?

A. Random prime Integer
B. Encrypted data transfer
C. Prime integer
D. Random number

Answer: A

Explanation/Reference:

 

Q249	
Which of the following is a Dos attack that is difficult to discover?

A. Syn-flood attack
B. Peer-to-peer attacks
C. Low-rate dos attack
D. Trojan

Answer: C

Explanation/Reference:

 
Q250	
question about show crypto isakmp sa ?

A. Remote peer was not able to encrypt the packet
B. ...
C. ...
D. ...

Answer: A

Explanation/Reference:

 

Q251	
A question about MDM

A. deployed certificates.
B. ...
C. ...
D. ...

Answer: A

Explanation/Reference:

 

Q252	
what causes a client to be placed in a guest or restricted VLAN on an 802.1x enabled network.

A. client entered wrong credentials multiple times.
B. client entered wrong credentials the first time
C. When 802.1X is not globally enabled on the Cisco catalyst switch
D. When AAA new-model is enabled

Answer: A

Explanation/Reference:

 

Q253	
Self zone (2 option)?

A. can be source or destination zone.
B. can be use stateful filtering during multicast.
C. all interfaces will be used for self zone
D. ...

Answer: AB

Explanation/Reference:

 AC has also been seen

Q254	
Which IDS/IPS is used for monitoring system health and…?

A. HIPS
B. WIPS
C. visibility tool
D. ...

Answer: A

Explanation/Reference:

 
Q255	
Which type of PVLAN port allows a host in the same VLAN to communicate only with promiscuous hosts

A.	Community host in the PVLAN
B.	Isolated host in the PVLAN
C.	Promiscuous host in the PVLAN
D.	Span for host in the PVLAN
E.	
Answer: B

Explanation/Reference:
The types of private VLAN ports are as follows:
+ Promiscuous – The promiscuous port can communicate with all interfaces, including the community and
isolated host ports, that belong to those secondary VLANs associated to the promiscuous port and associated
with the primary VLAN
+ Isolated – This port has complete isolation from other ports within the same private VLAN domain, except that
it can communicate with associated promiscuous ports.
+ Community — A community port is a host port that belongs to a community secondary VLAN. Community
ports communicate with other ports in the same community VLAN and with associated promiscuous ports.
These interfaces are isolated from all other interfaces in other communities and from all isolated ports within
the private VLAN domain.
Source: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/
CLIConfigurationGuide/PrivateVLANs.html#42874

Q256	
Which type of PVLAN port allows communication from all port types?
A. Community
B. Promiscuous
C. In-line
D. Isolated

Answer: B

Explanation/Reference:

The types of private VLAN ports are as follows:
+ Promiscuous – The promiscuous port can communicate with all interfaces, including the community and
isolated host ports, that belong to those secondary VLANs associated to the promiscuous port and associated
with the primary VLAN
+ Isolated – This port has complete isolation from other ports within the same private VLAN domain, except that
it can communicate with associated promiscuous ports.
+ Community — A community port is a host port that belongs to a community secondary VLAN. Community
ports communicate with other ports in the same community VLAN and with associated promiscuous ports.
These interfaces are isolated from all other interfaces in other communities and from all isolated ports within
the private VLAN domain.
Source: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/
CLIConfigurationGuide/PrivateVLANs.html#42874

Q257	
Which type of Layer 2 attack enables the attacker to intercept traffic that is intended for one specific recipient?
A. BPDU attack
B. DHCP Starvation
C. CAM table overflow
D. MAC address spoofing

Answer: D

Q258	
Which command initializes a lawful intercept view?
A. username cisco1 view lawful-intercept password cisco
B. parser view cisco li-view
C. li-view cisco user cisco1 password cisco
Parser view li-view inclusive

Answer: C

Q259	
Which two NAT types allows only objects or groups to reference an IP address? (choose two)
A. dynamic NAT
B. dynamic PAT
C. static NAT
D. identity NAT

Answer: AC

Q260	
Which IOS command do you enter to test authentication against a AAA server?
A. dialer aaa suffix <suffix> password <password>
B. ppp authentication chap pap test
C. aaa authentication enable default test group tacacs+
D. test aaa-server authentication dialergroup username <user> password

Answer: D

Q261	
Which option is a characteristic of the RADIUS protocol
A. uses TCP
B. offers multiprotocol support
C. combines authentication and authorization in one process
D. supports bi-directional challenge

Answer: C

Q262	
What are characteristics of the Radius Protocol? choose Two

A: Uses TCP port 49
B: Uses UDP Port 49
C: Uses TCP 1812/1813
D: Uses UDP 1812/1813
E: Comines authentication and authorization

Answer: DE

Q263	
Which aaa accounting command is used to enable logging of the start and stop records for user terminal sessions on the router?
A. aaa accounting network start-stop tacacs+
B. aaa accounting system start-stop tacacs+
C. aaa accounting exec start-stop tacacs+
D. aaa accounting connection start-stop tacacs+
E. aaa accounting commands 15 start-stop tacacs+

Answer: C

Q264	
Which quantifiable item should you consider when your organization adopts new technologies?
A. theats
B. vulnerability
C. risk
D. exploits

Answer: C

Q265	
what are the quantifiable things you would verify before introducing new technology in your company?
A. theats
B. vulnerability
C. risk
D. exploits

Answer: C

Q266	
Protocols supported in contest aware VRF over VRF lite? (2 choices)
A. EIGRP
B. Multicast
C. OSPF
D. UNICAST

Answer: AB

Q267	
Which three ESP fields can be encrypted during transmission? (Choose two.)
A. Security Parameter Index
B. Sequence Number
C. MAC Address
D. Padding
E. Pad Length
F. Next Header

Answer: EF

Explanation/Reference:
BD
The packet begins with two 4-byte fields (Security Parameters Index (SPI) and Sequence Number). Following these fields is the Payload Data, which has substructure that depends on the choice of encryption algorithm and mode, and on the use of TFC padding, which is examined in more detail later. Following the Payload Data are Padding and Pad Length fields, and the Next Header field. The optional Integrity Check Value (ICV) field completes the packet.
Source: https://tools.ietf.org/html/rfc4303#page-14

Q268	
Which two protocols enable Cisco Configuration Professional to pull IPS alerts from a Cisco ISR router? (Choose two.)
A. syslog
B. SDEE
C. FTP
D. TFTP
E. SSH
F. HTTPS

Answer: BF

Q269	
Which two characteristics apply to an Intrusion Prevention System (IPS) ? (Choose two)
A. Does not add delay to the original traffic.
B. Cabled directly inline with the flow of the network traffic.
C. Can drop traffic based on a set of rules.
D. Runs in promiscuous mode.
E. Cannot drop the packet on its own

Answer: BC

Q270	
When is the default deny all policy an exception in zone-based firewalls?
A. When traffic sources from the router via the self zone
B. When traffic traverses two interfaces in the same zone
C. When traffic terminates on the router via the self zone
D. When traffic traverses two interfaces in different zones

Answer: B

Q271	
Which NAT option is executed first during in case of multiple NAT translations
A. dynamic nat with shortest prefix
B. dynamic nat with longest prefix
C. static nat with shortest prefix
D. static nat with longest prefix

Answer: D

Q272	
Which three options are common examples of AAA implementation on Cisco routers? (Choose three.)

A. authenticating remote users who are accessing the corporate LAN through IPsec VPN connections
B. authenticating administrator access to the router console port, auxiliary port, and vty ports
C. implementing PKI to authenticate and authorize IPsec VPN peers using digital certificates
D. tracking Cisco NetFlow accounting statistics
E. securing the router by locking down all unused services
F. performing router commands authorization using TACACS+

Answer: ABF

Q273	
what type of address translation supports the initiation of communications bidirectionally
A. multi-session PAT
B. Static NAT
C. Dynamic PAT
D. Dynamic NAT.

Answer: B

Q274	
Which two features are supported in a VRF-aware software infrastructure before VRF-lite? (Choose two)
A. priority queuing
B. EIGRP
C. multicast
D. WCCP
E. fair queuing

Answer: BC

Q275	
Which two characteristics of the TACACS+ protocol are true? (Choose two.)

A. uses UDP ports 1645 or 1812
B. separates AAA functions
C. encrypts the body of every packet
D. offers extensive accounting capabilities
E. is an open RFC standard protocol

Answer: BC

Q276	
Which two options are advantages of an application layer firewall? (Choose two.)
A. provides high-performance filtering
B. makes DoS attacks difficult
C. supports a large number of applications
D. authenticates devices
E. authenticates individuals

Answer: BE

Q277	
Which ports need to be active for AAA server to integrate with Microsoft AD
A. 445 & 8080
B. 443 & 389
C. 445 & 389
D. 443 & 8080

Answer: C

Q278	
Which IPS mode is less secure than other options but allows optimal network throughput?
A. promiscuous mode
B. inline mode
C. inline-bypass mode
D. transparent mode

Answer: A

Q279	
Which ids/ips solution can monitor system processes and resources?
A. IDS
B. HIPS
C. proxy
D. IPS

Answer: B

Q280	
What IPSec mode is used to encrypt traffic between client / server and vpn endpoints?
A. tunnel
B. Trunk
C. Aggregated
D. Quick
E. Transport

Answer: E

Q281	
Which type of Cisco ASA access list entry can be configured to match multiple entries in a single statement?
A. nested object-class
B. class-map
C. extended wildcard matching
D. object groups

Answer: D

Q282	
Which statement is a benefit of using Cisco IOS IPS?
A. It uses the underlying routing infrastructure to provide an additional layer of security.
B. It works in passive mode so as not to impact traffic flow.
C. It supports the complete signature database as a Cisco IPS sensor appliance.
D. The signature database is tied closely with the Cisco IOS image.

Answer: A

Q283	
Which statement about zone-based firewall configuration is true?
A. Traffic is implicitly denied by default between interfaces the same zone
B. Traffic that is desired to or sourced from the self-zone is denied by default
C. The zone must be configured before it can be assigned
D. You can assign an interface to more than one interface

Answer: C

Q284	
What technology can you use to provide data confidentiality, data integrity and data origin authentication on your network?
A. Certificate Authority
B. IKE
C. IPSec
D. Data Encryption Standards

Answer: C

Q285	
With Cisco IOS zone-based policy firewall, by default, which three types of traffic are permitted by the router when some of the router interfaces are assigned to a zone? (Choose three.)

A. traffic flowing between a zone member interface and any interface that is not a zone member
B. traffic flowing to and from the router interfaces (the self zone)
C. traffic flowing among the interfaces that are members of the same zone
D. traffic flowing among the interfaces that are not assigned to any zone
E. traffic flowing between a zone member interface and another interface that belongs in a different zone
F. traffic flowing to the zone member interface that is returned traffic

Answer: BCD

Q286	
Which two statements about self-zone on cisco zone based firewall are true? (Choose two)
A. More than one interface can be assigned to the same zone.
B. Only one interface can be in a given zone.
C. An interface can only be in one zone.
D. An interface can be a member of multiple zones.
E. Every device interface must be a member of a zone.

Answer: AC

Q287	
Which two statements about the self zone on Cisco zone based policy firewall are true ? (Choose two)
A. multiple interfaces can be assigned to the self zone .
B. traffic entering the self zone must match a rule.
C. zone pairs that include the self zone apply to traffic transiting the device.
D. it can be either the source zone or destination zone .
E. it supports statefull inspection for multicast traffic

Answer: AD

Explanation/Reference:
Some have said it is E vs D. Need to research

Q288	
You are the security administrator for a large enterprise network with many remote locations. You have been given the assignment to deploy a Cisco IPS solution.
Where in the network would be the best place to deploy Cisco IOS IPS?

A. Inside the firewall of the corporate headquarters Internet connection
B. At the entry point into the data center
C. Outside the firewall of the corporate headquarters Internet connection
D. At remote branch offices

Answer: D

Q289	
What are two uses of SIEM software? (Choose two.)
A. correlation between logs and events from multiple sys
B. event aggregation that allows reduced logs storage
C. combined management access to firewalls
D. …

Answer: AB

Explanation/Reference:
This is the same question but has different available answers.

Q290	
What do you use when you have a network object or group and want to use an IP address?
A. static nat
B. dynamic nat
C. identity nat
D. static pat

Answer: B

Q291	
Which type of address translation should be used when a cisco asa is in transparent mode?
A. static nat
B. dynamic nat
C. overload
D. dynamic pat

Answer: A

Q292	
Which command do you enter to enable authentication for OSPF on an interface?
A. router(config-if)#ip ospf message-digest-key 1 md5 CISCOPASS
B. router(config-router)#area 0 authentication message-digest
C. router(config-router)#ip ospf authentication-key CISCOPASS
D. router(config-if)#ip ospf authentication message-digest

Answer: D

Q293	
Which IPS detection method can you use to detect attacks that is based on the attackers IP address?
A. policy-based
B. anomaly-based
C. reputation-based
D. signature-based

Answer: C

Q294	
Which four tasks are required when you configure Cisco IOS IPS using the Cisco Configuration Professional IPS wizard? (Choose four.)

A. Select the interface(s) to apply the IPS rule.
B. Select the traffic flow direction that should be applied by the IPS rule.
C. Add or remove IPS alerts actions based on the risk rating.
D. Specify the signature file and the Cisco public key.
E. Select the IPS bypass mode (fail-open or fail-close).
F. Specify the configuration location and select the category of signatures to be applied to the selected interface(s).

Answer: ABDF

Q295	
What feature defines a campus area network?
A. it has a single geographic location
B. it has a limited or restricted internet access
C. it has a limited number of segments
D. it lacks external connectivity

Answer: A

Q296	
Which Firepower Management Center feature detects and blocks exploits and hack attempts?
A. intrusion prevention
B. advanced malware protection (AMP)
C. content blocker
D. file control

Answer: A

Explanation/Reference:

I think the answer is A. See the Table 24-1 in the link below. Quite a few references cite AMP being the correct answer. 

https://www.cisco.com/c/en/us/td/docs/security/firesight/541/firepower-module-user-guide/asa-firepower-module-user-guide-v541/AMP-Config.pdf

Q297	
When CISCO IOS zone-based policy firewall is configured, which three actions can be applied to a traffic class? (Choose three)
A. pass
B. police
C. inspect
D. drop
E. queue
F. shape

Answer: ACD

Q298	
Which type of social-engineering attacks uses normal telephone service as the attack vector?
A. vishing
B. phising
C. smishing
D. war dialing

Answer: A

Q299	
A. Using network-specific installer package
B. Using self-signed certificates to validate the server – generate self-signed certificate to connect to server (Deployed certificates ;Issued certificate to the server likely)
C. Using application tunnel
D. Using MS-CHAPv2 as primary EAP method

Answer: B

Q300	
A Cisco ASA appliance has three interfaces configured. The first interface is the inside interface with a security level of 100. The second interface is the DMZ interface with a security level of 50. The third interface is the outside interface with a security level of 0.
By default, without any access list configured, which five types of traffic are permitted? (Choose five.)

A. outbound traffic initiated from the inside to the DMZ
B. outbound traffic initiated from the DMZ to the outside
C. outbound traffic initiated from the inside to the outside
D. inbound traffic initiated from the outside to the DMZ
E. inbound traffic initiated from the outside to the inside
F. inbound traffic initiated from the DMZ to the inside
G. HTTP return traffic originating from the inside network and returning via the outside interface
H. HTTP return traffic originating from the inside network and returning via the DMZ interface
I. HTTP return traffic originating from the DMZ network and returning via the inside interface
J. HTTP return traffic originating from the outside network and returning via the inside interface

Answer: ABCGH

Q301	
Which IOS command is used to define the authentication key for NTP?
A. Switch(config)#ntp authentication-key 1 md5 C1sc0
B. Switch(config)#ntp authenticate
C. Switch(config)#ntp source 192.168.0.1
D. Switch(config)#ntp trusted-key 1

Answer: A

Q302	
Which feature allow from dynamic NAT pool to choose the next IP address and not a port on a used IP address?
A. next IP
B. round robin
C. dynamic rotation
D. dynamic PAT rotation

Answer: B

Q303	
When AAA login authentication is configured on Cisco routers, which two authentication methods should be used as the final method to ensure that the administrator can still log in to the router in case the external AAA server fails? (Choose two.)
A. group RADIUS
B. group TACACS+
C. local
D. krb5
E. enable
F. if-authenticated

Answer: CE

Q304	
On Cisco ISR routers, for what purpose is the realm-cisco.pub public encryption key used?
A. used for SSH server/client authentication and encryption
B. used to verify the digital signature of the IPS signature file
C. used to generate a persistent self-signed identity certificate for the ISR so administrators can authenticate the ISR when accessing it using Cisco Configuration
Professional
D. used to enable asymmetric encryption on IPsec and SSL VPNs
E. used during the DH exchanges on IPsec VPNs

Answer: B

Q305	
Which two features of Cisco Web Reputation tracking can mitigate web-based threats? (Choose Two)
A. outbreak filter
B. buffer overflow filter
C. bayesian filter
D. web reputation filter
E. exploit filtering

Answer: AE

Explanation/Reference:

This one is a bit tricky aswell .. I think Exploit filtering should be one of the answers.

https://www.cisco.com/c/en/us/products/security/web-security-appliance/web_rep_index.html

Q306	
Which type of attach can exploit design flaws in the implementation of an application without going noticed?
A. volume-based DDoS attacks
B. application DDoS flood attacks
C. DHCP starvation attacks
D. low-rate DDoS attacks

Answer: D

Q307	
Which option is the resulting action in a zone-based policy firewall configuration with these conditions? ####################

source: zone1
destination: zone2
zone pair exists? Yes
policy exists? No

####################
A. no impact to zoning or policy
B. no policy lookup (pass)
C. drop
D. apply default policy

Answer: C

Q308	
Refer to the exhibit
####################

Router#show crypto ipsec sa
Interface: fastethernet0
Crypto map tag: SUM_CMAP _1, local addr 172.1.17.1.1
Protected vrf: (none)
	Local idnet (addr/mask/prot/port) : (10.40.20.0/255.255.255.0/0/0)
	Remote ident (addr/mask/prot/port) : (10.50.30.0/255.255.255.0/0/0)
	Current_peer 192.168.1.1 port 500
	PERMIT, flags=(origin_is_acl,)
	
	#pkts encaps: 68, #pkts encrypt: 68, #pkts digest: 68
	#pkts decaps: 0, #pkts decrypt: 0, #pkts verify: 0

####################

For which reason is the tunnel unable to pass traffic? 
A. UDP port 500 is blocked. 
B. The IP address of the remote peer is incorrect. 
C. The tunnel is failing to receive traffic from the remote peer. 
D. The local peer is unable to encrypt the traffic. 

Answer: C

Q309	
Which description of the nonsecret numbers that are used to start a Diffie-Hellman exchange is true? 
A. They are large pseudorandom numbers. 
B. They are very small numbers chosen from a table of known values 
C. They are numeric values extracted from hashed system hostnames. 
D. They are preconfigured prime integers 

Answer: D

Q310	
Refer to the exhibit
####################

192.168.1.11  Stateful Firewall  172.16.16.10
	     Inside		   Outside
	Source port 2300  Destination port 80

####################

Using a stateful Packet firewall and given an inside ACL entry of permit ip 192.16 1.0 0.0.0.255 any, what would be the resulting dynamically configured ACL for the return traffic on the outside ACL? 
A. permit tcp host 172.16.16.10 eq 80 host 192.168.1.11 eq 2300 
B. permit ip 172.16.16.10 eq 80 192.168.1.0 0.0.0.255 eq 2300 
C. permit tcp any eq 80 host 192 168.1.11 eq 2300 
D. permit ip host 172.16.16.10 eq 80 host 192.168.1.0 0.0.0.255 eq 2300

Answer: A

Q311	
Refer to the exhibit 
####################

Oct 13 19:46:06.170: AAA/MEMORY: create_user (0x4C5E1F60)user=”tecteam”
ruser=’NULL’ ds0=0 port=’tty515’ rern_addr=’10.0.2.13'autthen_type=ASCII
service=ENABLE priv=15 initial_task_id= 0 , vrf=(id=0)
Oct 13 19:46:06.170: AAA/AUTHEN/START(2600878790): port=’tty515' list=
action= LOGIN service=ENABLE
Oct 13 19:46:06.170: AAA/AUTHEN/START(2600878790): console enable - default to 
Enable password (if any)
Oct 13 19:46:06.170: AAA/AUTHEN/START(2600878790): Method= ENABLE 
Oct 13 19:46:06.170: AAA/AUTHEN(2600878790):status=GETPASS 
Oct 13 19:46:07.266: AAA/Al ITHEN/CONT(2600878790):contintie_login
(user=:’(undef)’) 
Oct 13 19:46:07.266: AAA/AUTHEN(2600878790):status=GETPASS 
Oct 13 19:46:07.266: AAA/AUTHEN/CONT(2600878790):Method=ENABLE 
Oct 13 19:46:07.266: AAA/AUTHEN(2600878790):password incorrect
Oct 13 19:46:07.266: AAA/AUTHEN(2600878790):status=FAIL 
Oct 13 19:46:07.266: AAA/MEMORY:free_user(0x4C5E1F60)user=’NULL’ 
ruser=’NULL’ port=’tty515' rem_addr=’10.0.2.13'authen_type=ASCII service=ENABLE 
priv=15 vrf=(id=0)

####################
 
Which statement about this output is true? 
A. The user logged into the router with the incorrect username and password. 
B. The login failed because there was no default enable password. 
C. The login failed because the password entered was incorrect. 
D. The user logged in and was given privilege level 15. 

Answer: C

Q312	
Refer to the below.
#################### 

Routerg# debug tacacs 
14:00:09: TAC+: Opening TCP/IP connection to 192.168.60.15 using source 
10.116.0.79 
14:00:09: TAC+: Sending TCP/IP packet number 383258052-1 to 192.168.60.15 
(AUTHEN/START) 
14:00:09: TAC+. Receiving TCP/IP packet number 383258052-2 from 192.168.60.15 
14:00:09: TAC+ (383258052): received authen response status = GETUSER 
14:00:10: TAC+: send AUTHEN/CONT packet 
14:00:10: TAC+: Sending TCP/IP packet number 383258052-3 to 192.168.60.15 
(AUTHEN/CONT) 
14:00:10: TAC+: Receiving TCP/IP packet number 383258052-4 from 192.168.60.15 
14:00:10: TAC+ (383258052): received authen response status = GETPASS 
14:00 :14: TAC+ : send AUTHEN/CONT packet 
14:00:14: TAC+ : Sending TCP/IP packet number 383258052-5 to 192.168.60.15 
(AUTHEN/CONT) 
14:00:14: TAC+: Receiving TCP/IP packet number 383258052-6 from 192.168.60.15 
14:00:14: TAC+ (383258052): received authen response status = PASS 
14:00:14: T.AC+ : Closing TCP/IP connection to 192.168.60.15 

####################

Which statement about this debug output is true? 
A. The requesting authentication request came from username GETUSER. 
B. The TACACS+ authentication request came from a valid user. 
C. The TACACS+ authentication request passed, but for some reason the user's connection was 
closed immediately. 
D. The initiating connection request was being spoofed by a different source address. 

Answer: B

Q313	
What is symmetric encryption? (Choose two)
A, it faster the asymmetric
B. it slower then asymmetric
C. use the certificate
D. use key pair to encript
E. uses the same key to encript and decrypt

Answer: AE

Explanation/Reference:

Have seen references to only choosing one answer, and Tut posts have said A would be the correct answer.

Q314	
Which command is to make sure that AAA Authentication is configured and to make sure that user can access the exec level to configure?

a) AAA authentication enable default local
b) AAA authentication enable local
c) AAA authentication enable tacacs+ default
d) ……..

Answer: A

Explanation/Reference:
Some questions were listed as Privilege level vs Exec level, is this the same?whi


Q315	
Which primary security attributes can be achieved by BYOD Architecture?
A. Trusted enterprise network
B. public wireless network
C. checking compliance with policy
D. pushing patches

Answer: AC

Q316	
A user reports difficulties accessing certain external web pages, When examining traffic to and from the external domain in full packet captures, you notice many SYNs that have the same sequence number, source, and destination IP address, but have different payloads.

Which problem is a possible explanation of this situation?
A. insufficient network resources
B. failure of full packet capture solution
C. misconfiguration of web filter
D. TCP injection

Answer: D

Q317	
Which of the following are IKE modes? (choose all and apply)
A. Main Mode
B. Fast Mode
C. Aggressive Mode
D. Quick Mode
E. Diffie-Hellman Mode

Answer: ACD

Explanation/Reference:
https://supportforums.cisco.com/t5/security-documents/main-mode-vs-aggressive-mode/ta-p/3123382

Main Mode - An IKE session begins with the initiator sending a proposal or proposals to the responder. The proposals define what encryption and authentication protocols are acceptable, how long keys should remain active, and whether perfect forward secrecy should be enforced, for example. Multiple proposals can be sent in one offering. The first exchange between nodes establishes the basic security policy; the initiator proposes the encryption and authentication algorithms it is willing to use. The responder chooses the appropriate proposal (we'll assume a proposal is chosen) and sends it to the initiator. The next exchange passes Diffie-Hellman public keys and other data. All further negotiation is encrypted within the IKE SA. The third exchange authenticates the ISAKMP session. Once the IKE SA is established, IPSec negotiation (Quick Mode) begins.

Aggressive Mode - Aggressive Mode squeezes the IKE SA negotiation into three packets, with all data required for the SA passed by the initiator. The responder sends the proposal, key material and ID, and authenticates the session in the next packet. The initiator replies by authenticating the session. Negotiation is quicker, and the initiator and responder ID pass in the clear.
 
Quick Mode - IPSec negotiation, or Quick Mode, is similar to an Aggressive Mode IKE negotiation, except negotiation must be protected within an IKE SA. Quick Mode negotiates the SA for the data encryption and manages the key exchange for that IPSec SA.


Q318	
Which of Diffie-Hellman group(s) is/are support(ed) by CISCO VPN Product (Choose all that apply?
A Group1
B Group2
C Group3
D Group5
E Group7
F Group8
G Group9

Answer: ABDE

Q319	
Which option is the default value for the Diffie–Hellman group when configuring a site-to-site VPN on an ASA device?
A. Group 1
B. Group 2
C. Group 7
D. Group 5

Answer: B

Q320	
What type of Diffie-Hellman group would you expect to be utiliazed on a wireless device?

A Group4
B Group7
C Group5
D Group3

Answer: B

Q321	
What are two options for running Cisco SDM? (Choose two.)
A. Running SDM from a router’s flash
B. Running SDM from the Cisco web portal
C. Running SDM from within CiscoWorks
D. Running SDM from a PC

Answer: AD

Q322	
How will the traffic be affected if policy from the self-zone is removed ?


A. all traffic will be inspected.
B. traffic will not be inspected.
C. traffic will be passed with logging action.
D. ……………..

Answer: B

Explanation/Reference:


Q323	
What is the primary purpose of the Integrated Services Routers (ISR) in the BYOD solution?
A. Provide connectivity in the home office environment back to the corporate campus
B. Provide WAN and Internet access for users on the corporate campus
C. Enforce firewall-type filtering in the data center
D. Provide connectivity for the mobile phone environment back to the corporate campus

Answer: A

Q324	
Which is not a function of mobile device management (MDM)?
A. Enforce strong passwords on BYOD devices
B. Deploy software updates to BYOD devices
C. Remotely wipe data from BYOD devices
D. Enforce data encryption requirements on BYOD devices

Answer: B

Q325	
The purpose of the certificate authority (CA) is to ensure what?
A. BYOD endpoints are posture checked
B. BYOD endpoints belong to the organization
C. BYOD endpoints have no malware installed
D. BYOD users exist in the corporate LDAP directory

Answer: B

Q326	
The purpose of the RSA SecureID server/application is to provide what?
A. Authentication, authorization, accounting (AAA) functions
B. One-time password (OTP) capabilities
C. 802.1X enforcement
D. VPN access

Answer: 

Q327	
What does ASA Transparent mode support?

A. it supports OSPF
B. it supports the use dynamic NAT
C. IP for each interface
D. requires a management IP address.

Answer: B

Explanation/Reference:


If the question is written correctly the answer is "It supports the use of Dynamic NAT". Although the configuration of an ASA in transparent mode does require a management IP address to pass traffic it is not something that is "supported" but rather configured in order to work. In the same sense, you cannot assign IP addresses to interfaces in Transparent mode so this is not supported. Options that can be supported are therefore OSPF and NAT. As referenced below OSPF does not work with ASA's in transparend mode so the only option left is NAT. 

No - OSPF supports routed firewall mode only. OSPF does not support transparent firewall mode.

Yes - NAT can be configured on the transparent ASA, but there are certain things to note. The first is that interface PAT cannot be configured because interfaces in transparent mode do not have IP addresses. The management IP address can also not be used as the mapped address.

Another thing to keep in mind is that if you configure NAT and the mapped address is not on the same subnet as the connected network, then you must add a static route on upstream device pointing to the ASA’s management IP address.

Yes - For IPv4, a management IP address is required for each bridge group for both management traffic and for traffic to pass through the ASA. For IPv6, at a minimum you need to configure link-local addresses for each interface for through traffic. 

No - Interfaces in transparent mode do not have IP address assignments.

https://learningnetwork.cisco.com/thread/88835 
https://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/route_ospf.



Q328	
What will happen with traffic if zone-pair created, but policy did not applied?
A. All traffic will be droped.
B. All traffic will be passed with logging.
C. All traffic will be passed without logging.
D. All traffic will be inspected.

Answer: C

Explanation/Reference:

I strongly believe, that answer is C, because of information in CCNA Security curriculum where was explained, that zone-pair without applied policy will pass all the traffic without any inspection. What confuses me is two variants off passing traffic in this question – with logging, and without. What logging is? Counters, syslog messages? Nontheless I am choosing C as the right answer.

Q329	
Which cisco IOS device support firewall, antispyware, anti-phishing, protection, etc.

A. Cisco IOS router
B. Cisco 4100 IOS IPS appliance
C. Cicso 5500 series ASA
D. Cisco 5500x next generation ASA

Answer: D

Q330	
What configs are under crypto map? (Choose two)
A. set peer
B. set host
C. set transform-set
D. inerface

Answer: AC

Explanation/Reference:

User reported a choose two, C was the other one chosen

Q331	
Which two options are Private-VLAN secondary VLAN types?
A. Isolated
B. Secured
C. Community
D. Common
E. Segregated

Answer: AC

Q332	
Which type of VLANs can communicate to PVLANs? (something like this) (choose 2)
A. promiscuous
B. isolated
C. community
D. backup
E. secondary

Answer: AB

Explanation/Reference:

I think Secondary was red herring (as PVLAN Terms can be Primary & Secondary)
I think there was a word or 2 missing from the above Q that helped. – but made me stop for a min or 2…

Q333	
Choose two PVLAN VLAN types:
A. Community
B. Isolated
C. promiscuous
D. Secondary

Answer: AB

Explanation/Reference:

There are mainly two types of ports in a Private VLAN: Promiscuous port (P-Port) and Host port. Host port further divides in two types – Isolated port (I-Port) and Community port (C-port).

Q334	
NAT option on ASA to stop address translation?
A. NAT none
B. NAT zero
C. NAT forward
D. ……

Answer: B

Q335	
How does Zone-Based Firewall Handle traffic to and from self-zone ?

A. Drop
B. Inspect with logging
C. Inspect without logging
D. Another option that I can’t recall

Answer: B

Q336	
What Firewall technology operates at 4 layer and above ? 
A. static filtering
B. applications firewall
C. statefull filtering
D. Circuit Level

Answer: B

Explanation/Reference:

Possible choose 2. If so C is also correct

Application layer firewalls (also called proxy firewalls or application gateways) operate at Layers 3, 4, 5, and 7 of the OSI model. Proxy services are specific to the protocol that they are designed to forward and can provide increased access control, provide careful detailed checks for valid data, and generate audit records about the traffic they transfer. Sometimes, application layer firewalls support only a limited number of applications.

Q337	
What protocol provides CIA ?
A. HA
B. ESP
C. IKEV1
D. IKEV2

Answer: B

Explanation/Reference:

Encapsulating Security Payload or ESP refers to the protocol which offers confidentiality on top of integrity and authentication to the IPSec data.

Q338	
What is the highest security level can be applied to an ASA interface?
a. 0
b. 50
c. 100
d. 200

Answer: C

Q339	
Something about distribution platform for BYOD. (Choose two)

A. on prime
B. cloud
C. hybrid cloud
D. dont remember

Answer: AB


