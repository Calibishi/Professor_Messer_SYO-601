# Professor_Messer_SYO-701
Notes on Professor Messer's SYO-701 YouTube Playlist

# CompTIA - Computing Technology Industry Association

# 1.1 Security Controls (7/21)

Categories:

- Technical Controls:
  -> Controls done by using systems like the operating system
  -> Ex: Firewalls, Anti-Virus

- Managerial Controls:
  -> Administrative controls tied to security design and implemtation
  -> Such as Security policies, security onboarding.

-Operational Controls:
  -> implemented by people (as opposed to systems)
  -> Security Guards, awareness programs, posters (for IT security)

- Physical Controls:
  -> Limit physical access
  -> Badge readers, Fences, locks.

Control Types:

- Preventative.
- Deterrent (like a splash screen).
- Detective.
- Corrective.
- Directive

# 1.2 CIA Triad (7/22 & 7/25)

- Confidentiality - stop the release of information before/early.
- Integrity - Messages cannot be changed without knowing.
- Availability - Networks and systems must be running and up.

- Maintaining confidentiality.
  -> Encryption. Encoding messages.
  -> Acces controls. Restricting access to a source.
  -> Multi-Factor Authentification.

- Providing Integrity. No mods.
  -> Hashing.
  -> Digital Signatures (w/Hashing).
  -> Certificates.
  -> Non-repudiaiton.

- Availability of Systems.
  -> Redundancy.
  -> Information always at fingertips.
  -> Fault tolerance. System will continue on! even after a failure.
  -> Patching. Managing and updating, stability, close security holes.

# 1.2 Non-Repudiation
  -> "Proving someone did something, such that they can't deny it after."

- Verifying information. Crytopgraphy. Your signature add non-repudiation.

- Proof of Integrity.
  -> crytographic hash. If the data changes, so does the hash.
  -> Only tells if the data has changed not the person writing it. Will talk about later how to check that.

- Hashing example of the Gutenbery Encyclopedia.
  -> The hash completely changes with one, single character change.
  -> Anyone change changes the hash.

- Proof of Origin.
  -> Ex: a signature. could be digital.
  -> Verifying public keys with digital signatures. Blockchain?
  -> Hashing private keys, decrypting  using public keys.

# 1.2 AAA - Authentification, Authorization, & Accounting (7/26)

- Starts with Identification.
- Authentication.
  -> Prove you are who you are. Passwords & other authen. techniques.
- Authorization - Now you're verified, what access do you have?
- Accounting - Logs. Login time, data sent and received, logout time.

- Triple A Servers.

- How do we truly authenticate?
  -> Oftentimes, businesses put a digitaly signed cert on the device, checked during login.

- Creating Authen.
  -> Creates a certificate for device and digitally signs the cert with the organization's Certificate Authority (CA).

- Authorization Models.
  -> AKA Abstraction. Different groups with different sets of rights and permissions. Essentially, this is OO class logic.
  -> No authorization model doesn't scale well.
    -+ Manually setting up rights and permissions would be difficult.

# 1.2 Gap Analysis (8/2)

- Where you are compared with where you want to be.
- Work towards a baseline.
  -> May be formal standards like NIST or ISO/IEC.
  -> Evaluate people and process.

- Comparison, weaknesses, & detailed analysis.
- The final analysis report.
- Path to get from current security to goal (security).

  # 1.2 Zero Trust (8/27)

- Many networks used to be relatively open on the inside.
- applying the zero-trust model, we use multi-factor auth, verification of identify via fingerprint, also encryption, system permissions, etc.

- Data Plane vs. Control Plane, C plane manages and directs the processes of the data plane which process packets, frames, and network data.
  -> Physical architecture.

- Adaptive Identity, Threat reduction control, Policy-driven access control

- Security Zones, trusted and untrusted traffic.
  -> Policy Enforcement Point.
    -> Policy Decision Point.
      -> Policy Engine and Policy Administrator.

# Physical Security (8/28)

- Physical Barriers / Bollards, can funnel traffic through a certain point + protect from vehicles and collisions
- Access Control Vestibules, could be a badge reader room and could lock/unlock various other room depending on setup.
- Fencing, barbed, bridge to cross to destination, see through fence or opaque.
- Lighting, Well lit areas deter criminals.
- Video Surveillance, could be CCTV (Closed Circuit Television), Features matter.
  -> Object Detection, Infared, Multiple Cameras networked together.
- Guards / Access Badges
- Sensors, Infared, Pressure, Microwave, Ultrasonic (detecting sound waves), facial recognition.


# Deception and Disruption (1/5/26)

- Honeypots, honeynets, honeyfiles, honeytoken (traceable data!)\


# Change Management

- Formal Process: request, purpose, scope, schedule, systems affected, risk, approval, test.
- Impact analysis.
- Sandbox Testing Environment
- Legacy Applications (no longer supported by developer).
- Dependencies
- Version Control


# Public Key Infrastructure (PKI) [1/6/26]

- policies and procedures associated w/ Digital Certificates.
- Certificate Authority.
- Symmetric Encryption - encrypt and decrypt with the same key.
  -> Doesn't scale well.
  -> Very Fast, however.
  -> Usually used together with Asymmetric E.
- Asymmetric Encryp - Two or more mathematically related keys.
  -> Private and public key.
    -{ The private key decrypts.
    -{ Cannot derive the private key from the public key.
  -> Everyone who has public key can excrypt the data using the public key.
  -> PGP / GPG
  -> Ex: Asymmetric Software, Ciphertext, Encrypted Data


# Encrypting Data

[ E / e = encryption]

- Ecrypting Data at rest
- Full Disk - BitLocker, FileVault, File e - EFS
- Transparent and Record-Level E
- Column-Level E
- VPN
- Encryption Algorithms, agreed upon before, compatibility.
- Cryptographic Keys
  -> Larger keys, more security.
  ->128-bit or larger symmetric keys, currently common.
- Key Streching: perform the encryption process multiple times (hash-slinging-slash-hashing slasher


# Key Exchange

- Out-of-band key exchange: exchanging the key without the 'net.
- In-band key exchange: sent over the network (faster).
- Symmetric session keys
- Public and Private key cryptography


# Encryption Technologies

- TPM - Trusted Platform Module: key generators.
- Large scale -> HSM - Hardware Security Modules, thousands of crypto-keys.
- Cryptographic accelerators.
- Key Management System, one centralized manager
- SSL/SSH/TLS Keys
- Secure Onclave - separate processor soley for protecting data.
  -> boot ROM
  -> True RNGenerator
  -> AES encryption
  -> root crypto keys & more.


# Obfuscation (w/ Stenography)

- Process of making something unclear/ hard to understand.
- like hiding objects in plain sight.
- Steganography - Greek for "Concealed Writing."
  -> hiding text in images (invisible)
  -> Network based: embed messages in TCP packets.
  -> Invisible watermarks: yellow dots on printers.
    -{In EKGs lol -}, Video, Audio Steg
  -> Tokenization.
    -{Take sensative data and replace it w/ non-sensative placeholder}
      -[ Credit Card Processing]
    -{Remote Token Service Servers}
  -> Data Masking - like hiding the Credit Card number on receipts.


# Hashing and Digital Signatures

- Cryptographic Hash, verification/integrity for downloaded documents.
- Digital Signatures used for authentication, non-repudiation, and integrity.
  -> non-repudiation: ensures that someone involved cannot deny receiving or sending information because their digital fingerprint is on it.
- SHA256 hash
  -> 256 bits / 64 hexa characters.
- Hash functions.
  > Collision: Different input into hashing alogorithm, but the same output hash.
    {Example with MD5, don't use this hashing algorithm).
- Salted Hashes, adding additional information (random salt).
- Rainbow Tables - reverse engineering hashing, doesn't work with salted hashes.
- Verifying digital signatures.


# Blockchain Technology

- Distributed Leger (Cryptocurrencies)
- Everyone on blockchain network maintains the ledger.
- Many uses.


# Certificates

- Contains public key and digital signature.
- Trust.
  > Certificates provide additional trust.
  > Web of Trust. Say if a trusted friend signs/approves something.
- Clicking the lock in web browser.
   > View Certificate -> X.509 Standardized Format (Certificate Details).
- Root of Trust.
- Ceritifcate Authorities (CA)
- Built-in CAs into any browser.
- Public vs. Internal CAs
- Subjest Alternative Name (SAN)
  > Wildcard domains.
- Certificate Revocation List (CRL) - certificated that have been revoked.
- OCSP stapling - Online Certificate Status Protocol.
  > sending status messages into SSL/TLS handshakes, with digital CA.


# Threat Actors (who did it?)

- Internal or External
- Resources/funding
- Level of Sophistication/capability
- What are the motivations? Their Purpose.
  > Motivations: Espionage, Competitiors, Blackmail, Financial, etc
- APT: Advanced Persistent Threat.
  > Stuxnet Rabbit hole example.
- Pre-made scripts, unskilled attackers.
- Hacktivist - hacker activist.
- Insider Threats
- Professional Threats
- Shadow IT
  > IT gone rouge.


# Threat Vector (Attack Vectors)

- Common to start with messenging systems like email with malicous links (phishing).
- SMS (Short Message Service)
- Social Engineering Techniques
  > Invoice scams,
- Image-based Vectors, SVG in XML (Scalable Vecotr Graphic) could put HTML, Javascript that has malicous code.
  > Cross-site scripting attacks.
  > XML embedding.
- Infected Executables in file format, PDFs
- ZIP/RAR files
- Vishing - Voice phising
- Spam over IP
- War Dialing, unpublished phone numbers
- Call Tampering, disrupting voice calls.
- Removable device vectors
  > malicious software on usb flash drives.
  > air-gapped networks.
  > leaving usb drives in public places.
- Agentless vulnerable software vectors.
- Unsupported System Vectors.
  > Patching.
  > Always update the list of devices and OSes with access.
- WPA3 PRotocol is latest security protocol atm.
- Wired - No 802.1X
- Bluetooth
- Open Service Ports
- More services you have to install, more "open ports."
- Firewalls.
- Default Credentials on most devices.
  > Always change the default username and passwords.


# Phishing

- Social engineering with a dab of spoofing
  > email, text, etc.
- Usually something is off.
- Spoofed emails, financial fraud, malicous links
- Typosquatiing (be careful with URLs)
- Lying, asta.
- Vishing/Smishing
- Bunch of scams.


# Impersonation

- Identity Fraud.
- Prevention
  > Never volunteer information.
  > Don't disclose personal details over the phone.
  > Verify the person yourself.
    -{ Check the phone number is the same as the public one for the company.


# Watering Hole Attack

- Using a website or server and compromising it.
- The attacker could be find a commonly visited site that target uses and infect it.
- Hence, it's like infecting a watering hole and poising those who drink from it.
- Prevention: Defence-in-depth.


# Other Social Engineering Techniques

- Making Misinformation/Disinformation
- To sway public opinion.
- Advertising.
- Often through Social Media.
  > Could be an account with fake followers.
  > This will trigger the popularity algorithm and have it spread over the platform.
- Brand Impersonation.


# Memory Injections

- Malware runs in memory.
  > memory contatins many running processes.
    -{DLLs (Dynamic Link Libraries), Threads, Buffers, Memory management functions, & much more}
  > malware runs it's own process or inject itself into the middle of a process.
-  .... Between starting address and Ending Address, Malicious DLLs on the disk ....


# Buffer Overflows [Attacks] (1/8/26) 

- An attacker writes more than expected into another section of memory.
  > Developers need to perform bounds checking (8 bytes for 8 byte sections).
- Attacker is looking for a repeatable overflow function that give advantages like rights and permissiions.


# Race Conditions

- Unplanned things/processes running at the same time.
  > TOCTOU - Time-of-check to time-of-use attack
  > Mars rover "Spirit" race condition (January 2004)
    -{ Developers sent additional code to fix it while still on Mars!}


# Malicious Updates

- Always keep OS and applications up to date.
- ALWAYS have a good back up.
  > Back up often.
- Downloads updates directly from developers site, not 3rd party websites.
- Automatic updates are good, including checks and digital signatures.
  > Can still contain malicious software.
  > SolarWinds Orion attack from infaltrating a companies software and planting malware in their automatic updates.
    -{ Attackers gained access to multiple government agencies and companies}


# Operating Systems

- Big target for attackers.
- Pretty Complex.
  > AKA more security vulnerabilites since there's so much code.
- Patch Tuesday (Windows)
- Best practice: Make sure you have a backup before downloading/updating/patching.
  > If updating multiple systems, use a testing environment and have backups.


# SQL Injection (SQLi)

- Added malware due to improperly programmed input and output.
- Put your own SQL requests in an existing app.
- Example: "SELECT * FROM user WHERE '1' = '1'"
  > IOW, show me everything.
- WebGoat - application that is made to have vulnerabilities (good practice).


# Cross-site Scripting (XSS)

- Vulnerabilities across multiple browsers
- Often done in JavaScript.
- Legitimate website + malware that send info back to the attacker.
- Persistent (Stored) XSS attack.
  > Such as a SM post on FaceBook.
- Example: June 2017, Subaru, A token that never expires, found by Security researcher.
- Consider limiting or disabling JavaScript.
- If you're an App developer,
  > Make sure that you check that your inputs are validated so that a user cannot add their own script.


# Hardware Vunerabilities

- Garage Doors, Light bulbs, door locks, refridgerator, etc.
  > Everything connected to the network.
- Firmware - OS of the hardware device.
  > Usually only updated by Vendors.
- EOL: End-of-Life
  > Manufacturer stops selling, stops supporting/updating.
    -{ Probably time to get a new device.]
- EOSL: End-of-service-life - MORE URGENT than EOL.
- Legacy devices - older OS, apps, middleware, EOL software.
  > May add additional firewalls, IPS signatures, security.


# Virtualization Security (beauty)

- Virtual Machines.
- Not possible to move from on VM on a hypervisor to another VM on a hypervisor, unless huge vulnerabilities. Usually difficult, but of course not impossible.
- Hypervisor are the virtual "pretend" hardware that VMs run off of like VirtualBox and VMWare, these are pretty complex.
- Resource Reuse
  > Hypervisor allocates resources, memory could be shared (6GB over 3 VM (2GB each) with 4 real GB).
    -{ The reason why we can go over is because
      1) The VM is allowed up 2GB for ex, but not all of it is usually used all at once.
      2) If there are all used simultaneously, then some memory will just be written on the disk, which will make things a bit slower.


# Cloud-specific Vunerabilities

- DoS - Denial of Service (DDos - Distributed...)
  > An attack when you bombart a system, service, or network with an overflow of requests or traffic, making it unavailiable.
  > DDoS is just with multiple distibuted devices versus a single device.
- Authentication bypass
- Directory traversal
- Remote Code Execution
- XSS could be used if not patched / input validated.
- Out of bounds writing.
- Rabbit hole with trying to fix DoS attacks, having both public and private networks, VPNs, firewalls, and NAT (Network Address Tranlation).
  > NAT is what blocks unsolicited traffic by dropping packets that do match an existing outbound connection in the translation table.
    -{ NAT asks “does this packet match a connection that was initiated from inside?”}


# Supply Chain Vulnerabilites

- Supply chain has many moving parts.
  > The physical hacking, per se, could happen.
- Always presume that there is some security risk, vet accordingly.
- Verify digital signatures.


# Misconfiguration Vulnerabilities

- Open permissions.
- Linux root / Windows Admin
- Some protocols are not encrypted:
  > Telnet,
  > FTP,
  > SMTP,
  > IMAP.
- How to check? View the packet capture.
- Use encrypted versions (SSH, HHTPS, SFTP, IMAPS, etc.)
- Wall of Sheep at DEF CON.
- Default configurations and passwords.
  > Mirai botnet, over 60 default configs.
  > Open source, used by attackers and researchers.
- Services mean open ports
  > Crack in the doorway of access.


# Mobile Device Vulnerabilities

- Jailbreaking (MacOS) / Rooting (Andriod)
  > More features but less security.
  > Often not allowed.
- Sideloading apps through jailbroken/rooted systems without an app store.


# Zero-Day Vulnerabilities

- Means unknown vulnerabilites that have not been patched/ method of mitigation
  > cve.mitre.org (Common Vulnerabilities and Exposures)


# An Overview of Malware

- Any software that is bad.
  > Viruses,
  > Worms,
  > Ransomeware, attacker encryts all data on system, often request money in exchange.
  > Trojan Horse,
  > Rootkit,
  > Keylogger,
  > Spyware,
  > Bloatware,
  > Logic Bomb,
- Always have a backup.
  > Rabbit hole with HDD/SSD, bootable clone, which drives to get and how Time Machine / bootable clones actually work.
- Anti-virus / Anti-Malware for systems.


# Viruses and Worms

- Malware that can replicate itself.
  > through file systems or network.
  > Some are invisible: run in the background.
  > Update the signature file up to date.
- Program Viruses, Boot sector viruses, Script Viruses, Macro Viruses, Fileless Virus.
- Worms can get bad quick.
  > Wannacry worm example.


# Spyware and Bloatware

- Spyware: malware that spies on you.
  > Browser monitoring,
  > Keyloggers: capture every stroke and send them back o the attacker.
- Maintain AV/AM (Anti-Virus/Anti-Malware)
- Always reasearch the applications or anything you download.
- Bloatware: With new devices/systems, these are apps installed by the manufacturer.
  > Takes up storage,
  > Could make system slower,
  > Any application could be exploited.
  > Solution: remove it, if you can, or run an uninstall the software somehow. Find a way lol. Use 3rd party uninstallers as a last resort.


# Other Malware Types

- Keyloggers
  > Can store clipboard info, screenshots, instant messaging, and search engine queries.
  > RAT - Remote Access Trojan.
- Logic bomb: Waits for a predefined event or time (Time bomb).
  > South Korea, 2013, bank email with attachment that activated at a specific time.
  > Difficult to find.
- Can be prevented with monitoring tools to look at key files for changes.
  > Alert on changes, constant auditing.
- Rootkit: (from Unix) hides in the kernel of the OS.
  > Won't see it in Task Manager since it's in OS.
  > Hard to see, hard to stop.
  > solution: standalone rootkit removal tools, only used after infection.
  > solution: secure boot with UEFI.
    -{ Will look for an OS signature and see if anything has changed and stop it from running if it finds anything}


# Physical Attacks (J)

- Old school.
- Someone with physical access can get full control.
- "Door locks only keep out honest people." C'est Vrai.
- Brute Force (physically).
- RFID: Cloning (Radio Frequency Identification)
  > Low frequencey, electromagnetism, reflecting radiowaves back.
  > Access Badges,
  > Key fobs,
  > Duplicators are on Amazon for < $50 lol.
  > One solution is MFA (Multi-factor-authentication)
- Environmental attacks
  > Power outage.
  > HVAC control system.
  > Fire suppression w/potential DoS.


# DoS (Denial of Service)

- Attacker forces a service to fail.
  > Via Overloading system,
  > Exploiting a design failure or vuln,
  > Could be a distraction/smokescreen for other nefarious activities,
  > Could be a power outage simply.
- Network DoS
  > Layer 2 loop with STP (unintentional closed loop),
- Bandwidth DoS,
- Unintentional DoS
- DDoS: Distributed Denial of Service.
  > Army of computers, traffic spike, botnets.
    -{ Thousands/millions}
    -{ Zues example}
- DDoS reflection and amplification.
  > NTP, DNS (uses the 'dig' command), ICMP protocols.
- Botnet Command and Control -> Botnets -> Open DNS resolver (for ex) -> Huge output then sent to the server.


# DNS Attacks

- DNS poisoning.
  > Could cause user to visit unintentional IP address.
  > Some include modifying DNS server itself (though pretty difficult/protected).
  > Modify the client host file with permissions.
  > Sit in the middle of DNS query request, requires a redirection of the request [on-path attack].
- DNS spoofing/poisoning.
  > Via exploiting the OS of administrative access to the DNS server, the attacker will change the destination to their IP address and route the user's request to them attacker.
- Domain Hijacking.
  > Access domain registration, where the traffic is controlled.
- URL Hijacking.
  > Advertising, redirect for adverts for revenue stream.
  > Could sell the misspelled domain name to the domain name owner.
  > Redirect traffic to a competitior.
  > Phishing site for login credentials.
  > Infect w/ drive-by download.
  > Typosquatting/brandjacking.
  > Different top-level domain: .com versus .org


# Wireless Attacks

- Dropped Wireless Networks
  > Wireless Deauthentication, significant wireless DNS attack.
  > 802.11 management frames (vulnerability)
  > "in the clear" = NOT encrypted
  > Need to know the Mac Address / Hardware Wifi Address.
  > IEEE has addressed this with 802.11ac and newer.
  > RF jamming (Radio frequency)
    -{ Prevents wireless communication from anyone nearby by decreaing the signal-to-noise ratio at the receiving device. Receiver can't hear the good signal (send or receive traffic}
    -{ Constant, random bits, legit frames, reactive jamming, random times.}
    -{ Attacker is nearby, get ready for the fox hunt, attenuator, directional antenna.}


# On-Path Attacks

- Allows attacker to sit in the middle of two devices
  > Man-in-the-middle attack.
  > Both parties would have no idea, mostly.
  > ARP poisoning (spoofing), attacker must be on the same subnet.
    -{ARP doesn't have an authentication for the intended device, hence this attack.}
- On-path browser Attack.
  > Malware configured as a proxy, can redirect traffic being sent and requested.
  > Waits for login info. and then exploitation.


# Replay Attacks:

- Needs information that can be replayed:
  > Via Network tap, ARP poisoning, or malware.
  > May be used with on-path attack.
- Pass the hash bruv (replay attack).
  > During authentication process.
  > Attacker captures username and hashed password.
    -{ Now attacker has access to the user's account.}
  > One solution: encryption accross the network and salted hashes.
- Browser cookies and session IDs.
  > Files that store information on computer by the browser.
  > Session IDs, Session Hijacking.
    -{ The attacker would use this ID to make the Web server think that it it the user visiting the site instead of the (actual) attacker.
- Header manipulation.
  > Packet Capture via Wireshar, Kimet and others.
  > Modify headers.
  > Modify cookies.
- Prevent session hijacking: Encrypt everything with something like HTTPS.
  > Encryption end-to-end.
  > Encryption end-to-somewhere (Personal VPN).


# Malicious Code

- Executables, scripts, macro viruses, worms, Trojan horses, etc.
- Needs strong defences:
  > AM,
  > Firewalls,
  > Continuous updates and patches
  > Secure Computing habits.


# Application Attacks (1/9/26)

- Injection Attacks.
  > SQL, HTML, XML, LDAP.
- Buffer Overflow.
  > Overwriting a buffer with memory, spills over.
  > Not simple, but powerful attack.
- Replay Attack review.
  > May start with an on-path attack.
- Privilege escalation.
  > Horizontal Privilege escalation, from user A to user B.
- Data Execution Prevention
- Address Space Layout randomization.
- Cross-site requests.
  > Client runs HTML, JavaScript often.
  > Server side, performs requests, HTML, PHP, transfer of money, uploading.
  > Cross-site request forgery, one-click attack, session riding (XSRF, CSRF (Sea Surf).
  > Solution could be a cryptographic token.
  > Ex: Someone is already logged into bank website, then they click a malicious link while this page is open granting the attacker a way in.
- Directory Traversal / Path Traversal
  > '../../' is a check to see if that server is susceptible to these traversals.


# Cryptographic Attacks

- The key is.. well... the key.
- If the algorithm is secure, the implementation of it is where the attacker will go.
- Birthday Attack.
  > Hash collision, same hash value for two different plaintexts.
  > Brute Force.
- Collisions.
  > MD5 (Message Digest Algorithm 5) was compromised.
- Downgrade Attack.
  > SSL Striping.
  > Attacker sits in the middle of the conversation.


# Password Attacks

- Some apps store passwords "in the clear" (huge risk).
- Stop using any apps that do this.
- All passwords should be stored as a hash.
  > Hash - data as a fixed-length string of text.
  > Every different input shouldn't have the same hash.
  > Non-reverse-engineerable.
  > Ex: SHA-256 hash (common)
- Spraying Attack.
  > Top 5 Passwords (on Wikipedia smh).
  > Used on multiple users only a limited time to not trigger any alarms or lockouts.
- Brute Force.
  > Process: After receiving the hash, they start hashing various passwords to get a match.
    -{ Usually, they obtain a list of users and hashes. Then it's just a matter of time and resources.}


# Indicators of Compromise (IOC)

- event that indicates an intrusion.
  > Such as a large amount of traffic.
  > Change to file hash values.
  > Irregular internation traffic.
  > Changes to DNS data.
  > Uncommon Login Pattersn
  > Spikes of read requests to certain files.
  > Can't download security or update app.
- Account is locked out not because of user.
  > Help desk impersonation to get password reset.
- Concurrent session usage (good way to check if there is activity somewhere else).
  > Example with google mail account.
- Authentication logs can be telling.
  > Say a login from the US and the same user logs in from AU.
- Resource consumption (Cyber-Detecting).
  > Every attacker's attack has an equal and opposite reaction (Newton's 3rd Law).
- Resource inaccessibility.
  > Server may be down.
  > Network disruption to coverup the actual exploit.
  > Server outage, exploit gone wrong.
  > Encrypted data (possible ransomware).
- Out-of-Cycle Logging.
  > Log everything you can.
  > OS patch logs.
  > Look out for obscure times for traffic flow.
- Missing Logs.
  > Attacker could delete logs, since logs are evidence.
  > Set up notifications to indicate when logs are missing.
- Private Information is published / documented.


# Segmentation and Access Control

- Segmenting the network.
  > Into smaller events.
  > Devices, VLANs, or virtual networks.
  > Performance.
  > Security, users should not talk directly to database servers.
  > Compliance, mandated segmentation by Compliance company.
- Access control lists (ACLs)
  > Allow or disallow traffic.
  > Restrict access to network devices.
  > used by many OS
- Application allow list / deny list.
- Application hash.


# Mitigation Techniques

- Patching.
  > Auto update might not be best. Should be tested.
- Encryption.
- File level encryption.
- Full disk encryption (FDE)
  > Bitlocker, FileVault, wtc.
- Application Data Encryption.
  > Manages by app, stored data protected.
- Monitoring and Logs
  > Built-in sensors, separate devices.
  > Collectors, SIEM consoles.
- Least Privilege.
  > Rights and permissions should be set to the bare minimum.
  > All user accounts must be limited.
- Configuration Enforcement.
  > Posture Assessment, each time a device connects.
  > OS patch version, EDR (Endpoint Detection and Response)
  > Certificate status.
  > Systems out of compliane are quarantined.
- Decommissioning old equipment.
  > Hard drive.
  > SSD
  > USB drives.
  > Recycle / Destroy device and drives.


# Hardening Techniques

- System hardening.
  > Always include security updates.
  > User Accounts secured by (at least) passwords.
  > Account limitations.
  > Limit Network Access.
  > Monitor and Secure.
  > Encryption.
    -{Specific files or FDE, Encrypt network communication with VPN)
- The Endpoint.
  > EDR. Very Nice.
    -{Signatures, Behavorial analysis, ML, process monitoring, lightweight agents}
    -{Root cause analysis on the threat.}
    -{Can immediately take action: isolate, quarantine, and rollback.}
- Host based firewalls.
- Host-based Intrusion Prevention Systems (HIPS).
- Each time you install an outward facing service, ports and opened inside the OS.
  > Close as many as possible except required.
  > Each open port is a potential vulnerability.
  > Control access with firewalls (best is NGFW: Next Generation Firewall).
  > Applications with broad port ranges are terrible practice (ex: 0 through 65.535)
  > Nmap, for scanning availiable port on a system.
- Default password changes.
  > Centralized A/MFA.
- All Software contain Bugs.
  > remove unused software.


# Cloud Infrastructures.

- Cloud responsiblity matrix.
  > Iaas, Paas, Saas [Infrastructure, Platform, and Software... As a Service], On-Prem (On Premises) etc.
  > Who is responsibility for security?
  > Cloud Providers and matrix of responsibilites.
- Hybrid Cloud (multiple clouds)
  > Extra complexity, network protection mismatches, data leaks across sharing.
- Third-party vendors, incident response, and monitoring constantly.
- Infrastructure as a code, one program for different providers.
- Serverless Architecture (FaaS: Function..), application instance with no server.
- Microservices and APIs.
  > Monolithic apps: one big application does everything.
  > Application Programming Interfaces.
    - scalable, resilient, containment is built in.
    $ Rabbit hole on APIs: they just connect apps together.
      + For ex, Uber uses 100 plus other apps through APIs.
      + User Interface [UI] vs API
      + Enpoints on the Back end puzzle piece.
      + YT, API keys and Docs.
      + Zapier, automations.


# Network Infrastructures Concepts

- Physical Isolation.
  > Air Gaps between switches.
- Logical segmentation with VLANs.
- SDN (Softare Defined Networking):
  > 3 Planes: Data, Control, and Management planes.
- Infrastructure layer / Data plane - process network frames and packets.
- Control plane/layer - routing tables, session tables, NAT tables
- Application layer - Management, configure and manage the device, SSH, browser, API
- How the physical architecture correlates to these 3 planes on the back of switch.


# Other Infrastructure Concepts

- Attacks can happen anywhere: even on-prem and in the cloud.
- On-Prem: On site IT Team, expensive though, difficult to staff.
  > Security changes can take time.
- Centralized vs. Decentralized.
- Virtualization.
  > Each VM needs an OS.
  > Infrastructure (physical) -> Hypervisors (manage VMs) -> VMs that run OS.
- Versus Application Containers.
  > Docker.
  > Another way to run multiple applications on one device, except there is only one Host OS.
- IoT: Internet of Things.
  > Sensors like the ones in alarm systems.
  > Home automation.
  > Video Doorbells.
  > Wearable Tech.
  > Weak Defaults.
- SCADA: Large scale IoT, basically.
- RTOS (Real-Time OS).
  > Using a non-deterministic OS.
  > Deterministic OS: in cars, military things, and industrial equipment, in cars for ex: the brakes takeover when you press them..
  > Depends on what you need.
- Embedded Systems.
- High Availability (HA).
  > Redundancy does NOT always mean available.
  > In short, it's a backup. Like a backup firewall.
  > Expensive though.


# Infrastructure Considerations (1/10/26)

- Availability.
  > resources are up and running, only to the right people.
- Resilience.
  > Can you bounce back? How fast?
- MTTR - Mean Time To Repair: Time it takes to replace the parts that are not available with ones that are available.
- Cost.
- Responsiveness.
  > How quick? [Flashback of Goldman Sach's 15 minute rule]
- Scalability.
- Ease of deployment.
  > Many moving parts: Web server, database, caching server, firewall, etc.
  > Cloud based ifrastructure (CBI), Orchestration (building a CBI on demand instantly) / automation.
- Risk Transference.
  > Cybersecurity Insurance, popular with rising ransomware attacks.
- "The only constant is change."
  > Patch Availability.
  > Patch early. Patch often.
  > Test in an sandbox/testing environment, then deploy.
- Inability to patch (crazy work in our age, depending on what one does).
  > HVAC controls, Time Clocks.
- Power ["We must turn on the Power!"]
  > On-Prem Data Center versus providers.
  > UPS - Uninterruptible Power Supply (for important matters such as life support in a hospital).
  > Generators.
- Compute Engine.
  > May be 1 processor or multiple.


# Secure Infrastructures

- Device Placement.
  > Differs in every network.
  > Firewalls, Honeypots, jump servers, load balancers.
- Security Zone.
  > Each section of the network can be accessed in a specific zone.
  > Untrusted  /  Trusted or Inside / Screened / Internet.
- Attack surface [The Gold]
  > How will the attackers come, if any?
    {Doors, Windows, App Code, Open ports, Auth process, Human error}.
  > We—-of course-- want this minimized.
  > Network Connectivity, better for this to be covered up as it runs through cables in the building.
  > App level, Network-level encryption.
    (IPsec tunnels, VPN connections.)


# Intrusion Prevention

- IPS, designed to watch traffic in real time.
- Intrusions.
- Detection vs. Prevention
  > Prevention stops it before it gets into network.
  > Detection just alarms or alerts.
- Failure modes.
  > Fail-Open, data will continue to flow, even though security process will not operate.
  > Fail-Closed, when system fails, data does not flow through.
- Active monitoring, data can be blocked in real-time.
  > Passive monitoring, IDS design, data cannot be blocked in real time, switch takes a copy of traffic and sends it to IPS.
    {copy, Port mirror (SPAN), network tap, common in detection systems.}


# Network Appliances

- Jump servers.
  > Access secure network zones from the outside.
  > 2 steps: External client -> jump server -> then SSH/Tunnel/VPN into the Web Server.
  > Big security concern if compromised.
- Proxies: sits between the users and external network.
  > Explicit Proxy.
  > Transparent Proxy.
  > Application Proxies (common), HTTP proxy, HTTPS, FTP, etc.
  > NAT (proxy) - Network Address Translation.
  > Forward/Internal Proxy, controls outbound traffic from user making request to the internet.
  > Reverse Proxy.
    {Can Pull from Cache, Controls inbound traffic from the Internet to the user}
  > Open Proxy, significant security risk, 3rd party, uncontrolled.
  > Load balancers.
     {Active/active, load caching, content switching, SSL offload.
    {Active/passive, some servers are active, others on standby if some fails.}
  > Sensors and collecters.
  > Security and Event Manager (SIEM)


# Port Security (1/15/26)

- Refers to indiviual interfaces on aswitch or connections to a wireless access point.
- Username and password with wifi for ex.
- EAP (Extensible Authenication Protocol)
  > Authentication protocol.
  > EAP integrates 802.1X [Port based Network Access Control (NAC), which prevents access to the network until authentication succeeds.
    {Supplicant (User system), Authenticator, & Authentication Server.}


# Firewall Types

- Standard, control the traffic between two points, corporate control on outbound & inbound data, control of bad content and malware.
- A network based firewall traditionally control traffic in OSI layer 4 (TCP or UDP port number).
  > Next-Gen Firewalls (NGFW) can do this in OSI layer 7 (the Application layer).
- Firewalls can also integrates VPNs, can operate as a router (layer 3 device), NAT (Network Address Transmission) functionality.
- (Older firewalls) UTM - Unified Threat Management / Web security gateway.
  > URL filter / content inspection / spam fileter, CSU/DSU, IDS/IPS, Firewall, Bandwidth shaper, VPN endpoint.
  > Cons: Only operate at layer 4 (port numbers), many features tend to slow down the firewall.
- NGFW - OSI Application Layer operation, making forwarding decisions.
  > Also called Application layer gateway, Stateful multilayer inspection, Deep packet inspection.
  > Full packet decoding, control traffic, who sent, what is sent, and where it should go.
  > Intrusion Prevention System functionality.
  > Content filtering (URL filtering, traffic control by category).
- WAF (Web application firewall).
  > Not like Next-Gen or UTMs, filters content based on input in web applications, like blocking SQL injection reaching the server.
  > Can be used with Next-Gen firewalls (different traffic lookout).


# Secure Communication

- Virtual Private Networks
  > Encrypts all private data going across a public network.
  > Can be in hardware or software.
  > Encrypted Tunnel, VPN Concentrator.
    {Encrypted packets, IPsec Headers and Trailers.}
  > SSL (Secure Sockets Layer) / TSL (Transport Layer Security) VPN.
      {runs over TCP/443 (web server traffic)}.
      {Almost no firewall issues.}
      {Can be run from browser or a light VPN client.}
- Site to Site IPsec VPN
  > VPN concentrators on both sides.
- SDN WAN (Software Defined Networking in a Wide Area Network)
  > Data centers are now in the cloud many times vs. one central one on site.
  > More efficient than just the cloud.
- SASE - Secure Access Service Edge
  > a "Next-Gen" VPN.
  > SASE on all clients.
  > sits between Users/Offices and Cloud services.
- Picking the right secure choice can be tough.


# Data Types and Classifications (1/16/26)

- Data Types
  > Regulated, managed by a third-party | Trade secrets, org's secret formulas | Intellectual Property | Legal Information | Financial Information
  > Human-readable, Non-human readable (barcodes).
- Classifying sensative data.
  > And adding permissions, restricted network access.
- Proprietary, property of an org, unique to an org, may have secrets.
- Sensative, PII [Personally Identifiable information], PHI, Protected Health Information


#













  







