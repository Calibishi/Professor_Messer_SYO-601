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
- Prevention: Defence-in-depth


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
  > AKA more security vunerbilites since there's so much code.
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
  > an attack when you bombart a system, service, or network with an overflow of requests or traffic, making it unavailiable.
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

- Means unknown vulnerabilites that have not been patched/ methed of mitigation
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

- Allows attacke to sit in the middle of two devices
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

#





























