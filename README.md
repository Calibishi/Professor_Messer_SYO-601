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


# Change Managment

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

#







































