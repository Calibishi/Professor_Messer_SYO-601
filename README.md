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
  
