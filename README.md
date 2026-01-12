# MKDF---Master Key Derivation Function

A password-based key derivation and verification tool. This tool uses Yescrypt to (1) generate the Master Key (MK) from the password; (2) hash the MK to store it; (3) the Data Protection Key (DPK) that is used to encrypt and decrypt user-specific data; and (4) the salts used; with accordance to NIST SP 800-132

## Why this tool exists
- Low level operations
- Less expensive than JS-based operations
- Safe by design

## Usage
```
$ echo "passwd" | mkdf --hash
d1a58e17f9ea11c9fe1e26654d89e6b6
sXaM6Nb2NxJvSqLdoeDF9RT3Lpzav6i62dNDAkPGXM2
1f308dde654f434535b8ff51788d2f6d
bgL/3d84vHSdXYX3GEOos3DxaLBd04UmPPbAffnh/W1
338361274f34e978baceb7df4c7143fa
```

This is an example output; the salt is randomly generated and so the hash changes too. The first line shows salt 1 that was used to hash the password and generate the DPK, the next line shows the MK's hash, followed by its salt (salt 2); then it shows the DPK and its salt (salt 3). All salts MUST be saved; the MK's hash MUST be saved too (it is used for authentication) and the DPK MUST NOT be saved but kept in memory then destroyed after the user logs out.

To verify if a given password is correct:

```
$ echo "passwd" | target/release/mkdf -v --s1 d1a58e17f9ea11c9fe1e26654d89e6b6 --s2 1f308dde654f434535b8ff51788d2f6d --s3 338361274f34e978baceb7df4c7143fa --phash sXaM6Nb2NxJvSqLdoeDF9RT3Lpzav6i62dNDAkPGXM2
Match
mpmOBtKgEiA4ZuQgSSSvcmaucS0yQYDsUviUDVcBVEB
```

Given the previous salts and the saved MK's hash, the program determines that the password is correct. It also calculates the DPK and prints it out. If we change even one character, it'll tell us that there was a mismatch: either the password, at least one salt, or the MK's hash in correct.

```
$ echo passwd | target/release/mkdf -v --s1 d1a58e17f9ea11c9fe1e26654d89e6b6 --s2 1f308dde654f434535b8ff51788d2f6d --s3 338361274f34e978baceb7df4c7143fa --phash sXaM6Nb2NxJvSqLdoeDF9RT3Lpzav6i62dNDAkPGXM1
Mismatch
```
## Contact
Maintainer: L. M. Oukaci
Email: ouka.lotfi@gmail.com
