# cryptobscura
Pure rust implementations of less common cryptographic primitives.

## Overview
These are no-std, pure rust implementations without any unsafe code, as a result they should work on any platform the rust compiler supports.
For a specific platform these will of course not be the most efficient possible implementations.
Ciphers implement the traits specified in the [cipher crate](https://crates.io/crates/cipher).

## Block ciphers

### FROG
Candidate block cipher submitted to the AES competition by `TecApro`.
It is based on a novel approach of constructing an internal key that is treated as a program operated on the data, trying to deny the attacker
as much information about the cipher's internal operation as possible[^1].
A 1999 analysis by Wagner, et al. showcases attacks on large sets of weak keys (2<sup>-29</sup> of the keyspace for decrypt)[^2].
This implementation does not make any attempt to prevent the use of these keys. The C reference implementation is obtained from the designers directly as submitted to NIST[^1].

### Hasty Pudding Cipher
Another AES candidate, this one designed by Richard Schroeppel. It was one of the first tweakable block ciphers and is notable for 
its relatively complicated key schedule and its use of an additional *spice* parameter as a kind of secondary key[^3].
The cipher comes in five different versions depending on the required block size, this implementation includes only HPC-Medium (65-128 bits) and HPC-Long (129-512 bits).
In its original iteration the cipher suffered from weak keys (around 2<sup>-8</sup> of the keyspace)[^4] these keys drop the Security level to around 2<sup>90</sup>.
Schroeppel addressed the issue in a modified version in 1999, the full modified specification can be found in [^5].
This crate implements the newer strengthened specification, that claims to fix the aforementioned attack.

## Testing
All ciphers are tested against known ciphertext-plaintext pairs using the blobby format akin to the tests used in the [block-cipher crate](https://github.com/RustCrypto/block-ciphers/tree/master/serpent/tests/data).
These are generated using the reference C implementations where available.
These implementations live in `./references/{CIPHERNAME}`. The test vectors are chosen based on the original NIST specification for the AES competition, found in `./references/nist_kat`.
The rust implementations are also compared to the reference implementations on large sets of pseudorandom data by linking the C implementation into the rust tests.

## ⚠️ THE USUAL WARNING
This project has not been independently audited.
Some of these primitives could or do suffer from cryptographic weaknesses known and unknown.
Side channel attacks might be feasible, constant-time operation is not guaranteed for all implementations and targets.
Use at your own risk and be aware that there are lots of potential pitfalls when working with primitives directly.
<!--
## Command line tool
Included in this repository is the cryptobscura-cli that allows encryption and decryption using the ciphers. See `./cryptobscura-cli/README.md` for more details.
-->
## License
Note that no copyright is asserted over the included C reference implementations, they fall under their own respective licenses.
This crate may be licensed under the [GNU Lesser General Public License, version 2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html#SEC1).

[^1]: [D. Georgoudis, D. Leroux, B. S. Chaves, TecApro International S.A.; "The FROG Encryption Algorithm"; 1998](https://web.archive.org/web/20170708064547/http://www.grupolotusbrasil.com.br/grupoconceptprime.com.br/ftp.suporte/util/LIVROS%20E%20TREINAMENTOS/SEGURANCA/criptografia_diciplina/CIE/cd-rom/softwares/Sources/sources.pascal/frog/frog.htm)
[^2]: [D. Wagner, N. Ferguson, B. Schneier; "Cryptanalysis of Frog"; Proceedings of the 2nd AES candidate conference; NIST; 1999](https://web.archive.org/web/20251031194144/https://www.schneier.com/wp-content/uploads/2016/02/paper-frog.pdf)
[^3]: [R. Schroeppel, H. Orman; "An Overview of the Hasty Pudding Cipher"; 1998](https://web.archive.org/web/20030621202024/http://www.cs.arizona.edu/~rcs/hpc/hpc-overview)

[^4]: [C. D’Halluin, G. Bijnens, B. Preneel, V. Rijmen; "Equivalent Keys of HPC"; Advances in Cryptology - ASIACRYPT’99; 1999](https://link.springer.com/chapter/10.1007/978-3-540-48000-6_4)

[^5]: [R. Schroeppel; "Hasty Pudding Cipher Specification"; Revised 1999](https://web.archive.org/web/20110717205702/http://richard.schroeppel.name:8015/hpc/hpc-spec)

[^6]: [Puddingmeister R. Schroeppel; "The Hasty Pudding Cipher: One Year Later; 1999"](https://web.archive.org/web/20021203180746/http://www.cs.arizona.edu/~rcs/hpc/hpc-oneyearlater)

<!---
Left here for future reference
C. Burwick, D. Coppersmith, E. D’Avignon, R. Gennaro, S. Halevi, C. Jutla, S.M. Matyas, L. O’Connor, M. Peyravian, D. Safford, N. Zunic; "MARS — A Candidate Cipher for AES"; NIST AES Proposal; Revised 1999
J. Kelsey, B. Schneier; "MARS Attacks! Preliminary Cryptanalysis of Reduced-Round MARS Variants"; Counterpane Internet Security, Inc., 3031 Tisch Way, San Jose, CA 95128; 2004


Mars attacks! revisited: differential attack on 12 rounds of the MARS core and defeating the complex MARS key-schedule
Authors: Michael Gorski, Thomas Knapke, Eik List, Stefan Lucks, Jakob WenzelAuthors Info & Claims
INDOCRYPT'11: Proceedings of the 12th international conference on Cryptology in India
Pages 94 - 113
https://doi.org/10.1007/978-3-642-25578-6_9
Published: 11 December 2011
-->
