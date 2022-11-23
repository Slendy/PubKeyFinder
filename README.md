# PubKeyFinder
Small C# program that implements the ECDSA public key recovery algorithm.

# Usage
By default this program will parse files containing PS3 NP Tickets in raw binary form and read their signature and message. 

* First argument (required)
  * Path to a directory containing the ticket files. If the path contains apces then it must be surrounded by double quotes.
* Second argument (optional)
  * A file filter that allows you to filter which files get parsed. For example if you only wanted files ending in .ticket you would use `*.ticket`
* Third argument (optional)
  * Allows you to override the hashing algorithm used on the message, by default it is `SHA1` for 192 bit signatures and `SHA224` for 224 bit signatures
* Fourth argument (optional)
  * Allows you to override the curve parameters used by the recovery algorithm, similarly to the last argument by default it is `secp192k1` for 192 bit signatures 
  and `secp224k1` for 224 bit signatures
