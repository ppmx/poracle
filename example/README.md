# Example: CBC Padding Oracle Attack

This is as example of a CBC padding oracle attack using [poracle](https://github.com/ppmx/poracle/).

It provides an implementation of an imaginary backend for something like a search engine.
This backend offers an HTTP-API where a frontend is expected to submit search requests.
There requests are CBC-encrypted and PKCS7-padded and base64 encoded.

This API is vulnerable to CBC-padding-oracle-attacks.


## Implementation

This example is provides the script `create_request.py` that implements a frontend constructing one imaginary search request.
To keep it simple the key used for the crypto is shared between the frontend and the backend and the search term should be kept secret for an attacker listening on the connection.

The initialization vector is the prefix of the encrypted string.


## Challenge

Here is a sniffed API Request to the backend which is running `http://127.0.0.1:8080`.

The request was: `GET /search?data=ODE3MzY0ODI5MTgyNjQwMZf5bBNoKx0M2X3LN1di9W9YwrrC935vOcf0Tb2E7YilFQA8UsJdzphd0Yb0h3DRTP5TBXYPpYArrD3qbad2iPU= HTTP/1.0`

Decrypt the string, get the query!


## Procedure

Run `service.go` and start `exploit.py` to demonstrate the attack. You first have to install the poracle package.
