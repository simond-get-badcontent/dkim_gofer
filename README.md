# dkim_gofer
DKIM validation stuffs. Works best with plaintext emails. Error checking is... pretty bad.

Might be sort of interesting if looking for some form of deeper insigt into the world of DKIM.

Install notes:

pip install argparse sys email re base64 dns.resolver hashlib rsa dkim

Usage (use --help for well, "help"):

dkim_gofer_validate.py --filename PATH_TO_YOUR_EMAIL/YOUR_EMAIL.EML
