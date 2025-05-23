#!/usr/bin/python3
"""
A project to parse out and validate DKIM signatures. It can also do stuff like
detecting if a signature is invalid due to headers or body mismatches.
"""

import argparse
import sys
import email
import re
import base64
import dns.resolver
import hashlib
import rsa
from email.policy import default
import dkim

# --------------------------------------------------------------------------------------------------
# DKIM Gofer - Validate
# --------------------------------------------------------------------------------------------------
# DKIM Gofer: Validates a DKIM signature in the provided EML file.
# Read: https://datatracker.ietf.org/doc/html/rfc6376
# --------------------------------------------------------------------------------------------------
# Author: Simon Lundmark
# --------------------------------------------------------------------------------------------------
# Changelog:
# 2025-05-23: Created and tested. //Simon
# --------------------------------------------------------------------------------------------------
# Install notes:
# pip install argparse sys email re base64 dns.resolver hashlib rsa dkim
# --------------------------------------------------------------------------------------------------
# Current version:
VERSION = "v. 0.1"
# --------------------------------------------------------------------------------------------------
# Usage (use --help for detailed help):
# Example 1: Run with all default values and tample data:
# ./dkim_gofer_validate.py --filename ./email/test_signed.eml
# --------------------------------------------------------------------------------------------------

PARSER = argparse.ArgumentParser(
    description='''Supply an EML or similarily structued file containing an email. ''',
    prog='DKIM Gofer')

PARSER.add_argument('--version',
                    action='version',
                    version='%(prog)s 0.1')
PARSER.add_argument('--filename',
                    required=False,
                    type=str,
                    help="user defined filename (example: email.eml)")
ARGS = PARSER.parse_args()

# Default line delimiter
line_delimiter = "\n" + "-"*80


def parse_dkim_signature(header_value):
    """
    Parses a DKIM-signature header into a dictionary of tag-value pairs,
    prints all parsed fields.
    """
    tag_value_pattern = re.compile(r"([a-z]+)=([^;]+)")
    pairs = {match.group(1): match.group(2).strip().replace(" ", "") for match in tag_value_pattern.finditer(header_value)}
    print(line_delimiter)
    print("Parsed DKIM-Signature header fields:\n")
    for k, v in pairs.items():
        print(f"  {k}= {v}")
    return pairs


def fetch_public_key(selector, domain):
    """
    Fetches the DKIM public key for the given selector and domain.
    Returns the base64-encoded public key as a string, or None on failure.
    """
    name = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(name, "TXT")
        # Concatenate all TXT record fragments into a single string
        txt = "".join([part.decode() if hasattr(part, 'decode') else part for r in answers for part in r.strings])
        print(line_delimiter)
        print("TXT DNS record found:\n")
        # Pretty print the TXT record
        for pair in txt.split(';'):
            pair = pair.strip()
            if not pair:
                continue
            if '=' in pair:
                k, v = pair.split('=', 1)
                print(f"{k.strip()} = {v.strip()}")

        # Extract the public key from the TXT record
        match = re.search(r"p=([A-Za-z0-9+/=]+)", txt)
        if not match:
            print("No p= parameter found in DNS DKIM record.")
            return None
        return match.group(1)
    except Exception as e:
        print(f"DNS query failed: {e}")
        return None


def canonicalize_header_simple(header_name, header_value):
    """
    Simple canonicalization for DKIM headers:
    - Lowercase header name.
    - Remove leading/trailing whitespace from value.
    - Single space after colon.
    - Ends with CRLF.
    """
    return f"{header_name.lower()}:{header_value.strip()}\r\n"


def canonicalize_header_relaxed(header_name, header_value):
    """
    Relaxed canonicalization for DKIM headers:
    - Lowercase header name.
    - Unfold lines (remove CRLF).
    - Compress whitespace to single spaces.
    - Strip whitespace from start/end of value.
    - Ends with CRLF.
    """
    h_name = header_name.lower()
    h_value = header_value.replace('\r\n', '').replace('\n', '').replace('\r', '')
    h_value = re.sub(r'\s+', ' ', h_value).strip(' ')
    return f"{h_name}:{h_value}\r\n"


def canonicalize_body_simple(body_bytes):
    """
    Simple canonicalization for DKIM body:
    - Remove all trailing CRLFs (empty lines at end).
    - Always ends with a single CRLF.
    """
    body = body_bytes.decode(errors='replace')
    # Remove all trailing CRLFs
    body = re.sub(r'((\r\n)*$)', '', body)
    # Always end with a single CRLF
    return (body + '\r\n').encode()


def canonicalize_body_relaxed(body_bytes):
    """
    Relaxed canonicalization for DKIM body (see RFC 6376 3.4.4):
    - Convert all line endings to CRLF
    - Reduce all sequences of WSP (space/tab) within lines to a single space
    - Remove all WSP at end of lines
    - Remove all trailing empty lines at end of body
    - Always end with a single CRLF
    """
    body = body_bytes.decode(errors='replace')
    # Split on CRLF ONLY, as per DKIM spec
    # (if no CRLF, fallback to splitlines for robustness)
    if '\r\n' in body:
        lines = body.split('\r\n')
    else:
        lines = body.splitlines()
    canon_lines = []
    for line in lines:
        # Reduce all sequences of WSP to a single SP, remove trailing WSP
        canon_line = re.sub(r'[ \t]+', ' ', line).rstrip(' \t')
        canon_lines.append(canon_line)
    # Remove trailing empty lines (lines that are exactly '')
    while canon_lines and canon_lines[-1] == '':
        canon_lines.pop()
    # Re-join with CRLF, always end with CRLF
    return ('\r\n'.join(canon_lines) + '\r\n').encode()


def get_headers_to_sign(message, header_list):
    """
    For the given list of header names (from h= in DKIM-Signature),
    returns a list of (header_name, header_value) tuples for the instances
    that should be signed (handling duplicates as per DKIM spec).
    Prevents 'IndexError: list index out of range' if a header
    in h= is not present in the email.
    """
    output = []
    counts = {}
    # Count how many times each header name appears in h=
    for h in header_list:
        h_lc = h.lower()
        counts[h_lc] = counts.get(h_lc, 0) + 1
    # Collect all headers in the message, in order
    all_headers = []
    for (hn, hv) in message.raw_items():
        all_headers.append((hn, hv))
    used = {}
    # For each header in h=, use the last unused occurrence in the message
    for h in header_list:
        h_lc = h.lower()
        matches = [i for i, (hn, _) in enumerate(all_headers) if hn.lower() == h_lc]
        use_count = used.get(h_lc, 0)
        if matches and use_count < len(matches):
            idx = matches[-use_count-1]
            output.append(all_headers[idx])
            used[h_lc] = use_count + 1
        else:
            # Header in h= not present in message, append an empty value as per RFC 6376 section 3.5
            output.append((h, ""))
            used[h_lc] = use_count + 1
    return output


def get_body_bytes(msg):
    """
    Returns the body as bytes, preserving line endings as close as possible to original.
    If multipart, uses the first part (prefer text/plain, fallback to first part).
    """
    if msg.is_multipart():
        # Use the raw payload of the first part (usually text/plain)
        part = msg.get_body(preferencelist=('plain', 'html'))
        if part is None:
            # fallback: first part
            part = msg.get_payload(0)
        payload = part.get_payload(decode=True)
        if payload is not None:
            return payload
        else:
            # fallback: encode to bytes
            content = part.get_content()
            return content.encode()
    else:
        # Use the original bytes
        payload = msg.get_payload(decode=True)
        if payload is not None:
            return payload
        else:
            # fallback: encode to bytes
            return msg.get_content().encode()


def check_dmarc(domain):
    """
    Parses a DMARC DNS record string and prints out each tag-value pair.
    """
    print(line_delimiter)
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                txt_value = txt_string.decode() if hasattr(txt_string, 'decode') else txt_string
                if txt_value.lower().startswith("v=dmarc"):
                    print(f"DMARC record found for {domain}:\n")
                    for pair in txt_value.split(';'):
                        pair = pair.strip()
                        if not pair:
                            continue
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            print(f"{k.strip()} = {v.strip()}")
                    return True
        print(f"No DMARC record found for {domain}.")
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        print(f"No DMARC record found for {domain}.")
        return False
    except Exception as e:
        print(f"Error checking DMARC for {domain}: {e}")
        return False


def main(eml_path):
    """
    Main function to do all the DKIM signature stuffs.
    """
    # Parse the EML file using the email lib
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=default)

    # Get the DKIM-Signature header from the message
    dkim_header = msg["DKIM-Signature"]
    if not dkim_header:
        print("No DKIM-Signature header found.")
        sys.exit(1)
    # Parse DKIM-Signature fields and print them (in the function)
    dkim_fields = parse_dkim_signature(dkim_header)

    # Extract required DKIM parameters
    selector = dkim_fields.get("s")
    domain = dkim_fields.get("d")
    headers_signed = dkim_fields.get("h")
    signature_b64 = dkim_fields.get("b")
    body_hash_b64 = dkim_fields.get("bh")
    canonicalization = dkim_fields.get("c", "simple/simple")

    # Ensure all required parameters are present
    if not all([selector, domain, headers_signed, signature_b64, body_hash_b64]):
        print("Missing required DKIM signature fields.")
        sys.exit(1)

    # Determine canonicalization algorithms for header and body
    c_header, c_body = (canonicalization.split("/") + ["simple", "simple"])[:2]

    # Fetch the public key from DNS DKIM TXT record
    pubkey_b64 = fetch_public_key(selector, domain)
    if not pubkey_b64:
        print("Could not fetch DKIM public key.")
        sys.exit(1)

    # Extract the message body as bytes for canonicalization and hashing
    body_bytes = get_body_bytes(msg)

    # Canonicalize the body and print which method is used
    if c_body == "simple":
        canon_body = canonicalize_body_simple(body_bytes)
    elif c_body == "relaxed":
        canon_body = canonicalize_body_relaxed(body_bytes)
    else:
        print(f"Unsupported body canonicalization: {c_body}")
        sys.exit(1)

    # Calculate the body hash and compare to the value in DKIM-Signature
    body_hash = base64.b64encode(hashlib.sha256(canon_body).digest()).decode()
    print(line_delimiter)
    if body_hash == body_hash_b64:
        print("Body hash matches DKIM-Signature.\n")
        print(f"Expected:\t {body_hash_b64}")
        print(f"Calculated:\t {body_hash}")
        body_match = True
    else:
        print("Body hash does not match DKIM-Signature.")
        print(f"Expected:\t {body_hash_b64}")
        print(f"Calculated:\t {body_hash}")
        body_match = False

    # Prepare the headers to sign, in canonicalized order
    header_names = [h.strip() for h in headers_signed.split(":")]
    headers = get_headers_to_sign(msg, header_names)
    canon_headers = ""
    for hname, hval in headers:
        if c_header == "simple":
            canon_headers += canonicalize_header_simple(hname, hval)
        elif c_header == "relaxed":
            canon_headers += canonicalize_header_relaxed(hname, hval)
        else:
            print(f"Unsupported header canonicalization: {c_header}")
            sys.exit(1)

    # Canonicalize the DKIM-Signature header itself, but with b= value empty
    dkim_header_nosig = re.sub(r"\bb=([^;]*)", "b=", dkim_header, count=1)
    if c_header == "simple":
        canon_headers += canonicalize_header_simple("DKIM-Signature", dkim_header_nosig)
    elif c_header == "relaxed":
        canon_headers += canonicalize_header_relaxed("DKIM-Signature", dkim_header_nosig)
    else:
        print(f"Unsupported header canonicalization: {c_header}")
        sys.exit(1)

    print(line_delimiter)
    with open(ARGS.filename, "rb") as f:
        eml_data = f.read()
    try:
        is_valid = dkim.verify(eml_data)
        if is_valid:
            print("DKIM signature is VALID.")
        else:
            print("DKIM signature is INVALID.")
            if body_match:
                print("Body hash matched, but some of the headers did not.")
    except Exception as e:
        print(f"Error during DKIM validation: {e}")

    # Finish by printing out a possible DMARC record
    check_dmarc(domain)


def super_cool_banner():
    """This program will probably not even work without this."""
    print("\n" * 50)
    print("""
_______   __  ___  __  .___  ___.                  
|       \ |  |/  / |  | |   \/   |                  
|  .--.  ||  '  /  |  | |  \  /  |                  
|  |  |  ||    <   |  | |  |\/|  |                  
|  '--'  ||  .  \  |  | |  |  |  |                  
|_______/ |__|\__\ |__| |__|  |__|                  
                                                    
  _______   ______    _______  _______ .______      
 /  _____| /  __  \  |   ____||   ____||   _  \     
|  |  __  |  |  |  | |  |__   |  |__   |  |_)  |    
|  | |_ | |  |  |  | |   __|  |   __|  |      /     
|  |__| | |  `--'  | |  |     |  |____ |  |\  \----.
 \______|  \______/  |__|     |_______|| _| `._____|
          
         _.-=-._  
     .'       '.  
    /     .-=-.  \ 
   |     /     \  |
   |    |  \_/  | | Validate
    \    \     /  /
     '._  '---' _.'
        `-.___.-'
                                Digging Life One Hole at a Time.
    """)


if __name__ == "__main__":
    super_cool_banner()
    main(ARGS.filename)
    print(line_delimiter)