#!/usr/bin/env python3
# megolm_export: operate on megolm session data
# Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import hmac
import base64
import struct
import getpass
import hashlib
import argparse

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# This parsing is from the spec:
#   <https://github.com/matrix-org/matrix-doc/blob/master/specification/modules/end_to_end_encryption.rst#key-exports>
#
# Given a passphrase, we have
#    {K, K'} = PBKDF2(HMAC-SHA-256, passphrase, S, N, 512)
# where K is the first 256 bits and K' the last 256 bits.
#
#  Size | Description
#  -----+------------------------------------------
#     1 | Export format version, which must be 0x01.
#    16 | The salt S.
#    16 | The initialization vector IV.
#     4 | The number of rounds N, as a big-endian unsigned 32-bit integer.
#   var | The encrypted JSON object.
#    32 | The HMAC-SHA-256 of all the above string concatenated together,
#       | using K' as the key.

HEADER = b"-----BEGIN MEGOLM SESSION DATA-----"
FOOTER = b"-----END MEGOLM SESSION DATA-----"

CryptoParams = struct.Struct(">c16s16sL")
MAC_SIZE = 32

def bail(*args):
	print("[!]", *args, file=sys.stderr)
	sys.exit(1)

# A bytes-friendly version of textwrap.fill.
def bytes_wrap(b, width):
	wrapped = []
	while b:
		wrapped.append(b[:width])
		b = b[width:]
	return b"\n".join(wrapped)

# Short-hand for the PBKDF2 and split we need for K and K'.
def stretch_keys(passphrase, S, N):
	if not isinstance(passphrase, bytes):
		passphrase = passphrase.encode("utf-8")
	keys = hashlib.pbkdf2_hmac("sha512", passphrase, S, N, dklen=512//8)
	return (keys[:256//8], keys[256//8:])

def enc_session_data(passphrase, json_data):
	# Figure out our parameters.
	version, S, IV, N = b"\x01", get_random_bytes(16), get_random_bytes(16), 500000

	# Clear bit 63 of IV.
	IV = bytearray(IV)
	IV[9] &= 0x7f

	# Get our keys.
	K, Kp = stretch_keys(passphrase, S, N)

	# Encrypt the JSON.
	cipher = AES.new(K, AES.MODE_CTR, nonce=b"", initial_value=IV)
	plaintext = json_data
	ciphertext = cipher.encrypt(plaintext)

	# Prepend the crypto parameters.
	params = CryptoParams.pack(version, S, IV, N)
	body = params + ciphertext

	# Compute the MAC.
	body += hmac.digest(Kp, body, "sha256")

	# Base64 everything, wrap it at 128-chars, and add the header+footer.
	session_data = bytes_wrap(base64.b64encode(body), 128)
	return b"\n".join([HEADER, session_data, FOOTER])

def dec_session_data(passphrase, session_data):
	# Get rid of any trailing newlines.
	session_data = session_data.strip()

	# Does it have the header and footer?
	if session_data[:len(HEADER)] != HEADER:
		bail("session data invalid: missing header %r" % (HEADER,))
	if session_data[-len(FOOTER):] != FOOTER:
		bail("session data invalid: missing footer %r" % (FOOTER,))

	# Get the body and base64-decode it.
	body = base64.b64decode(session_data[len(HEADER):-len(FOOTER)])

	if len(body) < CryptoParams.size + MAC_SIZE:
		bail("session data too small: %d < %d", len(body), CryptoParams.size + MAC_SIZE)

	# Get the parameters (we need S and N to check the MAC).
	params = body[:CryptoParams.size]
	version, S, IV, N = CryptoParams.unpack(params)

	# Figure out the keys.
	K, Kp = stretch_keys(passphrase, S, N)

	# Check the MAC.
	mac = body[-MAC_SIZE:]
	our_mac = hmac.digest(Kp, body[:-MAC_SIZE], "sha256")
	if not hmac.compare_digest(mac, our_mac):
		bail("session data corrupted or bad passphrase: mac check failed")

	# Okay, decrypt the JSON.
	cipher = AES.new(K, AES.MODE_CTR, nonce=b"", initial_value=IV)
	ciphertext = body[CryptoParams.size:-MAC_SIZE]
	return cipher.decrypt(ciphertext)

def main(args):
	parser = argparse.ArgumentParser(description="Operate on megolm session backups.")
	parser.add_argument("file", nargs="?", default="-", help="Backup text file (- for stdin).")
	mode_group = parser.add_mutually_exclusive_group(required=True)
	mode_group.add_argument("--into", dest="mode", const="encrypt", action="store_const", help="Encrypt and represent file as a megolm session backup.")
	mode_group.add_argument("--from", dest="mode", const="decrypt", action="store_const", help="Decrypt the given megolm session and output the contents.")
	args = parser.parse_args(args)

	if args.file == "-":
		args.file = "/dev/stdin"

	action = {
		"encrypt": enc_session_data,
		"decrypt": dec_session_data,
	}[args.mode]

	with open(args.file, "rb") as f:
		data = f.read()

	# Wait until after reading input to get the passphrase so pipelines work.
	passphrase = getpass.getpass("Backup passphrase [mode=%s]: " % (args.mode,))
	output = action(passphrase, data)

	sys.stdout.buffer.write(output + b"\n")
	sys.stdout.buffer.flush()

if __name__ == "__main__":
	main(sys.argv[1:])
