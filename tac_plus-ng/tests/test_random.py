# Copyright (C) 2026 TaranacLabs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL ITS AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""Random values the daemon puts into replies come from the kernel, not from an unseeded random().

Where the C library has no arc4random() (musl, glibc before 2.36),
misc/sysconf.h replaced it with random(), which nobody seeds: every
worker drew the same sequence. The salt of MS-MPPE-Send-Key (RFC 2548
2.4.2) in the Access-Accept of an MS-CHAPv2 login is the first value a
fresh worker draws, so it shows the sequence from outside.
"""

import os
import struct
import unittest

from tactest import DaemonTestCase, features, radius
from tactest.crypto import challenge_response, mschapv2_challenge_hash, nt_hash
from test_radius import DICTIONARY, NAS, SECRET

VENDOR_SPECIFIC = 26
MICROSOFT = 311
MS_CHAP_CHALLENGE = 11
MS_MPPE_SEND_KEY = 16
MS_MPPE_RECV_KEY = 17
MS_CHAP2_RESPONSE = 25
STARTS = 3

CONFIG = """
	include = "%s"
	device radius-nas {
		address = %s
		key = tactest
		radius.key = %s
	}
	user alice {
		password ms-chap = clear alicepw
	}
	ruleset {
		rule { script { permit } }
	}
""" % (DICTIONARY, NAS, SECRET)


def vsa(attribute, value):
    return struct.pack("!I", MICROSOFT) + bytes([attribute, len(value) + 2]) + value


def microsoft_attributes(packet, attribute):
    found = []
    for value in packet.get(VENDOR_SPECIFIC):
        if len(value) < 6 or struct.unpack("!I", value[:4])[0] != MICROSOFT:
            continue
        rest = value[4:]
        while len(rest) >= 2 and rest[1] >= 2:
            if rest[0] == attribute:
                found.append(rest[2:rest[1]])
            rest = rest[rest[1]:]
    return found


def mschapv2_request(user, password):
    authenticator_challenge, peer_challenge = os.urandom(16), os.urandom(16)
    challenge = mschapv2_challenge_hash(peer_challenge, authenticator_challenge, user.encode())
    nt_response = challenge_response(challenge, nt_hash(password))
    response = bytes([1, 0]) + peer_challenge + bytes(8) + nt_response
    req = radius.Packet(radius.ACCESS_REQUEST)
    req.attributes = [(radius.USER_NAME, user.encode()),
                      (VENDOR_SPECIFIC, vsa(MS_CHAP_CHALLENGE, authenticator_challenge)),
                      (VENDOR_SPECIFIC, vsa(MS_CHAP2_RESPONSE, response))]
    return req


@unittest.skipUnless("openssl" in features(), "MS-CHAP and MPPE keys need a build with OpenSSL")
class MppeKeySalt(DaemonTestCase):
    CONFIG = None

    def first_salts(self):
        """(Send-Key salt, Recv-Key salt) of the first MS-CHAPv2 login of a new daemon."""
        d = self.start_daemon(CONFIG, udp=True)
        r = self.radius(SECRET, daemon=d, source=NAS).exchange(mschapv2_request("alice", "alicepw"),
                                                               message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        send, recv = microsoft_attributes(r, MS_MPPE_SEND_KEY), microsoft_attributes(r, MS_MPPE_RECV_KEY)
        self.assertEqual((len(send), len(recv)), (1, 1), r)
        return send[0][:2], recv[0][:2]

    def test_salts_differ_between_daemon_starts(self):
        salts = [self.first_salts() for _ in range(STARTS)]
        for send, recv in salts:
            self.assertTrue(send[0] & 0x80 and recv[0] & 0x80, "RFC 2548: the salt has its high bit set")
        self.assertGreater(len(set(salts)), 1, "every daemon start drew the same salts: %s" % salts)


if __name__ == "__main__":
    unittest.main()
