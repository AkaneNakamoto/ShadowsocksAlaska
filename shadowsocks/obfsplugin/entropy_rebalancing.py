#!/usr/bin/env python
#
# Copyright 2020-2025 Akane Nakamoto
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging
import binascii
import struct
import base64
import datetime
import random

import secrets
import numpy as np

from shadowsocks import common
from shadowsocks.obfsplugin import plain
from shadowsocks.common import to_bytes, to_str, ord

def create_erb_obfs(method):
    return erb_simple(method)

obfs_map = {
        'erb_simple': (create_erb_obfs,),
}



LOWBOUND = 3.4
HIGHBOUND = 4.6

SD = 0.35
MINR = 1
MAXPADDINGBYTES = 255

DEBUG = 0

def pprint(*argc, **argv):
    if DEBUG:
        return print(*argc, **argv)


ascii_popcount_dict = {1: [b' ', b'@'], 2: [b'!', b'"', b'$', b'(', b'0', b'A', b'B', b'D', b'H', b'P', b'`'], 3: [b'#', b'%', b'&', b')', b'*', b',', b'1', b'2', b'4', b'8', b'C', b'E', b'F', b'I', b'J', b'L', b'Q', b'R', b'T', b'X', b'a', b'b', b'd', b'h', b'p'], 4: [b"'", b'+', b'-', b'.', b'3', b'5', b'6', b'9', b':', b'<', b'G', b'K', b'M', b'N', b'S', b'U', b'V', b'Y', b'Z', b'\\', b'c', b'e', b'f', b'i', b'j', b'l', b'q', b'r', b't', b'x'], 5: [b'/', b'7', b';', b'=', b'>', b'O', b'W', b'[', b']', b'^', b'g', b'k', b'm', b'n', b's', b'u', b'v', b'y', b'z', b'|'], 6: [b'?', b'_', b'o', b'w', b'{', b'}', b'~']}


class erb_simple(plain.plain):

    def __init__(self, method):
        super().__init__(method)


    def simple_sample(self, xn, x):

        bit_array = np.zeros(x*8, dtype=int)
        indices = np.random.choice(x*8, xn, replace=False)
        bit_array[indices] = 1
        byte_string = np.packbits(bit_array).tobytes()

        return byte_string

    def client_encode(self, buf):
        n = sum((byte.bit_count() for byte in buf)) 
        l = len(buf)
        entropy = n / l

        if(entropy < LOWBOUND or entropy > HIGHBOUND):
            return b'\x00' +  buf
        
        t = max( LOWBOUND - abs(np.random.normal(loc=0, scale=SD)), MINR)
        pprint("target entropy: ",  t)

        delta = int((1 + n - t * l) / t )
        
        if (delta > MAXPADDINGBYTES):
            pprint("above max padding", delta)
            return b'\x00' +  buf
        
        x = random.randint(delta, MAXPADDINGBYTES)

        xn = int(t * l - n + t * x)

        sampled = self.simple_sample(xn, x)

        return bytes([x]) + sampled + buf
    
    def client_decode(self, buf):

        return buf[1 + buf[0]:]
    
    def server_encode(self, buf):
        return self.client_encode(buf)
    
    def server_decode(self, buf):
        return self.client_decode(buf)
    

    

if __name__ == "__main__":

    DEBUG = 1

    random_bytes = secrets.token_bytes(128)

    n = sum(byte.bit_count() for byte in random_bytes)
    print("init entropy: ", n / len(random_bytes))

    model = erb_simple("")
    
    enc = model.client_encode(random_bytes)

    n = sum(byte.bit_count() for byte in enc)
    print("obfs entropy: ", n / len(enc) )

    assert random_bytes == model.server_decode(enc)

    print("decoding test pass")



