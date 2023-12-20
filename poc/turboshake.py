# A stateful implementation of TurboSHAKE adapted from the reference implementation
#
# We use TurboSHAKE in two steps:
#
#  1. Message fragments are absorbed into the hash state
#  2. Output fragments are squeezed out of the hash state
#
# The reference implementation of TurboSHAKE only provides a "one-shot" API,
# where the message and the length of the output are determined in advance.
#
# The stateful API is not needed if you know the desired output length in
# advance. Even if you don't know the desired output length, you can always do
# something like this:
#
#  1. Concatenate the message fragments into message `M`
#  2. Keep track of the output length `totalOutputBytesLen` squeezed so far and
#     output `TurboSHAKE(c, M, D, totalOutputBytesLen+nextOutputBytesLen)`.
#
# However if the output length is large, then this is prohibitively slow, even
# for reference code. In particular, this makes the unit tests for Prio3 and
# Poplar1 take well over 30 seconds to run. Thus the purpose of implementing a
# stateful API is to make our unit tests run in a reasonable amount of time.

import os
import sys

kangarootwelve_path = \
    "%s/draft-irtf-cfrg-kangarootwelve/py" % os.path.dirname(__file__)  # nopep8
assert os.path.isdir(kangarootwelve_path)  # nopep8
sys.path.append(kangarootwelve_path)  # nopep8

from TurboSHAKE import KeccakP1600, TurboSHAKE128


class TurboSHAKEAbosrb:
    '''TurboSHAKE in the absorb state.'''

    def __init__(self, c, D):
        '''
        Initialize the absorb state with capacity `c` (number of bits) and
        domain separation byte `D`.
        '''
        self.D = D
        self.rate_in_bytes = (1600-c)//8
        self.state = bytearray([0 for i in range(200)])
        self.state_offset = 0

    def update(self, M):
        '''
        Update the absorb state with message fragment `M`.
        '''
        input_offset = 0
        while input_offset < len(M):
            length = len(M)-input_offset
            block_size = min(length, self.rate_in_bytes-self.state_offset)
            for i in range(block_size):
                self.state[i+self.state_offset] ^= M[i+input_offset]
            input_offset += block_size
            self.state_offset += block_size
            if self.state_offset == self.rate_in_bytes:
                self.state = KeccakP1600(self.state, 12)
                self.state_offset = 0

    def squeeze(self):
        '''
        Consume the absorb state and return the TurboSHAKE squeeze state.
        '''
        state = self.state[:]  # deep copy
        state[self.state_offset] ^= self.D
        if (((self.D & 0x80) != 0) and
                (self.state_offset == (self.rate_in_bytes-1))):
            state = KeccakP1600(state, 12)
        state[self.rate_in_bytes-1] = state[self.rate_in_bytes-1] ^ 0x80
        state = KeccakP1600(state, 12)

        squeeze = TurboSHAKESqueeze()
        squeeze.rate_in_bytes = self.rate_in_bytes
        squeeze.state = state
        squeeze.state_offset = 0
        return squeeze


class TurboSHAKESqueeze:
    '''TurboSHAKE in the squeeze state.'''

    def next(self, length):
        '''
        Return the next `length` bytes of output and update the squeeze state.
        '''
        output = bytearray()
        while length > 0:
            block_size = min(length, self.rate_in_bytes-self.state_offset)
            length -= block_size
            output += \
                self.state[self.state_offset:self.state_offset+block_size]
            self.state_offset += block_size
            if self.state_offset == self.rate_in_bytes:
                self.state = KeccakP1600(self.state, 12)
                self.state_offset = 0
        return output


def NewTurboSHAKE128(D):
    '''
    Return the absorb state for TurboSHAKE128 with domain separation byte `D`.
    '''
    return TurboSHAKEAbosrb(256, D)


def testAPI(stateful, oneshot):
    '''Test that the outputs of the stateful and oneshot APIs match.'''

    test_cases = [
        {
            'fragments': [],
            'lengths': [],
        },
        {
            'fragments': [],
            'lengths': [
                1000,
            ],
        },
        {
            'fragments': [
                b'\xff' * 500,
            ],
            'lengths': [
                12,
            ],
        },
        {
            'fragments': [
                b'hello',
                b', ',
                b'',
                b'world',
            ],
            'lengths': [
                1,
                17,
                256,
                128,
                0,
                7,
                14,
            ],
        },
        {
            'fragments': [
                b'\xff' * 1024,
                b'\x17' * 23,
                b'',
                b'\xf1' * 512,
            ],
            'lengths': [
                1000,
                0,
                0,
                14,
            ],

        }
    ]

    D = 99
    for (i, test_case) in enumerate(test_cases):
        absorb = stateful(D)
        message = bytearray()
        for fragment in test_case['fragments']:
            absorb.update(fragment)
            message += fragment
        squeeze = absorb.squeeze()
        output = b''
        output_len = 0
        for length in test_case['lengths']:
            output += squeeze.next(length)
            output_len += length
        expected_output = oneshot(message, D, output_len)
        if output != expected_output:
            raise Exception('test case {} failed: got {}; want {}'.format(
                i,
                output.hex(),
                expected_output.hex(),
            ))


if __name__ == '__main__':
    testAPI(NewTurboSHAKE128, TurboSHAKE128)
