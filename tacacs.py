#!/usr/bin/python

# Copyright © 2008 by Jeffrey C. Ollie
#
# This file is part of Secant.
#
# Secant is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Secant is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Secant.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import generators

import md5
import re
import struct

TAC_PLUS_MAJOR_VER               = 0x0c

TAC_PLUS_MINOR_VER_DEFAULT       = 0x00
TAC_PLUS_MINOR_VER_ONE           = 0x01

TAC_PLUS_AUTHEN                  = 0x01 # Authentication
TAC_PLUS_AUTHOR                  = 0x02 # Authorization
TAC_PLUS_ACCT                    = 0x03 # Accounting

TAC_PLUS_UNENCRYPTED_FLAG        = 0x01
TAC_PLUS_SINGLE_CONNECT_FLAG     = 0x04

TAC_PLUS_AUTHEN_LOGIN            = 0x01
TAC_PLUS_AUTHEN_CHPASS           = 0x02
TAC_PLUS_AUTHEN_SENDPASS         = 0x03 # (deprecated)
TAC_PLUS_AUTHEN_SENDAUTH         = 0x04

TAC_PLUS_PRIV_LVL_MAX            = 0x0f
TAC_PLUS_PRIV_LVL_ROOT           = 0x0f
TAC_PLUS_PRIV_LVL_USER           = 0x01
TAC_PLUS_PRIV_LVL_MIN            = 0x00

TAC_PLUS_AUTHEN_TYPE_ASCII       = 0x01
TAC_PLUS_AUTHEN_TYPE_PAP         = 0x02
TAC_PLUS_AUTHEN_TYPE_CHAP        = 0x03
TAC_PLUS_AUTHEN_TYPE_ARAP        = 0x04
TAC_PLUS_AUTHEN_TYPE_MSCHAP      = 0x05

TAC_PLUS_AUTHEN_SVC_NONE         = 0x00
TAC_PLUS_AUTHEN_SVC_LOGIN        = 0x01
TAC_PLUS_AUTHEN_SVC_ENABLE       = 0x02
TAC_PLUS_AUTHEN_SVC_PPP          = 0x03
TAC_PLUS_AUTHEN_SVC_ARAP         = 0x04
TAC_PLUS_AUTHEN_SVC_PT           = 0x05
TAC_PLUS_AUTHEN_SVC_RCMD         = 0x06
TAC_PLUS_AUTHEN_SVC_X25          = 0x07
TAC_PLUS_AUTHEN_SVC_NASI         = 0x08
TAC_PLUS_AUTHEN_SVC_FWPROXY      = 0x09

TAC_PLUS_AUTHEN_STATUS_PASS      = 0x01
TAC_PLUS_AUTHEN_STATUS_FAIL      = 0x02
TAC_PLUS_AUTHEN_STATUS_GETDATA   = 0x03
TAC_PLUS_AUTHEN_STATUS_GETUSER   = 0x04
TAC_PLUS_AUTHEN_STATUS_GETPASS   = 0x05
TAC_PLUS_AUTHEN_STATUS_RESTART   = 0x06
TAC_PLUS_AUTHEN_STATUS_ERROR     = 0x07
TAC_PLUS_AUTHEN_STATUS_FOLLOW    = 0x21

TAC_PLUS_REPLY_FLAG_NOECHO       = 0x01

TAC_PLUS_CONTINUE_FLAG_ABORT     = 0x01

TAC_PLUS_AUTHEN_METH_NOT_SET     = 0x00
TAC_PLUS_AUTHEN_METH_NONE        = 0x01
TAC_PLUS_AUTHEN_METH_KRB5        = 0x02
TAC_PLUS_AUTHEN_METH_LINE        = 0x03
TAC_PLUS_AUTHEN_METH_ENABLE      = 0x04
TAC_PLUS_AUTHEN_METH_LOCAL       = 0x05
TAC_PLUS_AUTHEN_METH_TACACSPLUS  = 0x06
TAC_PLUS_AUTHEN_METH_GUEST       = 0x08
TAC_PLUS_AUTHEN_METH_RADIUS      = 0x10
TAC_PLUS_AUTHEN_METH_KRB4        = 0x11
TAC_PLUS_AUTHEN_METH_RCMD        = 0x20

TAC_PLUS_AUTHOR_STATUS_PASS_ADD  = 0x01
TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
TAC_PLUS_AUTHOR_STATUS_FAIL      = 0x10
TAC_PLUS_AUTHOR_STATUS_ERROR     = 0x11
TAC_PLUS_AUTHOR_STATUS_FOLLOW    = 0x21

TAC_PLUS_ACCT_FLAG_MORE          = 0x01 # deprecated
TAC_PLUS_ACCT_FLAG_START         = 0x02
TAC_PLUS_ACCT_FLAG_STOP          = 0x04
TAC_PLUS_ACCT_FLAG_WATCHDOG      = 0x08

TAC_PLUS_ACCT_STATUS_SUCCESS     = 0x01
TAC_PLUS_ACCT_STATUS_ERROR       = 0x02
TAC_PLUS_ACCT_STATUS_FOLLOW      = 0x21

class error:
    def __init__(self, message):
        self.message = message

argument_re = re.compile(r'^([^=*]+)([=*])(.*)$')

class Argument:
    def __init__(self, argument):
        self.key = None
        self.value = None
        self.is_optional = None
        argument_match = argument_re.match(argument)
        if argument_match:
            self.key = argument_match.group(1)
            self.value = argument_match.group(3)
            self.is_optional = argument_match.group(2) == '*'

    def __str__(self):
        if self.is_optional:
            return '%s*%s' % (self.key, self.value)
        else:
            return '%s=%s' % (self.key, self.value)

    def __repr__(self):
        if self.is_optional:
            return `'%s*%s' % (self.key, self.value)`
        else:
            return `'%s=%s' % (self.key, self.value)`

    def __len__(self):
        return len(self.key) + len(self.value) + 1
    
def generate_pseudo_pad(header, secret_key):
    md5_1 = md5.new()
    md5_1.update(header[4:8]) # session_id
    md5_1.update(secret_key)
    md5_1.update(header[:1])  # version
    md5_1.update(header[2:3]) # seq_no
    
    hash = md5_1.digest()
    
    while 1:
        for byte in hash:
            yield byte
        md5_n = md5_1.copy()
        md5_n.update(hash)
        hash = md5_n.digest()

class Packet:
    def __init__(self, secret_key = None, reply_to = None, copy_of = None):
        self.header = None
        self.ciphertext_body = None
        self.plaintext_body = None
        self.secret_key = secret_key
        self.major_version = 0xc
        self.minor_version = 0
        self.packet_type = 0
        self.seq_no = 0
        self.header_flags = 0
        self.session_id = 0
        self.length = 0

        if copy_of is not None:
            self.header = copy_of.header
            self.ciphertext_body = copy_of.ciphertext_body
            self.plaintext_body = copy_of.plaintext_body
            self.secret_key = copy_of.secret_key
            self.major_version = copy_of.major_version
            self.minor_version = copy_of.minor_version
            self.packet_type = copy_of.packet_type
            self.seq_no = copy_of.seq_no
            self.header_flags = copy_of.header_flags
            self.session_id = copy_of.session_id
            self.length = copy_of.length
            self.unpack_body()
            
        if reply_to is not None:
            self.session_id   = reply_to.session_id
            self.seq_no       = reply_to.seq_no + 1
            self.secret_key   = reply_to.secret_key
            self.header_flags = reply_to.header_flags
            self.packet_type  = reply_to.packet_type
            
    def set_header(self, header):
        self.header = header
        self.unpack_header()

    def set_body(self, ciphertext_body):
        self.ciphertext_body = ciphertext_body
        self.decrypt_body()
        self.unpack_body()
        
    def unpack_header(self):
        version, self.packet_type, self.seq_no, self.header_flags, self.session_id, self.length = struct.unpack('!BBBBII',
                                                                                                                self.header)
        self.major_version = (version >> 4) & 0xf
        self.minor_version = version & 0xf
        
    def decrypt_body(self):
        if (self.header_flags & TAC_PLUS_UNENCRYPTED_FLAG) and (self.secret_key is not None):
            self.plaintext_body = self.ciphertext_body
            
        else:
            self.plaintext_body = ''.join(map(lambda (data, pad): chr(ord(data) ^ ord(pad)),
                                              zip(self.ciphertext_body[:self.length],
                                                  generate_pseudo_pad(self.header, self.secret_key))))
            
    def encrypt_body(self):
        if (self.header_flags & TAC_PLUS_UNENCRYPTED_FLAG) and (self.secret_key is not None):
            self.ciphertext_body = self.plaintext_body
            
        else:
            self.ciphertext_body = ''.join(map(lambda (data, pad): chr(ord(data) ^ ord(pad)),
                                               zip(self.plaintext_body[:self.length],
                                                   generate_pseudo_pad(self.header, self.secret_key))))

    def unpack_body(self):
        pass
    
    def pack_header(self):
        self.header = struct.pack('!BBBBII',
                                  ((self.major_version & 0xf) << 4) | (self.minor_version & 0xf),
                                  self.packet_type,
                                  self.seq_no,
                                  self.header_flags,
                                  self.session_id,
                                  self.length)


    def pack_body(self):
        pass

    def pack(self):
        self.pack_body()
        self.pack_header()
        self.encrypt_body()
        return self.header + self.ciphertext_body
    
class AuthenticationStart(Packet):
    def __init__(self, secret_key=None, copy_of=None):
        self.packet_type = TAC_PLUS_AUTHEN
        
        self.action = None
        self.priv_lvl = None
        self.authen_type = None
        self.service = None
        self.user = ''
        self.port = ''
        self.rem_addr = ''
        self.data = ''

        Packet.__init__(self, secret_key=secret_key, copy_of=copy_of)

    def get_reply(self):
        return AuthenticationReply(reply_to=self)
    
    def unpack_body(self):
        if self.plaintext_body is None:
            raise 'error'
        
        (self.action,
         self.priv_lvl,
         self.authen_type,
         self.service,
         user_len,
         port_len,
         rem_addr_len,
         data_len) = struct.unpack('!BBBBBBBB', self.plaintext_body[:8])

        index = 8

        self.user = self.plaintext_body[index:index+user_len]
        index += user_len

        self.port = self.plaintext_body[index:index+port_len]
        index += port_len

        self.rem_addr = self.plaintext_body[index:index+rem_addr_len]
        index += rem_addr_len

        self.data = self.plaintext_body[index:index+data_len]
        index += data_len

    def pack_body(self):
        body = struct.pack('!BBBBBBBB',
                           self.action,
                           self.priv_lvl,
                           self.authen_type,
                           self.service,
                           len(self.user),
                           len(self.port),
                           len(self.rem_addr),
                           len(self.data))
        body += self.user
        body += self.port
        body += self.rem_addr
        body += self.data

        self.plaintext_body = body
        self.length = len(self.plaintext_body)

class AuthenticationReply(Packet):
    def __init__(self, reply_to):
        if not isinstance(reply_to, (AuthenticationStart, AuthenticationContinue)):
            raise 'error'

        Packet.__init__(self, reply_to=reply_to)
        
        self.authentication_status = None
        self.authentication_flags = None
        self.server_msg = None
        self.data = None
        
    def unpack_body(self):
        (self.authentication_status,
         self.authentication_flags,
         server_msg_len,
         data_len) = struct.unpack('!BBHH', self.plaintext_body[:6])

        index = 6

        self.server_msg = self.plaintext_body[index:index+server_msg_len]
        index += server_msg_len

        self.data = self.plaintext_body[index:index+data_len]
        index += data_len

    def pack_body(self):
        body = struct.pack('!BBHH',
                           self.authentication_status,
                           self.authentication_flags,
                           len(self.server_msg),
                           len(self.data))

        body += self.server_msg
        body += self.data

        self.plaintext_body = body
        self.length = len(self.plaintext_body)

class AuthenticationContinue(Packet):
    def __init__(self, secret_key=None, copy_of=None):
        self.authentication_flags = None
        self.user_msg = None
        self.data = None

        Packet.__init__(self, secret_key=secret_key, copy_of=copy_of)
        
    def get_reply(self):
        return AuthenticationReply(reply_to=self)

    def unpack_body(self):
        user_msg_len, data_len, self.authentication_flags = struct.unpack('!HHB', self.plaintext_body[:5])

        index = 5

        self.user_msg = self.plaintext_body[index:index+user_msg_len]
        index += user_msg_len

        self.data = self.plaintext_body[index:index+data_len]
        index += data_len

    def pack_body(self):
        body = struct.pack('!HHB', len(self.user_msg), len(self.data), self.authentication_flags)

        body += self.user_msg
        body += self.data

        self.plaintext_body = body
        self.length = len(self.plaintext_body)

class AuthorizationRequest(Packet):
    def __init__(self, secret_key=None, copy_of=None):
        
        self.authen_method = None
        self.priv_lvl = None
        self.authen_type = None
        self.authen_service = None
        self.user = ''
        self.port = ''
        self.rem_addr = ''
        self.args = []

        Packet.__init__(self, secret_key=secret_key, copy_of=copy_of)
        
    def unpack_body(self):
        (self.authen_method,
         self.priv_lvl,
         self.authen_type,
         self.authen_service,
         user_len,
         port_len,
         rem_addr_len,
         arg_cnt) = struct.unpack('!BBBBBBBB', self.plaintext_body[:8])

        index = 8

        arg_lengths = map(ord, self.plaintext_body[index:index+arg_cnt])
        index += arg_cnt

        user = self.plaintext_body[index:index+user_len]
        index += user_len

        port = self.plaintext_body[index:index+port_len]
        index += port_len

        rem_addr = self.plaintext_body[index:index+rem_addr_len]
        index += rem_addr_len

        self.args = []
        for arg_length in arg_lengths:
            self.args.append(Argument(self.plaintext_body[index:index+arg_length]))
            index += arg_length

    def pack_body(self):
        body = struct.pack('!BBBBBBBB',
                           self.authen_method,
                           self.priv_lvl,
                           self.authen_type,
                           self.authen_service,
                           len(self.user),
                           len(self.port),
                           len(self.rem_addr),
                           len(self.args))

        body += ''.join(map(lambda arg: chr(len(arg)), args))

        body += user
        body += port
        body += rem_addr

        for arg in args:
            body += str(arg)

        self.plaintext_body = body
        self.length = len(self.plaintext_body)

    def get_reply(self):
        return AuthorizationResponse(reply_to=self)
    
class AuthorizationResponse(Packet):
    def __init__(self, reply_to):
        assert isinstance(reply_to, AuthorizationRequest)
        
        self.authorization_status = None
        self.args = []
        self.server_msg = ''
        self.data = ''

        Packet.__init__(self, reply_to=reply_to)
        
    def unpack_body(self):
        (self.authorization_status,
         arg_cnt,
         server_msg_len,
         data_len) = struct.unpack('!BBHH', self.plaintext_body[:6])

        index = 6
        
        arg_lengths = map(ord, self.plaintext_body[index:index+arg_cnt])
        index += arg_cnt

        self.server_msg = self.plaintext_body[index:index+server_msg_len]
        index += server_msg_len

        self.data = self.plaintext_body[index:index+data_len]
        index += data_len

        self.args = []
        for arg_length in arg_lengths:
            self.args.append(Argument(self.plaintext_body[index:index+arg_length]))
            index += arg_length

    def pack_body(self):
        body = struct.pack('!BBHH',
                           self.authorization_status,
                           len(self.args),
                           len(self.server_msg),
                           len(self.data))


        body += ''.join(map(lambda arg: chr(len(arg)), self.args))

        body += self.server_msg
        body += self.data

        for arg in self.args:
            body += str(arg)

        self.plaintext_body = body
        self.length = len(self.plaintext_body)

class AccountingRequest(Packet):
    def __init__(self, secret_key = None, copy_of = None):
        self.accounting_flags = None
        self.authen_method = None
        self.priv_lvl = None
        self.authen_type = None
        self.authen_service = None
        self.user = None
        self.port = None
        self.rem_addr = None
        self.args = []

        Packet.__init__(self, secret_key=secret_key, copy_of=copy_of)
        
    def unpack_body(self):
        (self.accounting_flags,
         self.authen_method,
         self.priv_lvl,
         self.authen_type,
         self.authen_service,
         user_len,
         port_len,
         rem_addr_len,
         arg_cnt) = struct.unpack('!BBBBBBBBB', self.plaintext_body[:9])

        index = 9

        arg_lengths = map(ord, self.plaintext_body[index:index+arg_cnt])
        index += arg_cnt

        self.user = self.plaintext_body[index:index+user_len]
        index += user_len

        self.port = self.plaintext_body[index:index+port_len]
        index += port_len

        self.rem_addr = self.plaintext_body[index:index+rem_addr_len]
        index += rem_addr_len

        self.args = []
        for arg_length in arg_lengths:
            self.args.append(Argument(self.plaintext_body[index:index+arg_length]))
            index += arg_length

    def get_reply(self):
        return AccountingReply(reply_to=self)
    
class AccountingReply(Packet):
    def __init__(self, reply_to):
        if not isinstance(reply_to, AccountingRequest):
            raise 'error'

        self.accounting_status = None
        self.server_msg = ''
        self.data = ''

        Packet.__init__(self, reply_to=reply_to)
        
    def unpack_body(self):
        (server_msg_len, data_len, self.accounting_status) = struct.unpack('!HHB', self.plaintext_body[:5])

        index = 5

        self.server_msg = self.plaintext_body[index:index + server_msg_len]
        index += server_msg_len

        self.data = self.plaintext_body[index:index + data_len]
        index += data_len

    def pack_body(self):
        body = struct.pack('!HHB',
                           len(self.server_msg),
                           len(self.data),
                           self.accounting_status)

        body += self.server_msg
        body += self.data

        self.plaintext_body = body
        self.length = len(self.plaintext_body)
