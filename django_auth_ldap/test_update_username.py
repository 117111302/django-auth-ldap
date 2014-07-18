# coding: utf-8

# Copyright (c) 2009, Peter Sagerson
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# - Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import logging

try:
    import mockldap
except ImportError:
    mockldap = None

from django.contrib.auth.models import User
from django.test import TestCase

from django.utils import unittest

from django_auth_ldap import backend


class TestSettings(backend.LDAPSettings):
    """
    A replacement for backend.LDAPSettings that does not load settings
    from django.conf.
    """
    def __init__(self, **kwargs):
        for name, default in self.defaults.items():
            value = kwargs.get(name, default)
            setattr(self, name, value)


class LDAPTest(TestCase):
    top = ("o=test", {"o": "test"})
    people = ("ou=people,o=test", {"ou": "people"})
    groups = ("ou=groups,o=test", {"ou": "groups"})
    moregroups = ("ou=moregroups,o=test", {"ou": "moregroups"})

    alice = ("uid=alice,ou=people,o=test", {
        "uid": ["alice"],
        "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
        "userPassword": ["password"],
        "uidNumber": ["1000"],
        "gidNumber": ["1000"],
        "givenName": ["Alice"],
        "sn": ["Adams"],
        "mail": 'xuesong@intel.com'
    })
    directory = dict([alice])

    @classmethod
    def configure_logger(cls):
        logger = logging.getLogger('django_auth_ldap')
        formatter = logging.Formatter("LDAP auth - %(levelname)s - %(message)s")
        handler = logging.StreamHandler()

        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        logger.setLevel(logging.CRITICAL)

    @classmethod
    def setUpClass(cls):
        cls.configure_logger()
        cls.mockldap = mockldap.MockLdap(cls.directory)

    @classmethod
    def tearDownClass(cls):
        del cls.mockldap

    def setUp(self):
        self.mockldap.start()
        self.ldapobj = self.mockldap['ldap://localhost']

        self.backend = backend.LDAPBackend()
        self.backend.ldap  # Force global configuration

    def tearDown(self):
        self.mockldap.stop()
        del self.ldapobj

    def test_update_username(self):
        User.objects.create(username='xuesong@intel.com', email='xuesong@intel.com')

        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_UPDATE_FIELD='mail'
        )

        user = self.backend.authenticate(username='alice', password='password')

        self.assertTrue(user is not None)
        self.assertEqual(user.username, 'alice')
        self.assertEqual(user.email, 'xuesong@intel.com')
        self.assertEqual(User.objects.count(), 1)

    def test_update_username_when_multi_user(self):
        User.objects.create(username='xuesong@intel.com', email='xuesong@intel.com')
        User.objects.create(username='alice', email='xuesong@intel.com')
        User.objects.create(username='bob', email='xuesong@intel.com')

        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_UPDATE_FIELD='mail'
        )

        user = self.backend.authenticate(username='Alice', password='password')

        self.assertTrue(user is not None)
        self.assertEqual(user.username, 'alice')
        self.assertEqual(user.email, 'xuesong@intel.com')
        self.assertEqual(User.objects.count(), 1)


    def _init_settings(self, **kwargs):
        self.backend.settings = TestSettings(**kwargs)


# Python 2.5-compatible class decoration
LDAPTest = unittest.skipIf(mockldap is None, "django_auth_ldap tests require the mockldap package.")(LDAPTest)
