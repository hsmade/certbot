"""
The `~certbot_dns_transip.dns_transip` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Transip API.


Named Arguments
---------------

==========================================  ===================================
``--dns-transip-credentials``          Transip credentials_ INI file.
                                            (Required)
``--dns-transip-propagation-seconds``  The number of seconds to wait for
                                            DNS to propagate before asking the
                                            ACME server to verify the DNS
                                            record.
                                            (Default: 10)
==========================================  ===================================


Credentials
-----------

Use of this plugin requires a configuration file containing Transip API
credentials, obtained from your Transip account's `Applications & API
Tokens page <https://cloud.transip.com/settings/api/tokens>`_.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Transip API credentials used by Certbot
   dns_transip_token = 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff

The path to this file can be provided interactively or using the
``--dns-transip-credentials`` command-line argument. Certbot records the
path to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Transip account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-transip \\
     --dns-transip-credentials ~/.secrets/certbot/transip.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-transip \\
     --dns-transip-credentials ~/.secrets/certbot/transip.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 60 seconds
             for DNS propagation

   certbot certonly \\
     --dns-transip \\
     --dns-transip-credentials ~/.secrets/certbot/transip.ini \\
     --dns-transip-propagation-seconds 60 \\
     -d example.com

"""
