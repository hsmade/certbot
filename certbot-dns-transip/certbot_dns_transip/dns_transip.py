"""DNS Authenticator for Transip."""
import logging

from transip.service.dns import DnsEntry
from transip.service.domain import DomainService
import suds
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Transip

    This Authenticator uses the Transip API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Transip for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Transip credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Transip API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Transip credentials INI file',
            {
                'key_file': 'RSA key file for Transip account '
                            '(convert with openssl rsa -in transip.key -out decrypted_key)',
                'username': 'Transip username',
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_transip_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_transip_client().del_txt_record(domain, validation_name, validation)

    def _get_transip_client(self):
        return _TransipClient(username=self.credentials.conf('username'), key_file=self.credentials.conf('key_file'))


class _TransipClient(object):
    """
    Encapsulates all communication with the Transip API.
    """

    def __init__(self, username, key_file):
        self.domain_service = DomainService(login=username, private_key_file=key_file)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Transip
                                            API
        """
        try:
            domain = self._find_domain(domain_name)
        except suds.WebFault as e:
            logger.error('Error finding domain using the Transip API: %s', e)
            raise errors.PluginError('Error finding domain using the Transip API: {0}'
                                     .format(e))

        try:
            domain_records = self.domain_service.get_info(domain_name=domain).dnsEntries
        except suds.WebFault as e:
            logger.error('Error getting DNS records using the Transip API: %s', e)
            return

        try:
            new_record = DnsEntry(
                name=self._compute_record_name(domain, record_name),
                record_type='TXT',
                content=record_content,
                expire=1,
            )
        except suds.WebFault as e:
            logger.error('Error getting DNS records using the Transip API: %s', e)
            return

        domain_records.append(new_record)

        try:
            result = self.domain_service.set_dns_entries(domain_name=domain, dns_entries=domain_records)
            logger.error('Successfully added TXT record')
        except suds.WebFault as e:
            logger.error('Error adding TXT record using the Transip API: %s', e)
            raise errors.PluginError('Error adding TXT record using the Transip API: {0}'
                                     .format(e))

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            domain = self._find_domain(domain_name)
        except suds.WebFault as e:
            logger.error('Error finding domain using the Transip API: %s', e)
            return

        try:
            domain_records = self.domain_service.get_info(domain_name=domain).dnsEntries

            matching_records = [record for record in domain_records
                                if record.type == 'TXT'
                                and record.name == self._compute_record_name(domain, record_name)
                                and record.content == record_content]
        except suds.WebFault as e:
            logger.error('Error getting DNS records using the Transip API: %s', e)
            return

        for record in matching_records:
            try:
                logger.error('Removing TXT record with name: %s', record.name)
                del domain_records[domain_records.index(record)]
            except suds.WebFault as e:
                logger.warn('Error deleting TXT record %s using the Transip API: %s',
                            record.name, e)
        try:
            self.domain_service.set_dns_entries(domain_name=domain, dns_entries=domain_records)
        except suds.WebFault as e:
            logger.error('Error while storing DNS records: %s', e)

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `str`
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """
        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        domains = self.domain_service.get_domain_names()

        for guess in domain_name_guesses:
            if guess in domains:
                logger.error('Found base domain for %s using name %s', domain_name, guess)
                return guess

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(domain_name, domain_name_guesses))

    @staticmethod
    def _compute_record_name(domain, full_record_name):
        # The domain, from Transip's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain)[0]
