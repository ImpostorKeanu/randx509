from OpenSSL import crypto, SSL
from dataclasses import dataclass
from io import BytesIO

class ArgumentError(Exception):
    pass

class AttributeError(Exception):
    pass

def checkname(method):

    def decorator(self, name, *args, **kwargs):
        '''Check the name argument supplied to methods. The leading
        argument must be `name`. If the name matches an alias, then
        the value of `name` us replaced with the associated alias.
        '''

        if not name in Fields.VALID_FIELDS:

            for key, aliases in Certificate.ALIAS_MAP.items():
    
                if name in aliases:
                    name = key
                    break

        return method(self, name, *args, **kwargs)

    return decorator

class StaticFields:
    '''Override methods to facilitate alias resolution through the
    `@checkname` decorator.
    '''

    @checkname
    def __setattr__(self, name, value):
        return super().__setattr__(name, value)

    @checkname
    def __delattr__(self, name, value):
        return super().__setattr__(name, value)

    @checkname
    def __getattribute__(self, name):
        return super().__getattribute__(name)

class Fields:
    '''Class representing fields of an X509 certificate. Aliases for
    the fields are defined here as well and can be resolved using the
    `Fields.ALIAS_MAP` class variable, which is a dictionary mapping
    fields to possible alias values.
    '''

    ALIAS_MAP = {
        'country':('countryName','C',),
        'state_or_province_name':('stateOrProvinceName','ST',),
        'locality_name':('localityName','L',),
        'organization_name':('organizationName','O',),
        'organizational_unit_name':('organizationalUnitName','OU',),
        'common_name':('commonName','CN',),
        'email_address':(),
        'serial':(),
        'not_before':(),
        'not_after':(),
    }

    # List of valid field names
    VALID_FIELDS = sorted(list(ALIAS_MAP.keys()))

    # Comprehensive list of all valid aliases
    VALID_ALIASES = []
    for aliases in ALIAS_MAP.values():
        VALID_ALIASES += aliases

    # Sort the aliases
    VALID_ALIASES = sorted(VALID_ALIASES)

    # Comprehensive list of all valid name values
    VALID_FIELDS_ALL = sorted(VALID_FIELDS+VALID_ALIASES)

@dataclass
class CertificateData(StaticFields,Fields):

    country: str = ''
    state_or_province_name: str = ''
    locality_name: str = ''
    organization_name: str = ''
    organizational_unit_name: str = ''
    common_name: str = ''
    email_address: str = ''
    serial: int = 0
    not_before: int = 0
    not_after: int = 10*365*24*60*60
    enc_algo: str = 'rsa'
    key_length: int = 1024

class Arbiter:

    def __init__(self, certdata, enc_algo='rsa', key_length=1024,
            digest_algorithm='sha256'):

        # TODO
        '''
        - apply checks to enc_algo, key_length, and digest algorithm
        '''

        self.certdata = certdata
        self.enc_algo = enc_algo
        self.key_length = key_length
        self.digest_algorithm = digest_algorithm

    def validate(self):
        '''Apply loose valudations to the current state of the
        Certificate object. Raises `AttributeError` when an invalid
        value has been assigned to an attribute. Returns `True` when
        validation succeeded.
        '''

        # Allow only specific values for the encryption algorithm
        if self.enc_algo not in ['rsa','dsa']:
            raise AttributeError(
                'Invalid encryption algorithm applied to cert ({})' \
                    .format(self.enc_algo))

        # Ensure a value has been supplied for all fields
        for k,v in self.certdata.__dict__.items():

            # ===========================================
            # REQUIRE A VALUE FOR EACH INSTANCE ATTRIBUTE
            # ===========================================
            '''
            - Strings must not be empty
            - Integers must be greater than zero
            '''

            if (isinstance(v,str) and v == '') or \
                    (isinstance(v,int) and v < 0) or \
                    (v == None):
                raise AttributeError(
                    'Value required for attribute ({}). Currently: {}'\
                        .format(k,str(v) if v != '' else 'empty')
                )

        return True

    def generate(self, filetype, issuer_subject=None, issuer_keypair=None):
        '''

        - filetype - options: pem, asn1

        - issuer_subject - the subject that is issuing and signing the
        current certificate

        - cryptotype - rsa or dsa
        - digesttype - sha256

        - digest types defined here: https://github.com/openssl/openssl/blob/master/include/openssl/evp.h
        - crypto types defined here: https://github.com/pyca/pyopenssl/blob/4211b909fb5aa2c4db2b0f5acbab1480972a0554/src/OpenSSL/crypto.py
        '''

        self.validate()

        # ====================
        # DERIVE THE ALGORITHM
        # ====================

        if self.enc_algo == 'rsa':
            enc_algo = crypto.TYPE_RSA
        else:
            enc_algo = crypto.TYPE_DSA

        # ===============
        # PREPARE THE KEY
        # ===============

        # Generate a keypair
        self.keypair = crypto.PKey()
        self.keypair.generate_key(crypto.TYPE_DSA, self.key_length)

        # =========================
        # PREPARE ISSUER COMPONENTS
        # =========================
        '''
        '''

        self.issuer_keypair = \
            issuer_keypair if issuer_keypair else self.keypair
        self.issuer_subject = issuer_subject

        self.initCryptoCert()
        self.initCert(filetype)

    def initCryptoCert(self):
        '''Initialize the OpenSSL certificate with values bound to the
        current Certificate's instance variables.
        '''

        # Initialize the certificate
        self.cryptocert = crypto.X509()

        # =======================================================
        # UPDATE THE CERTIFICATES SUBJECT WITH INSTANCE VARIABLES
        # =======================================================

        # Use values from the ALIAS_MAP to pull the instance variable
        # from the current certificate
        for attr in Fields.ALIAS_MAP.values():

            # Skip any attribute where aliases are not present
            if not attr: continue
            try:

                # Set the value of the OpenSSL certificate subject to the
                # value of the instance variable from the Certificate
                setattr(self.cryptocert.get_subject(),
                        attr[0],
                        getattr(self.certdata, attr[0]))

            except Exception as error:

                # Raise a ValueError exception when an invalid value is
                # supplied for the OpenSSL certificate. Reflect that error
                # into the output as well.
                raise ValueError(
                    'Invalid value supplied for {}: {}'.format(
                     attr[0], error))

        # =========================
        # DERIVE THE ISSUER SUBJECT
        # =========================
        '''
        - Any OpenSSL subject can be provided during configuration
        - See Certificate.generate() 
        - Otherwise, the ceriticate is self-signed
        '''

        if not self.issuer_subject:
            self.issuer_subject = self.cryptocert.get_subject()

        # ================
        # PREPARE THE CERT
        # ================

        self.cryptocert.set_serial_number(self.certdata.serial)
        self.cryptocert.gmtime_adj_notBefore(self.certdata.not_before)
        self.cryptocert.gmtime_adj_notAfter(self.certdata.not_after)

        self.cryptocert.set_issuer(self.issuer_subject)
        self.cryptocert.set_pubkey(self.keypair)
        self.cryptocert.sign(self.issuer_keypair, self.digest_algorithm)

    def initCert(self, filetype):
        '''
        - filetype - pem or asn1
        '''

        filetype = filetype.upper()
        if not filetype in ['ASN1', 'PEM']:
            raise ValueError('filetype must be ASN1 or PEM')
        filetype = 'FILETYPE_'+filetype

        # =====================================================
        # GET THE GENERATED CERT/KEY VALUES FROM OpenSSL.crypto
        # =====================================================

        certbytes, keybytes = BytesIO(), BytesIO()

        certbytes.write(
            crypto.dump_certificate(getattr(crypto, filetype), self.cryptocert)
        )

        keybytes.write(
            crypto.dump_privatekey(getattr(crypto, filetype), self.keypair)
        )

        certbytes.seek(0)
        keybytes.seek(0)

        # ===============================
        # SET CERT/KEY INSTANCE VARIABLES
        # ===============================

        self.certbytes = certbytes.read()
        self.privatekey_bytes = keybytes.read()

        # ASN1 data structures can't be represented as a string, thus
        # the certstring and privatekey_string instance variables are
        # set to None
        if filetype.endswith('ASN1'):
            self.certstring = None
            self.privatekey_string = None
        else:
            self.certstring = self.certbytes.decode()
            self.privatekey_string = self.privatekey_bytes.decode()
