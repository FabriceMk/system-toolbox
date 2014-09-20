"""

This tool will scan a predefined folder with x509 pem certificates and check the expiration dates of all the certificates.

It will send reminder emails several times before a certificate expires.

Uses sendmail to send reminders, will add Web-based mailers services support later

Uses openssl command to check the certificate.

Best used once a day through a cron

@author: FabriceMk

"""

from subprocess import Popen, PIPE
from email.mime.text import MIMEText
import os, sys
from optparse import OptionParser
import time
from datetime import date

'''
Class for sending reminder mails through sendmail
'''


class MailSender(object):
    SENDMAIL_PATH = '/usr/sbin/sendmail'

    def __init__(self):
        #Put the recipients for the reminders in this array
        self.recipients = ['recipient@mail']

        #Put the sender address here
        self.sender = 'sender@mail'

    def send_email(self, subject, message):
        mail = MIMEText(message)
        mail['Subject'] = subject
        mail['From'] = self.sender
        mail['To'] = ",".join(self.recipients)

        p = Popen([self.SENDMAIL_PATH, '-toi'], stdin=PIPE)
        p.communicate(mail.as_string())


'''
Main class to check the expiration of a certificate
'''


class ExpirationChecker(object):
    OPENSSL_PATH = '/usr/bin/openssl'

    def __init__(self):
        '''
        Set the days when the reminders mails must be sent before the expiration date
        ie [15, 7, 2] will send a reminder email 15, 7 and 2 days prior the certificate expiration

        The script will always send a reminder the day of the expiration so no need to include the 0 value
        '''
        self.alerts_deadlines = [15, 10, 7, 4, 3, 2, 1]
        #Ensure a desc sorted list
        self.alerts_deadlines.sort(reverse=True)

        self.mail_sender = MailSender()

    '''
    Service method to check the expiration date of a certificate.
    Uses the openssl command to extract the expiration date
    '''

    def _check_expiration_date(self, cert_name, absolute_path):

        command = [self.OPENSSL_PATH, "x509", "-in", absolute_path, "-enddate", "-noout"]

        try:
            output, errors = Popen(command, stdout=PIPE).communicate()
            if errors is None:
                string_date = output.split('=')[1].rstrip('\n')
                expiration = time.strptime(string_date, '%b %d %H:%M:%S %Y %Z')
                expiration = date.fromtimestamp(time.mktime(expiration))
                now = date.today()

                delta = expiration - now

                if delta.days < 0:
                    # Certificate Outdated
                    subject = 'Certificate expired : ' + cert_name
                    message = 'The certificate "' + cert_name + '" has expired ' + str(
                        abs(delta.days)) + ' days ago. Regenerate if used.'
                    self.mail_sender.send_email(subject, message)

                elif delta.days == 0:
                    #Expiration today
                    subject = 'Certificate will expire today : ' + cert_name
                    message = 'The certificate "' + cert_name + '" will expire today. Regenerate if used.'
                    self.mail_sender.send_email(subject, message)

                else:
                    #Certificate not expired
                    for deadline in self.alerts_deadlines:
                        if delta.days == deadline:
                            subject = 'Certificate expiration in ' + str(delta.days) + ' : ' + cert_name
                            message = 'The certificate "' + cert_name + '" will expire in ' + str(
                                delta.days) + ' days. Remember to regenerate it.'
                            self.mail_sender.send_email(subject, message)
                            #No need to continue
                            break
        except:
            print "Unexpected error"

    '''
    Checks a single specified certificate
    '''

    def check_certificate(self, target_certificate):
        self._check_expiration_date(target_certificate, os.path.abspath(target_certificate))

    '''
    Scans a directory, looks for all .pem certificates found and process them
    '''

    def check_certificates_directory(self, target_directory):
        certificates_list = [cert for cert in os.listdir(target_directory) if cert.lower().endswith('.pem')]

        for cert in certificates_list:
            self._check_expiration_date(cert, os.path.abspath(target_directory) + '/' + cert)


def main(argv):
    parser = OptionParser()
    parser.add_option("-d", "--directory", type="string", dest="sourcedir",
                      help="checks expiration dates for x509 certificates in DIRECTORY", metavar="DIRECTORY")
    parser.add_option("-f", "--file", type="string", dest="sourcefile",
                      help="checks expiration dates for x509 FILE certificate", metavar="FILE")
    (options, _) = parser.parse_args()

    if options.sourcefile:
        checker = ExpirationChecker()
        checker.check_certificate(options.sourcefile)

    if options.sourcedir:
        checker = ExpirationChecker()
        checker.check_certificates_directory(options.sourcedir)


if __name__ == "__main__":
    main(sys.argv[1:])
