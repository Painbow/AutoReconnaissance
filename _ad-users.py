from autorecon.plugins import ServiceScan
import re

class LDAPBaseEnum(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "AD User Enumeration"
        self.tags = ['default', 'safe', 'kerberos', 'active-directory']

    def configure(self):
        self.match_service_name(['^kerberos','^kerberos-sec'])

    async def run(self, service):
        
        process, stdout, stderr = await service.execute(
            'ldapsearch -H ldap://{address} -v -x -s base -b \'\' "(objectClass=*)" "*" +'
        )

        while True:
            line = await stdout.readline()
            if line is not None:
                # Look for rootDomainNamingContext in the output
                match = re.search(r'rootDomainNamingContext:\s+DC=([^,\s]+),DC=([^,\s]+)', line)
                if match:
                    # Construct the DC format
                    domain = f'{match.group(1)}.{match.group(2)}'
                    
                    # Run the second command with the extracted DC
                    await service.execute(
                         f'nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm={domain},userdb=/usr/share/wordlists/seclists/Usernames/Names/names.txt '+'{address}', 
                         outfile='{scandir}/{protocol}_{port}_ad_users.txt'
                         )
            else:
                 break
        await process.wait()