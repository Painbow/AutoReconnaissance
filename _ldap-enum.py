from autorecon.plugins import ServiceScan
import re

class LDAPBaseEnum(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "LDAP Base Enumeration"
        self.tags = ['default', 'safe', 'ldap', 'active-directory']

    def configure(self):
        self.match_service_name('^ldap')

    async def run(self, service):
        
        process, stdout, stderr = await service.execute(
            'ldapsearch -H ldap://{address} -v -x -s base -b \'\' "(objectClass=*)" "*" +',
            outfile='{scandir}/{protocol}_{port}_ldap_base_enum_v1.txt'
        )

        while True:
            line = await stdout.readline()
            if line is not None:
                # Look for rootDomainNamingContext in the output
                match = re.search(r'rootDomainNamingContext:\s+DC=([^,\s]+),DC=([^,\s]+)', line)
                if match:
                    # Construct the DC format
                    dc_format = f'dc={match.group(1)},dc={match.group(2)}'
                    
                    # Run the second command with the extracted DC
                    await service.execute(
                        'ldapsearch -H ldap://{address} -v -x -b '+f'{dc_format}'+' "(objectClass=*)" "*" +',
                        outfile='{scandir}/{protocol}_{port}_ldap_base_enum_v2.txt'
                    )
            else:
                 break
        await process.wait()