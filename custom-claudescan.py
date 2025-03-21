from autorecon.plugins import ServiceScan
import re

class LDAPBaseEnum(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Claude Enumeration"
        self.tags = ['default', 'safe', 'ai']

    def configure(self):
        self.match_service_name('^ldap')

    def is_command(self, line):
        """Check if a line contains a command."""
        match = re.match(r'^\d+[\.\)]\s*(.+)$', line.strip())
        return match.group(1) if match else None
    
    async def run(self, service):
        process, stdout, stderr = await service.execute('python3 /home/kali/AutoRecon/plugins/_claudescan.py {port} {protocol} {address}', outfile='{scandir}/{protocol}_{port}_claude.txt')
        
        await stdout.readline()
        commands = []
        # First collect all commands
        while True:
            line = await stdout.readline()
            if not line:
                break
                
            line = line.strip()
            command = self.is_command(line)
            #print(line, command)
            
            if command:
                commands.append(command)
        
        # Then execute them all
        if not commands:
            print("No commands found in Claude AI output.")
        else:
            print(f"Found {len(commands)} commands to execute")
            for i, command in enumerate(commands, 1):
                print(f"Executing command {i}: {command}")
                await service.execute(
                    command,
                    outfile='{scandir}/{protocol}_{port}_claude_command_'+str(i)+'.txt'
                )
            
        await process.wait()
