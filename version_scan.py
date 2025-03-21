import json
import requests
import os
import asyncio
import re
import subprocess
import sys

class ServiceAnalyzer:
    def __init__(self):
        self.name = "Version Analysis"

    async def run_nmap(self, target):
        print(f"Starting NMAP scan on {target}...")
        cmd = f'nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- {target}'
        
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        return stdout.decode()

    def parse_nmap_output(self, nmap_output):
        services = []
        port_pattern = r'(\d{1,5})\/(tcp|udp)\s+open\s+(\S+)\s+(?:syn-ack ttl \d+)?(?:\s*\n|\s+(.+)\n)'
        matches = re.finditer(port_pattern, nmap_output, re.MULTILINE)
        
        for match in matches:
            service_info = {
                'port': match.group(1),
                'protocol': match.group(2),
                'service': match.group(3),
                'version': match.group(4).strip() if match.group(4) else "unknown"
            }
            print(f"Found service: {service_info}")
            services.append(service_info)
            
        return services
    
    def version_scan(self, service_info):
        version_patterns = [
            r'(.*?\d+\.[\d.]+\w*)',  # Matches text ending with version numbers like 2.4.1a
            r'(.*?\d+\.\d+)',        # Matches text ending with simple version numbers like 2.4
            r'(.*?version\s+[0-9.]+\w*)', # Matches text with "version X.Y.Z"
            r'(.*?v\s+[0-9.]+\w*)', # Matches text with "v X.Y.Z"
        ]

        if service_info['version'] != "unknown":
            version_info = []
            version_string = service_info['version']
            
            for pattern in version_patterns:
                matches = re.findall(pattern, version_string, re.IGNORECASE)
                if matches:
                    version_info.extend([match.strip() for match in matches])
                    break  # Take the first matching pattern only
            
            if version_info:
                return {
                    'service': service_info['service'],
                    'versions': version_info,
                    'full_version': service_info['version']
                }
        return None

    async def search_exploitdb(self, version):
        """Search ExploitDB using searchsploit with recursive term reduction"""
        async def try_search(search_term):
            try:
                cmd = f'searchsploit -j {search_term}'
                print(f"Trying search with: {search_term}")
                
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if stderr:
                    print(f"Searchsploit stderr: {stderr.decode()}")
                    
                output = stdout.decode()
                try:
                    results = json.loads(output)
                    # Check if we got any results
                    if results.get('RESULTS_EXPLOIT') or results.get('RESULTS_SHELLCODE'):
                        print(f"Found results with term: {search_term}")
                        return results
                    return None
                except json.JSONDecodeError:
                    print(f"Failed to parse searchsploit JSON output for term: {search_term}")
                    return None
                    
            except Exception as e:
                print(f"Error searching ExploitDB with term '{search_term}': {str(e)}")
                return None

        try:
            # Split the version string into terms
            terms = version.split()
            
            # Try increasingly shorter combinations of terms
            for i in range(len(terms), 0, -1):
                search_term = ' '.join(terms[:i])
                results = await try_search(search_term)
                if results:
                    # Add information about which search term succeeded
                    results['SUCCESSFUL_TERM'] = search_term
                    return results
            
            # If no results found with any combination
            print("No results found with any search term combination")
            return {
                "SEARCH": version,
                "RESULTS_EXPLOIT": [],
                "RESULTS_SHELLCODE": [],
                "SUCCESSFUL_TERM": None
            }
                    
        except Exception as e:
            print(f"Error in search_exploitdb: {str(e)}")
            return {
                "SEARCH": version,
                "RESULTS_EXPLOIT": [],
                "RESULTS_SHELLCODE": [],
                "SUCCESSFUL_TERM": None
            }

    async def analyze_vulnerabilities(self, service_info, version_data):
        print(f"\nAnalyzing vulnerabilities for: {version_data['versions']}")
        
        results = {
            'service': service_info['service'],
            'port': service_info['port'],
            'version': version_data['versions'],
            'exploits': None,
            'cves': []
        }

        print(f"Searching exploitdb for: {version_data['versions'][0]}")
        exploits = await self.search_exploitdb(version_data['versions'][0])
        print(f"Searchsploit results: {json.dumps(exploits, indent=2)}")
        results['exploits'] = exploits

        return results

    async def analyze_target(self, target):
        try:
            nmap_output = await self.run_nmap(target)
            services = self.parse_nmap_output(nmap_output)
            
            all_results = []
            for service_info in services:
                version_data = self.version_scan(service_info)
                if version_data:
                    vuln_results = await self.analyze_vulnerabilities(service_info, version_data)
                    all_results.append(vuln_results)

            output_dir = "version_scan_results"
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"{target}_vulnerability_analysis.txt")
            
            self.write_results(output_file, target, all_results)
            print(f"Results saved to {output_file}")

        except Exception as e:
            print(f"Error analyzing target: {str(e)}")
            raise

    def write_results(self, output_file, target, all_results):
        # Write summary file
        with open(output_file, "w") as f:
            f.write(f"Vulnerability Analysis Report for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            # Write summary of all services
            f.write("Services Analyzed:\n")
            for result in all_results:
                f.write(f"- {result['service']} on port {result['port']}\n")
            f.write("\n" + "=" * 50 + "\n")
            f.write("\nDetailed results for each service can be found in separate files in the same directory.\n")

        # Create separate files for each service
        output_dir = os.path.dirname(output_file)
        for result in all_results:
            # Create a safe filename from the service name
            safe_service_name = re.sub(r'[^\w\-_]', '_', result['service'])
            service_file = os.path.join(output_dir, 
                f"{target}_{safe_service_name}_port_{result['port']}_exploits.txt")
            
            with open(service_file, "w") as f:
                f.write(f"Vulnerability Analysis for {result['service']} (Port {result['port']})\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Service Details:\n")
                f.write(f"Port: {result['port']}\n")
                f.write(f"Version: {', '.join(result['version'])}\n")
                if result['exploits'].get('SUCCESSFUL_TERM'):
                    f.write(f"Results found using search term: {result['exploits']['SUCCESSFUL_TERM']}\n")
                f.write("\n")

                f.write("Exploits Found:\n")
                f.write("-" * 30 + "\n")
                
                if result.get('exploits', {}).get('RESULTS_EXPLOIT'):
                    for exploit in result['exploits']['RESULTS_EXPLOIT']:
                        f.write(f"Title: {exploit.get('Title', 'N/A')}\n")
                        f.write(f"EDB-ID: {exploit.get('EDB-ID', 'N/A')}\n")
                        f.write(f"Date: {exploit.get('Date', 'N/A')}\n")
                        f.write(f"Author: {exploit.get('Author', 'N/A')}\n")
                        f.write(f"Type: {exploit.get('Type', 'N/A')}\n")
                        f.write(f"Platform: {exploit.get('Platform', 'N/A')}\n")
                        f.write(f"Path: {exploit.get('Path', 'N/A')}\n")
                        f.write("-" * 20 + "\n")
                else:
                    f.write("No exploits found\n")
                
                if result.get('exploits', {}).get('RESULTS_SHELLCODE'):
                    f.write("\nShellcodes Found:\n")
                    f.write("-" * 30 + "\n")
                    for shellcode in result['exploits']['RESULTS_SHELLCODE']:
                        f.write(f"Title: {shellcode.get('Title', 'N/A')}\n")
                        f.write(f"Path: {shellcode.get('Path', 'N/A')}\n")
                        f.write("-" * 20 + "\n")

            print(f"Written service results to: {service_file}")

async def main():
    if len(sys.argv) < 2:
        print("Usage: python version_analyzer.py <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    analyzer = ServiceAnalyzer()
    await analyzer.analyze_target(target)

if __name__ == "__main__":
    asyncio.run(main())