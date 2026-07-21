
import argparse
import asyncio
import sys
import os

# Add parent directory to path to import SDK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from sdk.client import PentestAIClient

def main():
    parser = argparse.ArgumentParser(description='PentestAI CLI Tool')
    parser.add_argument('--url', default='http://localhost:8000', help='API Base URL')
    parser.add_argument('--key', required=True, help='API Key')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scan Command
    scan_parser = subparsers.add_parser('scan', help='Start a new scan')
    scan_parser.add_argument('target', help='Target URL to scan')

    # Status Command
    status_parser = subparsers.add_parser('status', help='Check scan status')
    status_parser.add_argument('id', help='Scan ID')

    args = parser.parse_args()
    client = PentestAIClient(base_url=args.url, api_key=args.key)

    if args.command == 'scan':
        asyncio.run(start_scan(client, args.target))
    elif args.command == 'status':
        asyncio.run(check_status(client, args.id))
    else:
        parser.print_help()

async def start_scan(client, target):
    try:
        print(f'[*] Starting scan for: {target}...')
        # In a real scenario, this would call the API
        # For now, we simulate the SDK call
        print(f'[+] Scan initiated successfully. Target: {target}')
    except Exception as e:
        print(f'[!] Error: {e}')

async def check_status(client, scan_id):
    try:
        print(f'[*] Checking status for scan: {scan_id}...')
        print(f'[+] Status: COMPLETED (Simulated)')
    except Exception as e:
        print(f'[!] Error: {e}')

if __name__ == "__main__":
    main()
