# PentestAI Python SDK

Official Python client for the PentestAI platform. This SDK allows you to integrate autonomous pentesting into your Python applications and CI/CD pipelines.

## Installation

```bash
cd sdk
pip install .
```

## Quick Start

### Initialize the Client

```python
from sdk.client import PentestAIClient
import asyncio

async def main():
    client = PentestAIClient(
        base_url='https://api.pentestai.io', 
        api_key='your_api_key_here'
    )
    
    # Start a scan
    scan = await client.start_scan(target_url='https://example.com')
    print(f'Scan started! ID: {scan.scan_id}')
    
    # Check status
    status = await client.get_scan_status(scan.scan_id)
    print(f'Current status: {status["status"]}')

if __name__ == "__main__":
    asyncio.run(main())
```

## Features
- **Async-First**: Built on `httpx` for high-performance asynchronous operations.
- **Type Safety**: Uses `Pydantic` models for request and response validation.
- **CI/CD Ready**: Designed to work seamlessly with our CLI and GitHub Actions templates.
