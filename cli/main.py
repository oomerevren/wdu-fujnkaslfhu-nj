import click
import asyncio
from sdk.client import PentestAIClient
from app.config import settings

client = PentestAIClient(base_url=settings.API_V1_STR, api_key="dev-key")

@click.group()
def cli():
    """PentestAI CLI Tool"""
    pass

@cli.command()
@click.argument('url')
def scan(url):
    """Start a new scan for the given URL"""
    async def run():
        result = await client.create_scan(target_url=url)
        click.echo(f'Scan started! ID: {result.get("id")}')
    asyncio.run(run())

@cli.command()
@click.argument('scan_id')
def status(scan_id):
    """Check the status of a specific scan"""
    async def run():
        result = await client.get_scan_status(scan_id)
        click.echo(f'Scan Status: {result.get("status")}')
    asyncio.run(run())

if __name__ == "__main__":
    cli()