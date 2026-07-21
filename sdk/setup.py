
from setuptools import setup, find_packages

setup(
    name='pentestai-sdk',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'httpx>=0.27.0',
        'pydantic>=2.0.0',
    ],
    python_requires='>=3.8',
)
