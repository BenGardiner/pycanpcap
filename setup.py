from setuptools import setup, find_packages

setup(
    name='pycanpcap',
    version='0.2',
    packages=find_packages(),
    description='candump and write a pcap using scapy (and python-can)',
    install_requires=['scapy >= 2.4.5', 'python-can~=4.3.1'],
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url='https://github.com/BenGardiner/pycanpcap',
    author='Ben Gardiner',
    author_email='ben.l.gardiner@gmail.com',
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
    ],
    include_package_data=True,
)
