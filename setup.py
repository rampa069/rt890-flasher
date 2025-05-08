from setuptools import setup, find_packages

setup(
    name="rt890-flasher",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pyserial>=3.5",
    ],
    entry_points={
        'console_scripts': [
            'rt890-flash=rt890_flasher.cli:flash_command',
            'rt890-backup=rt890_flasher.cli:backup_command',
            'rt890-restore=rt890_flasher.cli:restore_command',
        ],
    },
    author="Ramon Martinez",
    author_email="rampa@encomix.org",
    description="A tool for flashing and backing up Radtel RT-890 firmware",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/rampa069/rt890-flasher",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
) 