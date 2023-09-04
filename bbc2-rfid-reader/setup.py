import subprocess
from os import path
from setuptools import setup
from setuptools.command.install import install


here = path.abspath(path.dirname(__file__))

with open('README.rst') as f:
    readme = f.read()


class MyInstall(install):
    def run(self):
        try:
            pass

        except Exception as e:
            print(e)
            exit(1)

        else:
            install.run(self)


bbc2_requires = [
                    'py-bbclib>=1.6',
                    'pyserial>=3.5'
                ]

bbc2_packages = [
                 'bbc2',
                 'bbc2.lib'
                ]

bbc2_commands = []

bbc2_classifiers = [
                    'Development Status :: 4 - Beta',
                    'Programming Language :: Python :: 3.8',
                    'Topic :: Software Development'
                   ]

setup(
    name='bbc2-rfid-reader',
    version='0.3.4',
    description='RFID reader drivers for BBc-2',
    long_description=readme,
    url='https://github.com/beyond-blockchain',
    author='beyond-blockchain.org',
    author_email='office@beyond-blockchain.org',
    license='Apache License 2.0',
    classifiers=bbc2_classifiers,
    cmdclass={'install': MyInstall},
    packages=bbc2_packages,
    scripts=bbc2_commands,
    install_requires=bbc2_requires,
    zip_safe=False)


# end of setup.py
