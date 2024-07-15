from setuptools import find_packages, setup
from setuptools.command.install import install
import subprocess


with open('src/README.md', 'r') as f:
    long_description = f.read()


class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        subprocess.run(["python", "-m", "spacy", "download", "en_core_web_lg"])

setup(
    name="seclint",
    version="0.0.1",
    author="Claudia Mamede",
    author_email="cmamede@andrew.cmu.edu",
    description="A short description of your project",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    url="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.6",
    install_requires=[
        "click",
        "pyyaml",
        "spacy",

    ],
    extras_require={
        "dev": ["pytest", "twine"]
    },
    package_data={
        "": ["entities/patterns.jsonl", "config/rules.yml"]
    },
    include_package_data=True,
    packages=find_packages("src"),
    package_dir={"": "src"},
    entry_points ={ 
                'console_scripts': [ 
                    'seclint = seclint.main:main'
                ] 
            }, 

    cmdclass={
        'install': PostInstallCommand,
    }

)