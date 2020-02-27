import setuptools

with open("README.rst", "r") as f:
    long_description = f.read()


setuptools.setup(
    name="aeromiko",
    version="1.1.1",
    author="Andy Truett",
    author_email="andrew.truett@gmail.com",
    description="Aeromiko is a middle-man script to simplify extracting data from Aerohive APs using Netmiko",
    long_description_content_type="text/x-rst",
    long_description=long_description,
    license="MIT License",
    keywords="aerohive netmiko",
    url="https://github.com/andytruett/aeromiko",
    download_url="https://github.com/andytruett/Aeromiko/archive/1.1.1.tar.gz",
    packages=setuptools.find_packages(),
    install_requires=["netmiko>=2.4.0"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
)
