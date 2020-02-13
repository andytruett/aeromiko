========
Aeromiko
========

Aeromiko is a middle-man script to simplify extracting data from Aerohive APs using Netmiko

Installation
------------

To install Aeromiko, simply use pip:

.. code-block::

  $ pip install Aeromiko

Aeromiko has the following requirements (which pip will install for you)

- netmiko >= 2.4.0

Documentation
-------------

https://andytruett.github.io/aeromiko/

Usage
-----

.. code-block::

  import aeromiko

  ip = 127.0.0.1
  username = "admin"
  password = "password"

  access_point = aeromiko.AP(ip, username, password)

  access_point.connect()

  hostname = access_point.get_hostname()
  print(hostname)

-or-

`see example script <https://github.com/andytruett/Aeromiko/tree/master/example>`_

.. image:: https://raw.githubusercontent.com/andytruett/Aeromiko/master/example/example.png
