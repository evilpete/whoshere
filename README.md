# README #

A program to monitor hosts on local network and trigger user defined events via a python callback method

The Goal / design concept is to provide a fast and simple to use interface
supporting both object oriented and procedural methods

-------

## How do I get set up? ##

Simply install the package then set up targets list of network targets and optionally a configuration file


### Install ###
```shell
    python setup.py install --record files.txt
```

You will also need to install [scapy](http://doc.scrapy.org/) :
https://pypi.python.org/pypi/Scrapy

The quick way

```shell
    pip install scrapy
```


#### Target File ####
To run you will to set up a targets list of network targets and optionally a configuration file

The Target file contains a list containing IP_address, Mac_address and name for targets to me monitored.


Example Target file:

The "Target" file is a Json list of three values containing the IP, Mac, and Name/Identifier :

```json
[
  [ "", "14:2d:27:da:a7:03", "laptop_wifi" ],
  [ "", "a4:77:33:58:d0:f6", "livingroom_chromecast" ],
  [ "10.1.1.105", "dc:0b:34:b1:cc:5f", "is_home" ],
  [ "10.1.1.83", "a8:e3:ee:93:3d:c3", "is_ps3_on" ]
]
```
See example [mtargets.json-example](/mtargets.json-example)

The IP address is optional, leave blank is not included, the IP will be obtained when first packet is observed (useful on networks with non-static addressing).

The Mac address is *required* for all entries.

The IP address is optional, leave blank is not included, If a name is not given, the last three octets of the Mac address will me used.


#### Configuration File ####

Example Configuration file:

```ini
[DEFAULT]
http_port = 8088

[whoshere]
log_dir = /var/tmp/whoshere
pid_dir = /var/run
stat_file = /var/www/whoshere-status
time_away = 660

```


Config Options


`time_away`
: set the amount of time in seconds before a target's status is set to 0 (False), default `660`

`stat_file`
: is the path to a json file recording the current status of all targets, this file will be regularly updated, default is `/var/tmp/whoshere-status` (a `.js' and `.json` file will be generated)

`target_file`
: is the path for the target config file, default is `mtargets.json`

`log_dir`
: is the directory path for the log files

`pid_dir`
: is the directory path for the pid file

`iface`
: is the network interface to use, default is `eth0`

`http_port`
: if set simple http server will be run at the port serving the file `stat_file.json` containing the current status of all targets

See [whoshere.ini-example](/whoshere.ini-example)

#### Command line Args ####

```
/usr/local/bin/whoshere --help
usage: whoshere [-h] [--logdir LOG_DIR] [-t TARGET_FILE] [-c CONFIG_FILE] [-v]
                [-r] [--time-away TIME_AWAY] [-i IFACE]
```



`-h`
: Show this help message and exit

`--logdir` *LOG_DIR*
:  Path to log directory

`-t` *TARGET_FILE*
:  target list file,
   default `mtargets.json`

`-c` *CONFIG_FILE*
:   config filename, default `whoshere.ini`

`--verbose`
: Turn on verbose debug

`--redirect-io`
: Redirect_IO to log files

`--time-away` *TIME_AWAY*
: Timeout (in seconds) before target is marked as 'away',
  default `660`

`-i` *IFACE*
:  Network Interface to use,
   default `eth0`

`-P`, `--Printconfig`
: Print Config and Exit


-------

### Example Program/Application ###

#### whoshere-isy ####

[whoshere-isy](/whoshere-isy/whoshere-isy.py) is a example program that sets [State Variables](https://wiki.universal-devices.com/index.php?title=ISY-99i/ISY-26_INSTEON:Variable_Details) in a [ISY](http://www.universal-devices.com/residential/) standalone home automation controler.
The Target `name` field is used to identify the ISY Variables

For Example, the lime:
```
  [ "10.1.1.105", "dc:0b:34:b1:cc:5f", "is_home" ],
```
will cause the ISY Variable named `is_home` value to be set based on the status of device  `dc:0b:34:b1:cc:5f`

failed name matches are silently ignored.


[whoshere-isy](//whoshere-isy/whoshere-isy.py) will try to the [targets](/mtargets.json-example) and [config](/whoshere.ini-example) configuration files from the ISY before loading localy


To uploaded to the ISY with the options `--upload-config`  and `--upload-targets`.


For example:

To upload `whoshere.ini` config file to the ISY
```
    whoshere-isy --config whoshere.ini --upload-config
```

To upload `mtargets.ini` as the targets file to the ISY
```
    whoshere-isy --targets mtargets.ini --upload-targets
```

Uploaded targets and config files have precedence over local files, this behavior can be over ridden with the options `-c` and/or `-t`


Note: [ISYlib](https://github.com/evilpete/ISYlib-python) is required


See also: [ISY Discussion Group](http://forum.universal-devices.com/topic/22106-whoshere/)

-------

#### whoshere-iftt ####

[whoshere-iftt](/whoshere-iftt/whoshere-iftt.py) is a example program that can me used to trigger [IFTT](https://ifttt.com/) Applets

-------

## ToDo ##

* Some type of automated or assisted setup for mtargets file

-------
