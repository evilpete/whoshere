# README #

#### whoshere-isy ####

[whoshere-isy](/whoshere-isy.py) is a example program that sets [State Variables](https://wiki.universal-devices.com/index.php?title=ISY-99i/ISY-26_INSTEON:Variable_Details) in a [ISY](http://www.universal-devices.com/residential/) standalone home automation controler.
The Target `name` field is used to identify the ISY Variables

For Example, the lime:
```
  [ "10.1.1.105", "dc:0b:34:b1:cc:5f", "is_home" ],
```
will cause the ISY Variable named `is_home` value to be set based on the status of device `dc:0b:34:b1:cc:5f`

failed name matches are silently ignored.


[whoshere-isy](/whoshere-isy.py) will try to the [targets](/mtargets.json-example) and [config](/whoshere.ini-example) configuration files from the ISY before loading localy


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

