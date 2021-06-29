# Switch scanner

Installation:
```sh
$ pip3 install -r requirements.txt
$ apt install python-pytest -y
```

Simple run:
```sh
$ pytest app.py
```

Run without traceback:
```sh
$ pytest app.py --tb=no
```

Run tests which match the given substring expression:
```sh
$ pytest app.py -k test_switchport_port_security
```

Run tests and exit instantly on first error or failed test:
```sh
$ pytest app.py -x
```

Run tests without warnigs:
```sh
$ pytest app.py --disable-warnings
```

Run tests with all the output:
```sh
$ pytest app.py -s
```


[DOCUMENTATION](https://github.com/PnzJust/switch-ios-scanner/tree/main/documentation)