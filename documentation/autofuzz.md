This module is an implementation of the autoFuzzer described in the following KUL paper.
- calibrate - Calibrates the sensors
- identify - Replay a log file and identify message causing a specific event
- bruteforce - Bruteforce all ids with a given payload
- omission - Iterates over all the arbitration ids in a log and consecutively omits all the messages sent to a specific one
- mutate - Mutates the bits in a given range consecutively

This module will also ask you to register the behavior to be observed when it is started up, i.e. register the on and off state of the desired indicator light.
Since this module requires an extra specific hardware sensor harness set-up, we have added a more detailed [install and configure guide](documentation/sensorharnessconfig.md).

```
$ sudo ./cc.py autoFuzz -h

-------------------
CARING CARIBOU v0.3
-------------------

Loaded module 'autoFuzz'

usage: cc.py autoFuzz [-h] [--nsensors NSENSORS] [--calib-file CALIB_FILE]
                      {identify,bruteforce,log,calibrate,omission,mutate} ...

positional arguments:
  {identify,bruteforce,log,calibrate,omission,mutate}

optional arguments:
  -h, --help            show this help message and exit
  --nsensors NSENSORS, -ns NSENSORS
                        The number of attached sensors
  --calib-file CALIB_FILE, -cf CALIB_FILE
                        File to load calibration from
```

