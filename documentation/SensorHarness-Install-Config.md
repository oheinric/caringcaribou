# Configuring the Sensor Harness
The autoFuzzer module was developed with a specific hardware set-up in mind.
Specifically a certain architecture of sensors which is described in the following KUL paper.
To get the sensor harness up and running certain extra dependencies need to be installed.
In what follows we are going to assume that the hardware has been set-up correctly and we will focus on the software side.

# Install
1. Perform the steps for configuring the adafruit board found [here](https://learn.adafruit.com/adafruit-ft232h-breakout/linux-setup)
2. install can-utils
3. pip install Adafruit-GPIO
4. pip isntall j1939

**Note:** make sure you are using a semi-recent implementation of python-can, older implementations might not be supported.
