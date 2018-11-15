#!/usr/bin/python2

from Adafruit_GPIO import FT232H

MUX_ADDRESS = 0x70

class Mux:
    def __init__(self, addr, port=0, mux_i2c=None, gpio=None, mux_addr=MUX_ADDRESS):
        if mux_i2c is None:
            FT232H.use_FT232H()
            gpio = FT232H.FT232H()
            mux_i2c = FT232H.I2CDevice(gpio, mux_addr)

        self.gpio = gpio
        self.mux_i2c = mux_i2c
        self.mask = (1 << port) & 0xFF

        self.i2c = FT232H.I2CDevice(gpio, addr)


    def activate(self):
        self.mux_i2c.writeRaw8(self.mask)

    def write8(self, reg, val):
        self.activate()
        self.i2c.write8(reg, val)

    def readU8(self, reg):
        self.activate()
        return self.i2c.readU8(reg)

    def readU16(self, reg):
        self.activate()
        return self.i2c.readU16(reg)

    def ping(self):
        self.activate()
        return self.i2c.ping()
