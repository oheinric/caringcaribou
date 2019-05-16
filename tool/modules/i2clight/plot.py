import matplotlib.pyplot as plt
import matplotlib.animation as anim

from Mux import Mux
from RgbSensor import RgbSensor, ISL_I2C_ADDR


import math
import time

def plot_cont(fun, xmax):
    global y
    y = []
    fig = plt.figure()
    red_ax = fig.add_subplot(3,1,1)
    green_ax = fig.add_subplot(3, 1, 2)
    blue_ax = fig.add_subplot(3, 1, 3)

    def update(i):
        global y
        yi = fun()
        y.append(yi)
        if len(y) > xmax:
            d = len(y) - xmax
            y = y[d:]
        x = range(len(y))
        red_ax.clear()
        green_ax.clear()
        blue_ax.clear()

        red_ax.plot(x, [c[0] for c in y], 'r')
        green_ax.plot(x, [c[1] for c in y], 'g')
        blue_ax.plot(x, [c[2] for c in y], 'b')
        print(i, ': ', yi)

    a = anim.FuncAnimation(fig, update, frames=xmax, repeat=True, interval=20, save_count=0, repeat_delay=20)
    plt.show()

mux1 = Mux(ISL_I2C_ADDR, 0)
sensor1 = RgbSensor(mux1, fast=True)

if not sensor1.init():
    print("Error init sensor")

def read():
    return sensor1.readColor()

plot_cont(read, 100)
