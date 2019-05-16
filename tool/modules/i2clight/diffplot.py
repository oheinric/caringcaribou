import matplotlib.pyplot as plt
import matplotlib.animation as anim

from Mux import Mux
from RgbSensor import RgbSensor, ISL_I2C_ADDR


import math
import time

off_val = None
on_val = None

def plot_cont(fun, xmax):
    global y
    y = []
    fig = plt.figure()
    on_ax = fig.add_subplot(3, 1, 1)
    of_ax = fig.add_subplot(3, 1, 2)
    df_ax = fig.add_subplot(3, 1, 3)

    def update(i):
        global y
        yi = fun()
        y.append(yi)
        if len(y) > xmax:
            d = len(y) - xmax
            y = y[d:]
        x = range(len(y))
        on_ax.clear()
        of_ax.clear()
        df_ax.clear()

        on_ax.plot(x, [c[0] for c in y])
        of_ax.plot(x, [c[1] for c in y])
        df_ax.plot(x, [c[1] - c[0] for c in y])

        print(i, ': ', yi)

    a = anim.FuncAnimation(fig, update, frames=xmax, repeat=True, interval=20, save_count=0, repeat_delay=20)
    plt.show()

mux1 = Mux(ISL_I2C_ADDR, 0)
sensor1 = RgbSensor(mux1, fast=True)

if not sensor1.init():
    print("Error init sensor")

def read():
    val = sensor1.readColor()
    off_dif = (val[0] - off_val[0], val[1] - off_val[1], val[2] - off_val[2])
    on_dif = (val[0] - on_val[0], val[1] - on_val[1], val[2] - on_val[2])
    off_dif = math.sqrt(off_dif[0]*off_dif[0] + off_dif[1]*off_dif[1] + off_dif[2]*off_dif[2])
    on_dif = math.sqrt(on_dif[0]*on_dif[0] + on_dif[1]*on_dif[1] + on_dif[2]*on_dif[2])

    return on_dif, off_dif

print("Press enter when off")
raw_input()
off_val = sensor1.readColor()
print("Press enter when on")
raw_input()
on_val = sensor1.readColor()

plot_cont(read, 100)
