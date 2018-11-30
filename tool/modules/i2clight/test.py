
import time

from Mux import Mux
from RgbSensor import RgbSensor, ISL_I2C_ADDR


def main():
    mux1 = Mux(ISL_I2C_ADDR, 0)
    mux2 = Mux(ISL_I2C_ADDR, 1, mux1.mux_i2c, mux1.gpio)
    sensor1 = RgbSensor(mux1)
    #sensor2 = RgbSensor(mux2)

    if not sensor1.init():
        print("Error init sensor1?")
        return
    #if not sensor2.init():
    #    print("Error init sensor2")
    #    return
    max_delay = 0
    p_time = time.time()
    try:
        while True:
            print("1: " + str(sensor1.readColor()))
            t = time.time()
            d = t - p_time
            p_time = t
            if d > max_delay:
                max_delay = d
            #print("2: " + str(sensor2.readColor()))
    except KeyboardInterrupt:
        print("max delay: " + str(max_delay))


if __name__ == "__main__":
    main()
