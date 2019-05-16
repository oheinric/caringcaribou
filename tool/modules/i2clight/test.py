
import time

from Mux import Mux
from RgbSensor import RgbSensor, ISL_I2C_ADDR

N_SENSORS = 1
def main():
    sensors = []

    mux1 = Mux(ISL_I2C_ADDR, 0)
    sensors.append(RgbSensor(mux1))
    for i in range(N_SENSORS - 1):
        mux = Mux(ISL_I2C_ADDR, i + 1, mux1.mux_i2c, mux1.gpio)
        sensor = RgbSensor(mux, fast=False)
        if not sensor.init():
            print("Error init sensor", i + 1)
            return
        sensors.append(sensor)

    max_delay = 0
    p_time = time.time()

    try:
        while True:
            for i in range(N_SENSORS):
                print(i+1, ": ", sensors[i].readColor())
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
