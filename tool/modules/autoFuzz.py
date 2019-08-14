from __future__ import print_function

from lib.can_actions import CanActions, ARBITRATION_ID_MAX, ARBITRATION_ID_MIN
from lib.common import hex_str_to_nibble_list, int_from_byte_list, list_to_hex_str, str_to_int_list

from time import sleep
from sys import exit
import argparse
import re
import time
import sys
import math
import can
import random


from i2clight.Mux import Mux
from i2clight.RgbSensor import RgbSensor, ISL_I2C_ADDR

import j1939

J1939_PROP_ID_START = 0xFF00
J1939_PROP_ID_END = 0xFFFF

try:
    input = raw_input
except NameError:
    pass

def read_light(sensor):
    return sensor.readColor()
    # t = sensor.readColor()
    # s = t[0]+t[1]+t[2]
    # return (t[0]/s, t[1]/s, t[2]/s)
    # return math.sqrt(t[0]*t[0]+t[1]*t[1]+t[2]*t[2])

FILE_LINE_COMMENT_PREFIX = "#"

class CanMessage:
    """
    Message wrapper class used by file parsers.
    """

    def __init__(self, arb_id, data, delay, is_extended=False, is_error=False, is_remote=False):
        """
        :param arb_id: int - arbitration ID
        :param data: list of ints - data bytes
        :param delay: float - delay in seconds
        """
        self.arb_id = arb_id
        self.data = data
        # Negative delays are not allowed
        self.delay = max([delay, 0.0])
        self.is_extended = is_extended
        self.is_error = is_error
        self.is_remote = is_remote


def parse_candump_line(curr_line, prev_timestamp, force_delay):
    """
    Parses a line on candump log format, e.g.
    (1499197954.029156) can0 123#c0ffee

    :param curr_line: str to parse
    :param prev_timestamp: datetime timestamp of previous message (to calculate delay)
    :param force_delay: float value to override delay or None to use calculated delay
    :return: CanMessage representing 'curr_line', datetime.datetime timestamp of 'curr_line'
    """
    segments = curr_line.strip().split(" ")
    time_stamp = float(segments[0][1:-1])
    msg_segs = segments[2].split("#")
    arb_id = int(msg_segs[0], 16)
    data = str_to_int_list(msg_segs[1])
    if prev_timestamp is None:
        delay = 0
    elif force_delay is not None:
        delay = force_delay
    else:
        delay = time_stamp - prev_timestamp
    message = CanMessage(arb_id, data, delay)
    return message, time_stamp


def parse_pythoncan_line(curr_line, prev_timestamp, force_delay):
    """
    Parses a line on python-can log format (which differs between versions)

    :param curr_line: str to parse
    :param prev_timestamp: datetime timestamp of previous message (to calculate delay)
    :param force_delay: float value to override delay or None to use calculated delay
    :return: CanMessage representing 'curr_line', datetime.datetime timestamp of 'curr_line'
    """
    line_regex = re.compile(r"Timestamp: +(?P<timestamp>\d+\.\d+) +ID: (?P<arb_id>[0-9a-fA-F]+) +"
                            r"((\d+)|(?P<is_extended>[SX]) (?P<is_error>[E ]) (?P<is_remote>[R ])) +"
                            r"DLC: +[0-8] +(?P<data>(?:[0-9a-fA-F]{2} ?){0,8}) *(Channel: (?P<channel>\w*))?")
    parsed_msg = line_regex.match(curr_line)
    arb_id = int(parsed_msg.group("arb_id"), 16)
    time_stamp = float(parsed_msg.group("timestamp"))
    data = list(int(a, 16) for a in parsed_msg.group("data").split(" ") if a)
    if prev_timestamp is None:
        delay = 0
    elif force_delay is not None:
        delay = force_delay
    else:
        delay = time_stamp - prev_timestamp
    # Parse flags
    is_extended = parsed_msg.group("is_extended") == "X"
    is_error = parsed_msg.group("is_error") == "E"
    is_remote = parsed_msg.group("is_remote") == "R"
    message = CanMessage(arb_id, data, delay, is_extended, is_error, is_remote)
    return message, time_stamp


def parse_file(filename, force_delay):
    """
    Parses a file containing CAN traffic logs.

    :param filename: Path to file
    :param force_delay: Delay value between each message
                        (if omitted, the delays specified by log file are used)
    :return: list of CanMessage instances
    """

    try:
        messages = []
        with open(filename, "r") as f:
            timestamp = None
            line_parser = None
            for line in f:
                # Skip comments and blank lines
                if line.startswith(FILE_LINE_COMMENT_PREFIX) or (not line.strip()):
                    continue
                # First non-comment line - identify log format
                if line_parser is None:
                    if line.startswith("("):
                        line_parser = parse_candump_line
                    elif line.startswith("Timestamp"):
                        line_parser = parse_pythoncan_line
                    else:
                        raise IOError("Unrecognized file type - could not parse file")
                # Parse line
                try:
                    msg, timestamp = line_parser(line, timestamp, force_delay)
                except (ValueError, AttributeError) as e:
                    raise IOError("Could not parse line:\n  '{0}'\n  Reason: {1}" \
                            .format(line.rstrip("\n"), e))
                messages.append(msg)
            return messages
    except IOError as e:
        print("ERROR: {0}\n".format(e))
        return None

class AutoFuzzer:
    """
    Fuzzer that uses the sensor to recover a relevant CAN message ID.
    """
    def __init__(self, sensors):
        self.sensors = sensors
        self.retry_count = 0

    def on_dist(self, i):
        sensor, on_val, off_val = self.sensors[i]
        val = read_light(sensor)
        off_dif = (val[0] - off_val[0], val[1] - off_val[1], val[2] - off_val[2])
        on_dif = (val[0] - on_val[0], val[1] - on_val[1], val[2] - on_val[2])
        off_dif = math.sqrt(off_dif[0]*off_dif[0] + off_dif[1]*off_dif[1] + off_dif[2]*off_dif[2])
        on_dif = math.sqrt(on_dif[0]*on_dif[0] + on_dif[1]*on_dif[1] + on_dif[2]*on_dif[2])
        return on_dif-off_dif


    def is_on(self, i):
        """ Returns wheter the sensor i detects the 'on' state """
        sensor, on_val, off_val = self.sensors[i]
        val = read_light(sensor)
        off_dif = (val[0] - off_val[0], val[1] - off_val[1], val[2] - off_val[2])
        on_dif = (val[0] - on_val[0], val[1] - on_val[1], val[2] - on_val[2])
        off_dif = math.sqrt(off_dif[0]*off_dif[0] + off_dif[1]*off_dif[1] + off_dif[2]*off_dif[2])
        on_dif = math.sqrt(on_dif[0]*on_dif[0] + on_dif[1]*on_dif[1] + on_dif[2]*on_dif[2])
        return on_dif < off_dif

    def get_state(self):
        return tuple(self.is_on(i) for i in range(len(self.sensors)))

    def wait_for_on(self, i, delay):
        """ Waits d seconds or for on signal whichever comes first """
        start = time.time()
        while time.time() - start < delay:
            if self.is_on(i):
                return True
        return False

    def wait_for_off(self, i, delay):
        """ Waits d seconds or for on signal whichever comes first """
        start = time.time()
        while time.time() - start < delay:
            if not self.is_on(i):
                return True
        return False

    def send_messages(self, messages, i, target_on=True, stop_after_signal=True):
        """
        Sends a list of messages separated by a given delay.

        :param messages: List of messages, where a message has the format (arb_id, [data_byte])
        :return True if the state has changed to on after sending any of the messages
        """
        found_signal = False

        with CanActions(notifier_enabled=False) as can_wrap:
            n = 0
            for msg in messages:
                n += 1
                print("\r  {1}/{2}: Arb_id: 0x{0:08x}" \
                        .format(msg.arb_id, n, len(messages)),
                      end='')
                sys.stdout.flush()
                can_wrap.send(msg.data, msg.arb_id, msg.is_extended, msg.is_error, msg.is_remote)
                if target_on:
                    if self.wait_for_on(i, msg.delay):
                        if stop_after_signal:
                            print("")
                            return True
                        else:
                            print(" on!", end='')
                            found_signal = True
                else:
                    if self.wait_for_off(i, msg.delay):
                        if stop_after_signal:
                            print("")
                            return True
                        else:
                            print("Turned off!", end='')
                            found_signal = True
        print("")
        return found_signal

    def identify_fuzz(self, args):
        print("Parsing messages")
        dual = args.dual
        msgs = parse_file(args.data, args.delay)
        if not msgs:
            print("No messages parsed")
            return False
        print(len(msgs), " messages parsed")
        self.fuzz_messages(msgs, dual, args.sensor)


    def fuzz_messages(self, msgs, dual, sensorI):
        """
        Performs the fuzzing using the given messages

        :return True if the message was found
        """
                # stack of messgaes
        on_stack = [msgs]
        off_stack = [msgs]
        self.retry_count = 0

        on_msg = None
        off_msg = None

        while (on_msg is None) or (dual and off_msg is None):
            if not self.is_on(sensorI):
                if on_msg is None:
                    print("Finding On message")
                    on_msg = self.fuzz_stack(on_stack, sensorI, target_on=True)
                else:
                    self.send_messages([on_msg], sensorI)
            elif dual:
                if off_msg is None:
                    print("Finding Off message")
                    off_msg = self.fuzz_stack(off_stack, sensorI, target_on=False)
                else:
                    self.send_messages([off_msg], sensorI)
            else:
                while self.is_on(sensorI):
                    time.sleep(0.01)


        print("On message:")
        print("  Arb_id: 0x{0:08x}, data: {1}" \
                    .format(on_msg.arb_id, ["{0:02x}".format(a) for a in on_msg.data]))

        if off_msg is not None:
            print("Off message:")
            print("  Arb_id: 0x{0:08x}, data: {1}" \
                        .format(off_msg.arb_id, ["{0:02x}".format(a) for a in off_msg.data]))
        return on_msg, off_msg

    def fuzz_stack(self, msgs_stack, sensorI, target_on=True):
        """ splits the first set of messages from msgs_stack
        Will replay each half and observe the sensors.
        When an activation is detected it will add that half to the stack.
        When a single message is left it is returned.

        :return The single responsible message or None
        """
        
        signal_delay = 0.5
        repeat_delay = 0.5
        def delay_func(target_on):
            if target_on:
                return self.wait_for_on(sensorI, signal_delay)
            return self.wait_for_off(sensorI, signal_delay)


        messages = msgs_stack[-1]
        if len(messages) == 1:
            print("Found message!")
            msg = messages[0]
            return msg

        mid = len(messages) // 2

        print("Sending first half")
        found = self.send_messages(messages[:mid], sensorI, target_on)

        if not found:
            found = delay_func(target_on)

        print("found" if found else "not found")
        sleep(repeat_delay)
        if found:
            self.retry_count = 0
            msgs_stack.append(messages[:mid])
            return None


        print("Sending second half")
        found2 = self.send_messages(messages[mid:], sensorI, target_on)

        if not found2:
            found2 = delay_func(target_on)

        print("found" if found2 else "not found")

        sleep(repeat_delay)
        if found2:
            self.retry_count = 0
            msgs_stack.append(messages[mid:])
            return None

        print("neither halfs")
        if self.retry_count > 5 and len(msgs_stack) > 1:
            print("going back up")
            self.retry_count = 0
            msgs_stack.pop()
        else:
            self.retry_count += 1
            print("retrying, count: ", self.retry_count)

        return None

    def brute_force(self, args):
        """ brute force fuzzing """
        msg_log = []

        def log_msg(msg):
            msg_log.append(msg)


        if args.valid_message is not None:
            message_str = args.valid_message.split('#')
            valid_id = int(message_str[0], 16)
            data_str = message_str[1]
            valid_data = [int(data_str[i:i+2], 16) for i in range(0, len(data_str), 2)]


        def verify_response(can_wrap):
            can_wrap.send(valid_data, valid_id)
            start = time.time()
            while time.time() - start < args.verify_timeout:
                if self.is_on(0):
                    print("Verify correct")
                    while self.is_on(0):
                        time.sleep(0.1)
                    return True
            print("verify false")
            return False

        delay = args.delay
        datas = args.data
        j1939 = args.j1939

        min_id = args.min
        max_id = args.max
        if min_id is None:
            if j1939:
                min_id = J1939_PROP_ID_START
            else:
                min_id = ARBITRATION_ID_MIN

        if max_id is None:
            if j1939:
                max_id = J1939_PROP_ID_END
            else:
                max_id = ARBITRATION_ID_MAX

        source_min = 0x32
        source_max = source_min
        if j1939:
            source_max = 0x32

        payloads = []
        if datas == "random":
            payloads.append(None)
        else:
            for data in datas.split(':'):
                if len(data) % 2 != 0:
                    print("data length must be even")
                    return
                if len(data) / 2 > 8:
                    print("data length must be smaller than eight")
                    return
                data_bytes = [int(data[i:i+2], 16) for i in range(0, len(data), 2)]
                payloads.append(data_bytes)

        ident_backup = int(0.5 / delay)

        messages_sent = 0
        
        ident_messages = {}

        state = self.get_state()
        print("min id: ", min_id, "max id: ", max_id)
        print("start state: ", state)
        with CanActions(notifier_enabled=False) as can_wrap:
            source = source_min
            while source <= source_max:
                arb_id = min_id
                while arb_id <= max_id:
                    for payload in payloads:
                        if payload is None:
                            length = random.randint(0, 7)
                            payload = [random.randint(0, 0xff) for _ in range(length)]
                        message = None
                        if j1939:
                            print(hex(source), ": ", hex(arb_id), " ", payload)
                            arb = ArbitrationID(pgn=arb_id, source_address=source)
                            message = can.Message(arbitration_id=arb.can_id, data=payload, extended_id=True, timestamp=time.time())
                        else:
                            message = can.Message(arbitration_id=arb_id, data=payload, extended_id=False, timestamp=time.time())
                            print(message)

                        can_wrap.bus.send(message)
                        log_msg(message)

                        start = time.time()
                        while time.time() - start < delay:
                            new_state = self.get_state()
                            if new_state != state:
                                print(" Sensor changed to: ", new_state)
                                if args.ident is not None and \
                                        (args.ident == -1 or new_state[args.ident] != state[args.ident]):
                                    print("Identifying...")
                                    sensor_index = args.ident
                                    if sensor_index == -1:
                                        sensor_index = list(map(lambda x: x[0] != x[1],
                                                                zip(state, new_state))).index(True)
                                    imsg = self.fuzz_messages(
                                        [CanMessage(msg.arbitration_id, msg.data, 0.2, msg.is_extended_id)
                                         for msg in msg_log[-ident_backup:]],
                                        args.dual, sensor_index)
                                    ident_messages[sensor_index] = imsg
                                    new_state = self.get_state()

                                state = new_state
                        if args.verify_interval is not None and messages_sent % args.verify_interval == 0:
                            if not verify_response(can_wrap):
                                print("ECU not responding")
                                return

                        messages_sent += 1
                    arb_id += 1
                    if datas == "random":
                        arb_id = random.randint(min_id, max_id)
                source += 1
        for s in ident_messages:
            on_msg, off_msg = ident_messages[s]
            on_msg = can.Message(arbitration_id=on_msg.arb_id, data=on_msg.data)
            print("sensor", s, "msg: ", on_msg)

    def log_sensor(self, args):
        delay = 0.1
        while True:
            print(self.get_state())
            sleep(delay)

    def calibrate_to_file(self, args):
        filename = args.file
        with open(filename, "w") as f:
            for _, on_val, off_val in self.sensors:
                for v in [on_val, off_val]:
                    # write R, G and B
                    f.write(str(v[0]) + " " + str(v[1]) + " " + str(v[2]))
                    f.write(":")
                f.write("\n")


    def omission_fuzz(self, args):
        arb_ids = set()

        sensorI = args.sensor

        print("Parsing messages")
        msgs = parse_file(args.data, args.delay)
        if not msgs:
            print("No messages parsed")
            return False
        for msg in msgs:
            arb_ids.add(msg.arb_id)
        print("  {0} messages parsed, {1} arbitration ids".format(len(msgs), len(arb_ids)))

        # TODO: blacklist

        for arb_id in arb_ids:
            print("Testing arb_id: 0x{0:08x}".format(arb_id))
            if self.send_messages([msg for msg in msgs if msg.arb_id != arb_id],
                                  sensorI,
                                  target_on=True,
                                  stop_after_signal=False):
                print("Signal observed, moving on")
                sleep(2)
                continue
            print("!!!! Found id: 0x{0:08x}".format(arb_id))
            return

    def mutate_fuzz(self, args):
        start_bit = args.start_bit
        end_bit = args.end_bit

        delay = args.delay
        msg_log = []

        ident_backup = int(0.5 / delay)

        message_str = args.message.split('#')
        arbitration_id = int(message_str[0], 16)
        data_str = message_str[1]
        data = [int(data_str[i:i+2], 16) for i in range(0, len(data_str), 2)]

        state = self.get_state()
        with CanActions(notifier_enabled=False) as can_wrap:
            for bit in range(start_bit, end_bit + 1):
                byte = bit // 8
                offset = bit % 8
                payload = list(data)
                payload[byte] = data[byte] ^ (1 << offset)
                message = can.Message(arbitration_id=arbitration_id, data=payload, extended_id=False)
                print(message)
                can_wrap.bus.send(message)
                msg_log.append(message)

                #sleep(delay)
                start = time.time()
                while time.time() - start < delay:
                    new_state = self.get_state()
                    if new_state != state:
                        print(" Sensor changed to: ", new_state)
                        if args.ident is not None and \
                                (args.ident == -1 or new_state[args.ident] != state[args.ident]):
                            print("Identifying...")
                            sensor_index = args.ident
                            if sensor_index == -1:
                                sensor_index = list(map(lambda x: x[0] != x[1],
                                                        zip(state, new_state))).index(True)
                            self.fuzz_messages(
                                [CanMessage(msg.arbitration_id, msg.data, 0.2, msg.is_extended_id)
                                 for msg in msg_log[-ident_backup:]],
                                args.dual, sensor_index)
                            new_state = self.get_state()

                        state = new_state



def parse_args(args):
    """
    Argument parser for the send module.

    :param args: List of arguments
    :return: Argument namespace
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(prog="cc.py autoFuzz",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="automatic fuzzer using a sensor harness for feedback",
                                     epilog="""The autoFuzz module provides a number of fuzzing methods that use an external sensor harness for feedback during fuzzing""")
    parser.add_argument("--nsensors", "-ns", help="The number of attached sensors", type=int, default=1)
    parser.add_argument("--calib-file", "-cf", type=str, default=None, help="File to load calibration from")
    subparsers = parser.add_subparsers(dest="module_function")
    subparsers.required = True

    # Parser for the identify fuzzing method
    ident_parse = subparsers.add_parser("identify")

    ident_parse.add_argument("data", metavar="filename", help="path to file")
    ident_parse.add_argument("--delay", "-d", metavar="D", type=float, default=None,
                             help="delay between messages in seconds"\
                                     "(overrides timestamps in file)")
    ident_parse.add_argument("--dual", "-2", type=bool, default=False,
                             help="Find both on and off messages")
    ident_parse.add_argument("--sensor", "-s", type=int, default=0, help="The sensor index to use")
    ident_parse.set_defaults(func=AutoFuzzer.identify_fuzz)

    # Parser for the brute force fuzzing method
    brute_parse = subparsers.add_parser("bruteforce")

    brute_parse.add_argument("data", metavar="data", help="hex encoded constant data")
    brute_parse.add_argument("--delay", "-d", metavar="D", type=float, default=0.1,
                             help="delay between messages")
    brute_parse.add_argument("--min", type=int, default=None, help="start arb id")
    brute_parse.add_argument("--max", type=int, default=None, help="end arb id")
    brute_parse.add_argument("--ident", type=int, default=None, help="The sensor to use for identification after a change")
    brute_parse.add_argument("--dual", "-2", type=bool, default=False,
                             help="Find both on and off messages")
    brute_parse.add_argument("--j1939", type=bool, default=False, help="Use j1939 pgns")
    brute_parse.add_argument("--valid-message", type=str, default=None)
    brute_parse.add_argument("--verify-interval", type=int, default=None)
    brute_parse.add_argument("--verify-timeout", type=float, default=1.0)
    brute_parse.set_defaults(func=AutoFuzzer.brute_force)

    log_parse = subparsers.add_parser("log")

    log_parse.set_defaults(func=AutoFuzzer.log_sensor)

    calibrate_parse = subparsers.add_parser("calibrate")
    calibrate_parse.add_argument("file", type=str, help="The filename of the calibration file to write to")
    calibrate_parse.set_defaults(func=AutoFuzzer.calibrate_to_file)

    omission_parse = subparsers.add_parser("omission")
    omission_parse.add_argument("data", metavar="filename", help="path to file")
    omission_parse.add_argument("--delay", "-d", metavar="D", type=float, default=None,
                             help="delay between messages")
    omission_parse.add_argument("--sensor", "-s", type=int, default=0, help="The number of the sensor to use")
    omission_parse.set_defaults(func=AutoFuzzer.omission_fuzz)

    mutation_parse = subparsers.add_parser("mutate")
    mutation_parse.add_argument("--start-bit", type=int, default=0,
                                help="start bit to mutate")
    mutation_parse.add_argument("--end-bit", type=int, default=63, 
                                help="last bit to mutate")
    mutation_parse.add_argument("--delay", "-d", type=float, default=0.01, 
                                help="delay between messages")
    mutation_parse.add_argument("--dual", "-2", type=bool, default=False,
                             help="Find both on and off messages")
    mutation_parse.add_argument("--ident", type=int, default=None, help="The sensor to use for identification after a change")
    mutation_parse.add_argument("message", type=str, help="the message to mutate")
    mutation_parse.set_defaults(func=AutoFuzzer.mutate_fuzz)


    args = parser.parse_args(args)
    return args


def module_main(args):
    """
    autoFuzz module main wrapper.

    :param args: List of module arguments
    """
    args = parse_args(args)

    calibration = None
    if args.calib_file is not None:
        calibration = []
        with open(args.calib_file, "r") as f:
            for line in f:
                vals = line.split(":")
                on_val_s = vals[0]
                off_val_s = vals[1]
                on_val = tuple(float(x) for x in on_val_s.split())
                off_val = tuple(float(x) for x in off_val_s.split())
                calibration.append((on_val, off_val))
        if args.nsensors > len(calibration):
            print("Error: too much sensors for the calibration file")
            return

    sensors = []

    i2c_port = None
    gpio_port = None

    for i in range(args.nsensors):
        sensor = None
        on_val = None
        off_val = None

        print("initializing sensor")
        mux = None
        if i == 0:
            mux = Mux(ISL_I2C_ADDR, 0)
            i2c_port = mux.mux_i2c
            gpio_port = mux.gpio
        else:
            mux = Mux(ISL_I2C_ADDR, i, i2c_port, gpio_port)

        sensor = RgbSensor(mux)

        if not sensor.init():
            print("Error initializing sensor")
            return
        if calibration is not None:
            on_val, off_val = calibration[i]
        else:
            print("calibrating sensor ", i)
            input("press enter when control is OFF")
            off_val = read_light(sensor)
            input("press enter when control is ON")
            on_val = read_light(sensor)

        print("on val: {0}\noff val: {1}".format(on_val, off_val))
        sensors.append((sensor, on_val, off_val))

    input("Press enter to start")

    fuzzer = AutoFuzzer(sensors)

    start = time.time()
    args.func(fuzzer, args)

    print("Fuzzing took", time.time() - start, " seconds")
