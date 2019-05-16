from __future__ import print_function

from lib.can_actions import CanActions, ARBITRATION_ID_MAX, ARBITRATION_ID_MIN

from time import sleep
from sys import exit
import argparse
import re
import time
import sys
import math


from i2clight.Mux import Mux
from i2clight.RgbSensor import RgbSensor, ISL_I2C_ADDR

from j1939 import ArbitrationID

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
    def __init__(self, sensor, off_val, on_val):
        self.sensor = sensor
        self.on_val = on_val
        self.off_val = off_val
        tmp = (off_val[0] - on_val[0], off_val[1] - on_val[1], off_val[2] - on_val[2])
        self.off_dist = math.sqrt(tmp[0]*tmp[0]+tmp[1]*tmp[1]+tmp[2]*tmp[2])
        self.retry_count = 0

    def on_dist(self):
        val = read_light(self.sensor)
        off_dif = (val[0] - self.off_val[0], val[1] - self.off_val[1], val[2] - self.off_val[2])
        on_dif = (val[0] - self.on_val[0], val[1] - self.on_val[1], val[2] - self.on_val[2])
        off_dif = math.sqrt(off_dif[0]*off_dif[0] + off_dif[1]*off_dif[1] + off_dif[2]*off_dif[2])
        on_dif = math.sqrt(on_dif[0]*on_dif[0] + on_dif[1]*on_dif[1] + on_dif[2]*on_dif[2])
        return on_dif-off_dif


    def is_on(self):
        """ Returns wheter the sensor detects the 'on' state """
        val = read_light(self.sensor)
        off_dif = (val[0] - self.off_val[0], val[1] - self.off_val[1], val[2] - self.off_val[2])
        on_dif = (val[0] - self.on_val[0], val[1] - self.on_val[1], val[2] - self.on_val[2])
        off_dif = math.sqrt(off_dif[0]*off_dif[0] + off_dif[1]*off_dif[1] + off_dif[2]*off_dif[2])
        on_dif = math.sqrt(on_dif[0]*on_dif[0] + on_dif[1]*on_dif[1] + on_dif[2]*on_dif[2])
        return on_dif < off_dif

    def wait_for_on(self, d):
        """ Waits d seconds or for on signal whichever comes first """
        start = time.time()
        while time.time() - start < d:
            if self.is_on():
                return True
        return False

    def wait_for_off(self, d):
        """ Waits d seconds or for on signal whichever comes first """
        start = time.time()
        while time.time() - start < d:
            if not self.is_on():
                return True
        return False

    def send_messages(self, messages, target_on=True, stop_after_signal=True):
        """
        Sends a list of messages separated by a given delay.

        :param messages: List of messages, where a message has the format (arb_id, [data_byte])
        :return True if the state has changed to on after sending any of the messages
        """
        found_signal = False

        with CanActions(notifier_enabled=False) as can_wrap:
            for msg in messages:
                print("\r  Arb_id: 0x{0:08x}" \
                        .format(msg.arb_id),
                      end='')
                sys.stdout.flush()
                can_wrap.send(msg.data, msg.arb_id, msg.is_extended, msg.is_error, msg.is_remote)
                if target_on:
                    if self.wait_for_on(msg.delay):
                        if stop_after_signal:
                            print("")
                            return True
                        else:
                            found_signal = True
                else:
                    if self.wait_for_off(msg.delay):
                        if stop_after_signal:
                            print("")
                            return True
                        else:
                            found_signal = True
        print("")
        return found_signal

    def fuzz_method(self, args):
        print("Parsing messages")
        dual = args.dual
        msgs = parse_file(args.data, args.delay)
        if not msgs:
            print("No messages parsed")
            return False
        print("  {0} messages parsed".format(len(msgs)))
        start = time.time()
        self.fuzz_messages(msgs, dual) 
        end = time.time()
        print("Fuzzing took {0} seconds".format(end - start))


    def fuzz_messages(self, msgs, dual):
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
            if not self.is_on():
                print("!!!!! A")
                if on_msg is None:
                    print("Finding On message")
                    on_msg = self.fuzz_stack(on_stack, target_on=True)
                else:
                    self.send_messages([on_msg])
            elif dual:
                print("!!!!! B")
                if off_msg is None:
                    print("Finding Off message")
                    off_msg = self.fuzz_stack(off_stack, target_on=False)
                else:
                    self.send_messages([off_msg])
            else:
                print("!!!!! C")
                while self.is_on():
                    time.sleep(0.01)


        print("On message:")
        print("  Arb_id: 0x{0:08x}, data: {1}" \
                    .format(on_msg.arb_id, ["{0:02x}".format(a) for a in on_msg.data]))

        if off_msg is not None:
            print("Off message:")
            print("  Arb_id: 0x{0:08x}, data: {1}" \
                        .format(off_msg.arb_id, ["{0:02x}".format(a) for a in off_msg.data]))

    def fuzz_stack(self, msgs_stack, target_on=True):
        """ sends half the stack recursivly TODO: better doc """

        signal_delay = 0.25

        messages = msgs_stack[-1]
        if len(messages) == 1:
            # TODO: verify message (but wait for response when delay is low)
            # may also occur in last send stuff
            print("Found message!")
            msg = messages[0]
            return msg

        mid = len(messages) // 2

        print("Sending first half")
        found = self.send_messages(messages[:mid], target_on)

        if not found:
            found = found or (self.wait_for_on(signal_delay) if target_on else self.wait_for_off(signal_delay))

        print("found" if found else "not found")
        sleep(0.5)
        if found:
            self.retry_count = 0
            msgs_stack.append(messages[:mid])
            return None


        print("Sending second half")
        found2 = self.send_messages(messages[mid:], target_on)

        if not found2:
            found2 = found2 or (self.wait_for_on(signal_delay) if target_on else self.wait_for_off(signal_delay))
        print("found" if found2 else "not found")

        sleep(0.5)
        if found2:
            self.retry_count = 0
            msgs_stack.append(messages[mid:])
            return None

        print("neither halfs")
        if self.retry_count > 5:
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

        delay = args.delay
        data = args.data
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


        if len(data) % 2 != 0:
            print("data length must be even")
            return
        if len(data) / 2 > 8:
            print("data length must be smaller than eight")
            return
        data_bytes = [int(data[i:i+2], 16) for i in range(0, len(data), 2)]

        state = self.is_on()
        print("min id: ", min_id, "max id: ", max_id)
        print("start state: ", state)
        with CanActions(notifier_enabled=False) as can_wrap:
            source = source_min
            while source <= source_max:
                arb_id = min_id
                while arb_id < max_id:
                    print(hex(source), ": ", hex(arb_id))
                    if j1939:
                        arb = ArbitrationID(pgn=arb_id, source_address=source)
                        can_wrap.send(data_bytes, arb.can_id, is_extended=True)
                    else:
                        can_wrap.send(data_bytes, arb_id)

                    start = time.time()
                    while time.time() - start < delay:
                        new_state = self.is_on()
                        if new_state != state:
                            state = new_state
                            print(" Sensor changed to: ", state)
                            if args.ident:
                                print("Identifying...")
                                self.fuzz_messages(
                                    [CanMessage(i, data_bytes, delay)
                                     for i in range(arb_id - int(0.5 / delay), arb_id + 1)],
                                    True)
                            break
                    arb_id += 1
                source += 1

    def log_sensor(self, args):
        delay = 0.1
        while True:
            if self.is_on():
                print("ON ", self.on_dist())
            else:
                print("OFF ", self.on_dist())
            sleep(delay)

    def absence_fuzz(self, args):
        arb_ids = set()

        print("Parsing messages")
        msgs = parse_file(args.data, args.delay)
        if not msgs:
            print("No messages parsed")
            return False
        for msg in msgs:
            arb_ids.add(msg.arb_id)
        print("  {0} messages parsed, {1} arbitration ids".format(len(msgs), len(arb_ids)))

        # TODO: blacklist
        #arb_ids.remove(0x18ef1727)

        for arb_id in arb_ids:
            target = not self.is_on()
            print("Testing arb_id: 0x{0:08x}".format(arb_id))
            if self.send_messages([msg for msg in msgs if msg.arb_id != arb_id],
                                  target_on=target,
                                  stop_after_signal=False):
                print("Signal observed, moving on")
                #sleep(0.5)
                continue
            print("!!!! Found id: 0x{0:08x}".format(arb_id))
            #sleep(0.5)


            

def parse_args(args):
    """
    Argument parser for the send module.

    :param args: List of arguments
    :return: Argument namespace
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(prog="cc.py autoFuzz",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="TODO",
                                     epilog="""TODO""")
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
    ident_parse.set_defaults(func=AutoFuzzer.fuzz_method)

    # Parser for the brute force fuzzing method
    brute_parse = subparsers.add_parser("bruteforce")

    brute_parse.add_argument("data", metavar="data", help="hex encoded constant data")
    brute_parse.add_argument("--delay", "-d", metavar="D", type=float, default=None,
                             help="delay between messages")
    brute_parse.add_argument("--min", type=int, default=None, help="start arb id")
    brute_parse.add_argument("--max", type=int, default=None, help="end arb id")
    brute_parse.add_argument("--ident", type=bool, default=False, help="identify when message changes")
    brute_parse.add_argument("--j1939", type=bool, default=False, help="Use j1939 pgns")
    brute_parse.set_defaults(func=AutoFuzzer.brute_force)

    log_parse = subparsers.add_parser("log")

    log_parse.set_defaults(func=AutoFuzzer.log_sensor)

    absence_parse = subparsers.add_parser("absence")
    absence_parse.add_argument("data", metavar="filename", help="path to file")
    absence_parse.add_argument("--delay", "-d", metavar="D", type=float, default=None,
                             help="delay between messages")
    absence_parse.set_defaults(func=AutoFuzzer.absence_fuzz)


    args = parser.parse_args(args)
    return args


def module_main(args):
    """
    autoFuzz module main wrapper.

    :param args: List of module arguments
    """
    args = parse_args(args)


    sensor = None
    on_val = None
    off_val = None

    print("initializing sensor")

    mux = Mux(ISL_I2C_ADDR, 0)
    sensor = RgbSensor(mux)

    if not sensor.init():
        print("Error initializing sensor")
        return

    print("calibrating...")
    input("press enter when control is OFF")
    off_val = read_light(sensor)
    input("press enter when control is ON")
    on_val = read_light(sensor)

    print("on val: {0}\noff val: {1}".format(on_val, off_val))
    input("Press enter to start")


    print("Sending messages")
    fuzzer = AutoFuzzer(sensor, off_val, on_val)
    args.func(fuzzer, args)
