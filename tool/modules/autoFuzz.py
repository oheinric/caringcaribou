from lib.can_actions import CanActions, int_from_str_base, str_to_int_list
from time import sleep
from sys import exit
import argparse
import re
import time

from i2clight.Mux import Mux
from i2clight.RgbSensor import RgbSensor, ISL_I2C_ADDR

try:
    input = raw_input
except NameError:
    pass

def read_light(sensor):
    t = sensor.readColor()
    return t[1]

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

    def is_on(self):
        """ Returns wheter the sensor detects the 'on' state """
        val = read_light(self.sensor)
        off_dif = abs(val - self.off_val)
        on_dif = abs(val - self.on_val)
        return on_dif < off_dif

    def wait_for_on(self, d):
        """ Waits d seconds or for on signal whichever comes first """
        start = time.time()
        while time.time() - start < d:
            if self.is_on():
                return True
        return False

    def send_messages(self, messages):
        """
        Sends a list of messages separated by a given delay.

        :param messages: List of messages, where a message has the format (arb_id, [data_byte])
        :return True if the state has changed to on after sending any of the messages
        """
        with CanActions(notifier_enabled=False) as can_wrap:
            for msg in messages:
                print("  Arb_id: 0x{0:08x}, data: {1}" \
                        .format(msg.arb_id, ["{0:02x}".format(a) for a in msg.data]))
                can_wrap.send(msg.data, msg.arb_id, msg.is_extended, msg.is_error, msg.is_remote)
                if self.wait_for_on(msg.delay*2):
                    return True
        print("No ON signal detected")
        return False


    def fuzz_messages(self, messages):
        """
        Performs the fuzzing using the given messages

        :return True if the message was found
        """
        if len(messages) == 1:
            # TODO: verify message (but wait for response when delay is low)
            # may also occur in last send stuff
            print("Found message:")
            msg = messages[0]
            print("  Arb_id: 0x{0:08x}, data: {1}" \
                    .format(msg.arb_id, ["{0:02x}".format(a) for a in msg.data]))
            return True

        while True:
            mid = len(messages) // 2
            print("Sending first half")
            sleep(5)
            found = self.send_messages(messages[:mid])
            if not found:
                found = found or self.wait_for_on(2)
            #found = input("Found [Y/n]")
            print("done")
            print("Sending second half")
            sleep(5)
            found2 = self.send_messages(messages[mid:])
            if not found2:
                found2 = found2 or self.wait_for_on(2)
            #
            print("done")
            #found2 = input("Found [Y/n]")
            if (not found) and (not found2):
                # not found -> retry one level up, which was found
                print("not found")
                sleep(5)
                return False
            if found and (not found2):
                print("found in first half")
                if self.fuzz_messages(messages[:mid]):
                    return True
            elif (not found) and found2:
                print("found in second half")
                if self.fuzz_messages(messages[mid:]):
                    return True
            else:
                print("found in both halfs")
                if self.fuzz_messages(messages[mid:]):
                    return True
                if self.fuzz_messages(messages[:mid]):
                    return True


def parse_args(args):
    """
    Argument parser for the send module.

    :param args: List of arguments
    :return: Argument namespace
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(prog="cc.py autoFuzz",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=
                                     "Raw message transmission module for CaringCaribou.\n"
                                     "Messages can be passed as command line arguments or "
                                     "through a file.",
                                     epilog="""Example usage:
  cc.py autoFuzz can_dump.txt
  cc.py autoFuzz -d 0.2 can_dump.txt""")

   # Parser for sending messages from file
    parser.add_argument("data", metavar="filename", help="path to file")
    parser.add_argument("--delay", "-d", metavar="D", type=float, default=None,
                        help="delay between messages in seconds (overrides timestamps in file)")
    parser.set_defaults(func=parse_file)

    args = parser.parse_args(args)
    return args


def module_main(args):
    """
    autoFuzz module main wrapper.

    :param args: List of module arguments
    """
    args = parse_args(args)
    print("Parsing messages")
    messages = args.func(args.data, args.delay)
    if not messages:
        print("No messages parsed")
    else:
        print("  {0} messages parsed".format(len(messages)))
        print("init sensor")

        sensor = None
        on_val = None
        off_val = None

        mux = Mux(ISL_I2C_ADDR, 0)
        sensor = RgbSensor(mux)

        print("calibrating...")
        input("press enter when control is OFF")
        off_val = read_light(sensor)
        input("press enter when control is ON")
        on_val = read_light(sensor)

        print("on val: {0}, off val: {1}".format(on_val, off_val))
        input("Press enter to start")

        # while True:
        #     val = read_light(sensor)
        #     don = abs(on_val - val)
        #     doff = abs(off_val - val)
        #     if don > doff:
        #         print("OFF")
        #     else:
        #         print("ON")

        print("Sending messages")
        fuzzer = AutoFuzzer(sensor, off_val, on_val)
        fuzzer.fuzz_messages(messages)
