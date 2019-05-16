from lib.can_actions import CanActions, int_from_str_base, str_to_int_list
from time import sleep
from sys import exit
import argparse
import re
import time


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

def lo8(x):
    return int(x) & 0xFF

def hi8(x):
    return (int(x) >> 8) & 0xFF

def can_send(can, addr, a=0, b=0, c=0, d=0, e=0, f=0, g=0, h=0):
    extended = addr >= 0x800
    can.send([a, b, c, d, e, f, g, h], addr, extended, False, False)

BAT_WARNING = True
TURN_LIGHTS = 0x3

TRUNK_OPEN = False
DOOR_OPEN = False

BACKLIGHT = False

CHECK_LAMP = False
CLUTCH_CONTROL = True

KEYBAT = True

LIGHT_HIGH = False
LIGHT_FOG = False

PREHEAT = True
WATER_TEMP = False
DPF_WARN = True

ABS = True
OFF_ROAD = True
HANDBRAKE = True
TIRE_PRESSURE = True

SEATBELT = False

SPEED = 130 # mph
RPM = 1000
DISTANCE = 0


def send_messages():
    with CanActions(notifier_enabled=False) as can_wrap:
        counter = 0

        distance_cL = lo8(DISTANCE)
        distance_cH = hi8(DISTANCE)

        bat_warning = 0b10000000 if BAT_WARNING else 0
        turn_lights = TURN_LIGHTS
        trunk = 0b00100000 if TRUNK_OPEN else 0
        door = 1 if DOOR_OPEN else 0
        backlight = 1 if BACKLIGHT else 0
        check_lamp = 0b00010000 if CHECK_LAMP else 0
        clutch_control = 1 if CLUTCH_CONTROL else 0
        keybat_warn = 0b10000000 if KEYBAT else 0

        high_beam = 0b01000000 if LIGHT_HIGH else 0
        fog_light = 0b00100000 if LIGHT_FOG else 0
        light_mode = high_beam | fog_light

        engine_control = (0b10 if PREHEAT else 0) | (0b10000 if WATER_TEMP else 0)
        dpf_warning = 0b10 if DPF_WARN else 0

        drive_mode = (0b0001 if ABS else 0) \
                   | (0b0010 if OFF_ROAD else 0) \
                   | (0b0100 if HANDBRAKE else 0) \
                   | (0b1000 if TIRE_PRESSURE else 0)

        seat_belt = 0b0100 if SEATBELT else 0

        speed = SPEED
        rpm = RPM
        while True:
            #speed += 0.01
            speedL = lo8(speed * 225)
            speedH = hi8(speed * 225)

            rpmL = lo8(rpm * 4)
            rpmH = hi8(rpm * 4)


            # immobilizer:
            can_send(can_wrap, 0x3D0, 0, 0x80)
            # engine on and esp disabled:
            can_send(can_wrap, 0xDA0, 0x01, 0x80)

            # Cruise control:
            # can_send(can_wrap, 0x289, 0, 0x1)
            counter += 1
            if counter == 20:
                counter = 0
                

                #rpm += 100

                #print("RPM: ", rpm, " SPEED: ", speed)

                turn_lights = 2 if turn_lights == 3 else 3

                # lights:
                can_send(can_wrap, 0x470,
                        bat_warning | turn_lights,
                        trunk | door, backlight, 0,
                        check_lamp | clutch_control,
                        keybat_warn, 0,
                        light_mode)
                # diesel engine:
                #can_send(can_wrap, 0x480, 0, engine_control, 0, 0, 0, dpf_warning)

            # motor speed
            #can_send(can_wrap, 0x320, 0, (speedL * 100) & 0xFF, (speedH * 100) & 0xFF)
            # RPM
            can_send(can_wrap, 0x280, 0x49, 0x0E, rpmL, rpmH, 0x0E, 0, 0x1B, 0x0E)

            # speed
            can_send(can_wrap, 0x5A0, 0xFF,
                    speedL, speedH,
                    drive_mode, 00,
                    distance_cL, distance_cH, 0xAD)

            # ABS / speed!
            can_send(can_wrap, 0x1A0, 0x18, speedL, speedH, 0, 0xFE, 0xFE, 0, 0xFF)

            # airbag
            can_send(can_wrap, 0x050, 0, 0x80, seat_belt)

            time.sleep(0.020)


def parse_args(args):
    """
    Argument parser for the send module.

    :param args: List of arguments
    :return: Argument namespace
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(prog="cc.py dashboard",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="Example dashboard control",
                                     epilog="""Example usage:""")
    args = parser.parse_args(args)
    return args


def module_main(args):
    """
    Send module main wrapper.

    :param args: List of module arguments
    """
    args = parse_args(args)
    send_messages()
