#!/usr/bin/python2

from Mux import Mux
from RgbSensor import RgbSensor, ISL_I2C_ADDR

import pygame
from pygame.locals import *
import math

def main():
    
    mux1 = Mux(ISL_I2C_ADDR, 0)
    sensor1 = RgbSensor(mux1)

    if not sensor1.init():
        print("Error init color sensor")
        return

    # Initialise screen
    pygame.init()
    screen = pygame.display.set_mode((150, 50))
    pygame.display.set_caption('Basic Pygame program')

    # Fill background
    background = pygame.Surface(screen.get_size())
    background = background.convert()
    background.fill((250, 250, 250))

    # Display some text
    font = pygame.font.Font(None, 36)
    text = font.render("Hello There", 1, (10, 10, 10))
    textpos = text.get_rect()
    textpos.centerx = background.get_rect().centerx
    background.blit(text, textpos)

    # Blit everything to the screen
    screen.blit(background, (0, 0))
    pygame.display.flip()

    max_c = 0

    # Event loop
    while 1:
        for event in pygame.event.get():
            if event.type == QUIT:
                return

        color = sensor1.readColor()
        size = color[0]+color[1]+color[2]#math.sqrt(color[0]*color[0] + color[1]*color[1] + color[2]*color[2])
        #max_c = size
        if size > max_c:
            max_c = size

        color = (color[0] / max_c * 256, color[1] / max_c * 256, color[2] / max_c * 256)
        background.fill(color)
        screen.blit(background, (0, 0))
        pygame.display.flip()


if __name__ == '__main__':
    main()
