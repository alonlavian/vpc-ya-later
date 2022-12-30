# ###################################################################################
# Script/module: modules\colorprint.py
# Author: Richard Knechtel
# Date: 08/18/2022
# Description: This is a module of functions for printing in color.
# Python Version: 3.8.x
#
#
# LICENSE: 
# This script is in the public domain, free from copyrights or restrictions.
# Ref:
# https://github.com/rknechtel/Scripts/blob/master/Python/ProjectTemplate/modules/colorprint.py
#
# Click Ref:
# https://click.palletsprojects.com/en/8.1.x/utils/
#
# ANSI Codes Ref:
# https://en.wikipedia.org/wiki/ANSI_escape_code
#
# ###################################################################################

# -----------------------------------------------------------------------------------
# Example Usages:
#
# from modules import colorprint as cp
#
# cp.print_fg_green("My Green text")
#
# cp.print_bg_blue("My Blue background")
#
# # cp.print_fg_bg("My Colorized text with foreground and background color.", COLOR_BLUE, COLOR_RED)
#
# print(cp.turn_fg_red("My Red Text") cp.turn_fg_green("My Green Text"))
#
# -----------------------------------------------------------------------------------


#---------------------------------------------------------[Imports]------------------------------------------------------

import click

#---------------------------------------------------[Colorization Initialisations]-------------------------------------------------------

# Console Text Colors:

# -------------------------------------------------------------------
# Constants: For use with function print_fg_bg()

COLOR_BLACK = "black"
COLOR_RED = "red"
COLOR_GREEN = "green"
COLOR_YELLOW = "yellow"
COLOR_BLUE = "blue"
COLOR_MAGENTA = "magenta"
COLOR_CYAN = "cyan"
COLOR_WHITE = "white"
COLOR_BRIGHT_BLACK = "bright_black"
COLOR_BRIGHT_RED = "bright_red"
COLOR_BRIGHT_GREEN = "bright_green"
COLOR_BRIGHT_YELLOW = "bright_yellow"
COLOR_BRIGHT_BLUE = "bright_blue"
COLOR_BRIGHT_MAGENTA = "bright_magenta"
COLOR_BRIGHT_CYAN = "bright_cyan"
COLOR_BRIGHT_WHITE = "bright_white"

# -------------------------------------------------------------------
# ANSI Color Codes for use with Functions turn_fg_* and turn_bg_*

# Foreground Colors
FG_BLACK = '\033[30m'
FG_RED = '\033[31m'
FG_GREEN = '\033[32m'
FG_YELLOW = '\033[33m'
FG_BLUE = '\033[34m'
FG_MAGENTA = '\033[35m'
FG_CYAN = '\033[36m'
FG_WHITE = '\033[37m'

FG_LIGHT_GREY = '\033[90m'
FG_LIGHT_RED = '\033[91m'
FG_LIGHT_GREEN = '\033[92m'
FG_LIGHT_YELLOW = '\033[93m'
FG_LIGHT_BLUE = '\033[94m'
FG_LIGHT_MAGENTA = '\033[95m'
FG_LIGHT_CYAN = '\033[96m'
FG_LIGHT_WHITE = '\033[97m'


# Background Colors
BG_BLACK = '\033[40m'
BG_RED = '\033[41m'
BG_GREEN = '\033[42m'
BG_YELLOW = '\033[43m'
BG_BLUE = '\033[44m'
BG_MAGENTA = '\033[45m'
BG_CYAN = '\033[46m'
BG_WHITE = '\033[47m'

BG_LIGHT_GREY = '\033[100m'
BG_LIGHT_RED = '\033[101m'
BG_LIGHT_GREEN = '\033[102m'
BG_LIGHT_YELLOW = '\033[103m'
BG_LIGHT_BLUE = '\033[104m'
BG_LIGHT_MAGENTA = '\033[105m'
BG_LIGHT_CYAN = '\033[106m'
BG_LIGHT_WHITE = '\033[107m'

# -------------------------------------------------------------------
# Special ANSI Codes:

ENDC = '\033[0m'
RESET = '\033[39m'

#-----------------------------------------------------------[Functions]------------------------------------------------------------

# -----------------------------------------------------------------------------------
# Special Formatting and Styles
# -----------------------------------------------------------------------------------

# ###################################################################################
# Function: print_reset
def print_reset(message, nl=True):
    click.echo(click.style(str(message), reset=True), nl=nl)

# ###################################################################################
# Function: print_blink
def print_blink(message, nl=True):
    click.echo(click.style(str(message), blink=True), nl=nl)

# ###################################################################################
# Function: print_reverse
def print_reverse(message, nl=True):
    click.echo(click.style(str(message), reverse=True), nl=nl)

# ###################################################################################
# Function: print_bold
def print_bold(message, nl=True):
    click.echo(click.style(str(message), bold=True), nl=nl)

# ###################################################################################
# Function: print_dim
def print_dim(message, nl=True):
    click.echo(click.style(str(message), dim=True), nl=nl)

# ###################################################################################
# Function: print_underline
def print_underline(message, nl=True):
    click.echo(click.style(str(message), underline=True), nl=nl)

# ###################################################################################
# Function: print_italic
def print_italic(message, nl=True):
    click.echo(click.style(str(message), italic=True), nl=nl)

# ###################################################################################
# Function: print_strikethrough
def print_strikethrough(message, nl=True):
    click.echo(click.style(str(message), strikethrough=True), nl=nl)


# -----------------------------------------------------------------------------------
# Coloring:
# -----------------------------------------------------------------------------------

# -----------------------------------------------------------------------------------
# Forground Coloring:

# ###################################################################################
# Function: print_fg_black
def print_fg_black(message, nl=True):
    click.echo(click.style(str(message), fg='black'), nl=nl)
	
# ###################################################################################
# Function: print_fg_red
def print_fg_red(message, nl=True):
    click.echo(click.style(str(message), fg='red'), nl=nl)

# ###################################################################################
# Function: print_fg_green
def print_fg_green(message, nl=True):
    click.echo(click.style(str(message), fg='green'), nl=nl)

# ###################################################################################
# Function: print_fg_yellow
def print_fg_yellow(message, nl=True):
    click.echo(click.style(str(message), fg='yellow'), nl=nl)

# ###################################################################################
# Function: print_fg_blue
def print_fg_blue(message, nl=True):
    click.echo(click.style(str(message), fg='blue'), nl=nl)

# ###################################################################################
# Function: print_fg_magenta
def print_fg_magenta(message, nl=True):
    click.echo(click.style(str(message), fg='magenta'), nl=nl)

# ###################################################################################
# Function: print_fg_cyan
def print_fg_cyan(message, nl=True):
    click.echo(click.style(str(message), fg='cyan'), nl=nl)

# ###################################################################################
# Function: print_fg_white
def print_fg_white(message, nl=True):
    click.echo(click.style(str(message), fg='white'), nl=nl)

# ###################################################################################
# Function: print_fg_grey
def print_fg_grey(message, nl=True):
    click.echo(click.style(str(message), fg='bright_black'), nl=nl)
    
# ###################################################################################
# Function: print_fg_bright_red
def print_fg_bright_red(message, nl=True):
    click.echo(click.style(str(message), fg='bright_red'), nl=nl)

# ###################################################################################
# Function: print_fg_bright_green
def print_fg_bright_green(message, nl=True):
    click.echo(click.style(str(message), fg='bright_green'), nl=nl)

# ###################################################################################
# Function: print_fg_bright_yellow
def print_fg_bright_yellow(message, nl=True):
    click.echo(click.style(str(message), fg='bright_yellow'), nl=nl)

# ###################################################################################
# Function: print_fg_bright_blue
def print_fg_bright_blue(message, nl=True):
    click.echo(click.style(str(message), fg='bright_blue'), nl=nl)

# ###################################################################################
# Function: print_fg_bright_magenta
def print_fg_bright_magenta(message, nl=True):
    click.echo(click.style(str(message), fg='bright_magenta'), nl=nl)

# ###################################################################################
# Function: print_fg_bright_cyan
def print_fg_bright_cyan(message, nl=True):
    click.echo(click.style(str(message), fg='bright_cyan'), nl=nl)

# ###################################################################################
# Function: print_fg_bright_white
def print_fg_bright_white(message, nl=True):
    click.echo(click.style(str(message), fg='bright_white'), nl=nl)

# -----------------------------------------------------------------------------------
# Background Coloring:

# ###################################################################################
# Function: print_bg_black
def print_bg_black(message, nl=True):
    click.echo(click.style(str(message), bg='black'), nl=nl)
	
# ###################################################################################
# Function: print_bg_red
def print_bg_red(message, nl=True):
    click.echo(click.style(str(message), bg='red'), nl=nl)

# ###################################################################################
# Function: print_bg_green
def print_bg_green(message, nl=True):
    click.echo(click.style(str(message), bg='green'), nl=nl)

# ###################################################################################
# Function: print_bg_yellow
def print_bg_yellow(message, nl=True):
    click.echo(click.style(str(message), bg='yellow'), nl=nl)

# ###################################################################################
# Function: print_bg_blue
def print_bg_blue(message, nl=True):
    click.echo(click.style(str(message), bg='blue'), nl=nl)

# ###################################################################################
# Function: print_bg_magenta
def print_bg_magenta(message, nl=True):
    click.echo(click.style(str(message), bg='magenta'), nl=nl)

# ###################################################################################
# Function: print_bg_cyan
def print_bg_cyan(message, nl=True):
    click.echo(click.style(str(message), bg='cyan'), nl=nl)

# ###################################################################################
# Function: print_bg_white
def print_bg_white(message, nl=True):
    click.echo(click.style(str(message), bg='white'), nl=nl)

# ###################################################################################
# Function: print_bg_grey
def print_bg_grey(message, nl=True):
    click.echo(click.style(str(message), bg='bright_black'), nl=nl)
    
# ###################################################################################
# Function: print_bg_bright_red
def print_bg_bright_red(message, nl=True):
    click.echo(click.style(str(message), bg='bright_red'), nl=nl)

# ###################################################################################
# Function: print_bg_bright_green
def print_bg_bright_green(message, nl=True):
    click.echo(click.style(str(message), bg='bright_green'), nl=nl)

# ###################################################################################
# Function: print_bg_bright_yellow
def print_bg_bright_yellow(message, nl=True):
    click.echo(click.style(str(message), bg='bright_yellow'), nl=nl)

# ###################################################################################
# Function: print_bg_bright_blue
def print_bg_bright_blue(message, nl=True):
    click.echo(click.style(str(message), bg='bright_blue'), nl=nl)

# ###################################################################################
# Function: print_bg_bright_magenta
def print_bg_bright_magenta(message, nl=True):
    click.echo(click.style(str(message), bg='bright_magenta'), nl=nl)

# ###################################################################################
# Function: print_bg_bright_cyan
def print_bg_bright_cyan(message, nl=True):
    click.echo(click.style(str(message), bg='bright_cyan'), nl=nl)

# ###################################################################################
# Function: print_bg_bright_white
def print_bg_bright_white(message, nl=True):
    click.echo(click.style(str(message), bg='bright_white'), nl=nl)  



# ###################################################################################
# Function: print_fg_bg
def print_fg_bg(message, foreground, background, nl=True):
  """
  Function: print_fg_bg
  Description: Print Text with a Background and Foreground Colors
  Parameters: Message/text to Print
              Foreground Color (Example: COLOR_BLUE)
              Background Color (Example: COLOR_RED)
  Returns: None
  Example Usage: print_fg_bg("Print This Text", COLOR_BLUE, COLOR_RED)
  """
  click.echo(click.style(str(message), bg=f'{background}', fg=f'{foreground}'), nl=nl)
  

#------------------------------------------------------------------------------------
# Turn on Text Color Functions

# Foreground Colors:

# ###################################################################################
# Function: turn_fg_black
def turn_fg_black(texttocolor):
    return FG_BLACK + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_red
def turn_fg_red(texttocolor):
    return FG_RED + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_green
def turn_fg_green(texttocolor):
    return FG_GREEN + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_yellow
def turn_fg_yellow(texttocolor):
    return FG_YELLOW + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_blue
def turn_fg_blue(texttocolor):
    return FG_BLUE + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_magenta
def turn_fg_magenta(texttocolor):
    return FG_MAGENTA + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_cyan
def turn_fg_cyan(texttocolor):
    return FG_CYAN + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_white
def turn_fg_white(texttocolor):
    return FG_WHITE + texttocolor + ENDC


# ###################################################################################
# Function: turn_fg_light_grey
def turn_fg_light_grey(texttocolor):
    return FG_LIGHT_GREY + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_light_red
def turn_fg_light_red(texttocolor):
    return FG_LIGHT_RED + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_light_green
def turn_fg_light_green(texttocolor):
    return FG_LIGHT_GREEN + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_light_yellow
def turn_fg_light_yellow(texttocolor):
    return FG_LIGHT_YELLOW + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_light_blue
def turn_fg_light_blue(texttocolor):
    return FG_LIGHT_BLUE + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_light_magenta
def turn_fg_light_magenta(texttocolor):
    return FG_LIGHT_MAGENTA + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_light_cyan
def turn_fg_light_cyan(texttocolor):
    return FG_LIGHT_CYAN + texttocolor + ENDC

# ###################################################################################
# Function: turn_fg_light_white
def turn_fg_white(texttocolor):
    return FG_LIGHT_WHITE + texttocolor + ENDC


# Background Colors:

# ###################################################################################
# Function: turn_bg_black
def turn_bg_black(texttocolor):
    return BG_BLACK + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_red
def turn_bg_red(texttocolor):
    return BG_RED + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_green
def turn_bg_green(texttocolor):
    return BG_GREEN + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_yellow
def turn_bg_yellow(texttocolor):
    return BG_YELLOW + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_blue
def turn_bg_blue(texttocolor):
    return BG_BLUE + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_magenta
def turn_bg_magenta(texttocolor):
    return BG_MAGENTA + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_cyan
def turn_bg_cyan(texttocolor):
    return BG_CYAN + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_white
def turn_bg_white(texttocolor):
    return BG_WHITE + texttocolor + ENDC


# ###################################################################################
# Function: turn_bg_light_grey
def turn_bg_light_grey(texttocolor):
    return BG_LIGHT_GREY + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_light_red
def turn_bg_light_red(texttocolor):
    return BG_LIGHT_RED + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_light_green
def turn_bg_light_green(texttocolor):
    return BG_LIGHT_GREEN + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_light_yellow
def turn_bg_light_yellow(texttocolor):
    return BG_LIGHT_YELLOW + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_light_blue
def turn_bg_light_blue(texttocolor):
    return BG_LIGHT_BLUE + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_light_magenta
def turn_bg_light_magenta(texttocolor):
    return BG_LIGHT_MAGENTA + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_light_cyan
def turn_bg_light_cyan(texttocolor):
    return BG_LIGHT_CYAN + texttocolor + ENDC

# ###################################################################################
# Function: turn_bg_light_white
def turn_bg_white(texttocolor):
    return BG_LIGHT_WHITE + texttocolor + ENDC

# ###################################################################################
# Function: turn_reset
def turn_reset():
    return RESET + ENDC

