import argparse
import re
from log import *

parser = argparse.ArgumentParser(description='TCP over UDP Implementation')
# Argparse allows for the use of commandline input of variables when compiling the program

parser.add_argument("-a", help="IP Address")
parser.add_argument("-f", help="Filename")
parser.add_argument("-cp", help="Port Number")
parser.add_argument("-sp", help="Server Port")
parser.add_argument("-m", help="Mode (r = Read from Server, w = Write to Server)")

args = parser.parse_args()

addressFormat = re.compile('\d{1,3}(\.\d{1,3}){3}')

if args.a != addressFormat:
    logger.error('Invalid Address: %s', args.a)
    exit(1)

if int(args.cp) <= 5000 or int(args.cp) >= 65535:  # Checks if Server Port is in Range, if not exit(1)
    logger.error('Invalid Port Number: %s', args.cp)
    exit(1)

if int(args.sp) <= 5000 or int(args.sp) >= 65535:  # Checks if Server Port is in Range, if not exit(1)
    logger.error('Invalid Port Number: %s', args.sp)
    exit(1)

if not args.f:
    logger.error('No File Name Provided: %s', args.f)
    exit(1)

clientport = int(args.cp)
serverport = int(args.sp)
address = args.a
filename = args.f
mode = args.m
