from nmap_module import *
from clamav_module import *
from carmitre_module import *
from reports_module import *
import config
import logging
import argparse
import os 
import sys
import threading


def load_configurations(args):
    settings = config.load_config(args.config)

    if args.nmap_options:
        settings['nmap_options'] = args.nmap_options
    if args.clamav_options:
        settings['clamav_options'] = args.clamav_options
    if args.carmitre_options:
        settings['carmitre_options'] = args.carmitre_options
    
    return settings

def main():
    logging.info("Starting main function and analysis of security tools")

    # Analysis of the arguments and configuration file
    args = parse_arguments()
    settings = load_configurations(args)

    # Execution of the nmap tool
    logging.info("Starting nmap analysis")
    nmap_results = nmap_scanner.scan