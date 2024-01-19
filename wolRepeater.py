#!/usr/bin/env python

import binascii
import re
import socket
import sys
import logging
import os
import getopt
import json
import jsonschema

# https://regex101.com/r/2l8eJp/3
DGRAM_REGEX = re.compile(r'(?:^([fF]{12})(([0-9a-fA-F]{12}){16})([0-9a-fA-F]{12})?$)')
ETHER_REGEX = re.compile( r'^[0-9a-fA-F]{12}$')

BIND_ADDRESS = "0.0.0.0"
BIND_PORT = 5009

TARGET_ADDRESS = "255.255.255.255"
TARGET_PORT = 9


MAC_PASS_FILE = ""

FORCED_AUTH_HOSTS = {}
# Password to send on forward packets
FORWARD_PASS = ""
# Password to check on received packets
GLOBAL_PASS = ""

LOG_FILE = ""

def is_allowed(address, password):
    if address in FORCED_AUTH_HOSTS:
        logger.debug("Enforcing authentication for {} : {} <-> {}". format(address, FORCED_AUTH_HOSTS[address], password) )
        return password == FORCED_AUTH_HOSTS[address]
    elif GLOBAL_PASS != "":
        logger.debug("Enforcing Global authentication for {} : {} <-> {}". format(address, GLOBAL_PASS, password) )
        return password == GLOBAL_PASS
    return True

def forward_packet(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.connect((TARGET_ADDRESS, TARGET_PORT))
    sock.send(data)
    sock.close()


def handle_packet(data):
    payload = binascii.hexlify(data).decode('utf-8')
    logger.debug("Received payload: %s" % payload)

    if DGRAM_REGEX.match(payload):
        search = DGRAM_REGEX.search(payload)
        address = search.group(3)
        password = search.group(4)

        if is_allowed(address, password):
            
            if ( FORWARD_PASS != "" ):
                newPayload = search.group(1) + search.group(2) + FORWARD_PASS
                logger.debug( "New payload     : {}".format(payload) )
                data = binascii.unhexlify( newPayload )
            #
            logger.info("Forwarding the packet for %s to %s:%s" % (address, TARGET_ADDRESS, TARGET_PORT))

            forward_packet(data)
            
        else:
            logger.debug("This request has been denied because the received password is not correct")
    else:
        logger.debug("Received payload is not valid, ignoring...")


def start_listener():
    logger.debug( "Start_listener on {}:{}".format( BIND_ADDRESS, BIND_PORT ))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_ADDRESS, BIND_PORT))

    while True:
        data, addr = sock.recvfrom(108)
        logger.debug("Received packet from %s:%s" % (addr[0], addr[1]))
        handle_packet(data)


def show_help( error=0 ):
    logger.debug( "show_help")
    print( 
        "wolRepeater", 
        "Forma de uso:",
        "    {} [-h] [-i ip] [-p port] [-t ip] [-r port] [-s password] [-z password] [-f mac_and_passwd_json_file] [-l log file] [-v loglevel]".format( __file__ ),
        "",
        "   -h show this help.",
        "   -i binding ip. Default {}.".format(BIND_ADDRESS),
        "   -p binding port. Default {}.".format(BIND_PORT),
        "   -t target ip. Default {}.".format(TARGET_ADDRESS) ,
        "   -r target port. Default {}.".format(TARGET_PORT),
        "   -f json file with mac's and passwords for SecureOn. View format down.",
        "   -s password for use on forward packet with SecureOn. Default ''.",
        "   -z password to check on received packets with SecureOn. Default ''.",
        "   -l file log",
        "   -v LOGLEVEL",
        "",
        "json format file:",
        "",
        "[",
        "  { \"ethernet\": \"112233445566\", \"password\": \"aabbccddeeff\", ",
        "  { \"ethernet\": \"aa2233445566\", \"password\": \"11bbccddeeff\"  ",
        "]",
        "",
        "Variables de entorno:",
        "   LOGLEVEL=[DEBUG|INFO|WARNING|ERROR|CRITICAL] default=INFO",
        "",
        "Examples:",
        "     {} -h ".format( __file__ ),
        "     {} -i 192.168.1.100".format( __file__ ),
        "     {} -p 8000".format( __file__ ),
        "     {} -t 192.168.1.100".format( __file__ ),
        "     {} -r 8000".format( __file__ ),
        "     {} -s 112233445566".format( __file__ ),
        "     {} -f /etc/wol/mac_and_pass.json".format( __file__ ),
        "     {} -z aabbccddeeff".format(__file__ ),
        "     {} -l /var/log/wol_replicator.log".format( __file__ ),
        "     {} -v DEBUG".format( __file__ ),
        "     LOGLEVEL=DEBUG {}".format(__file__),
        "",
        sep = "\n"
        )
    sys.exit( error )
    #

def json_validation ( data ):

    logger.debug( "Data: '{}'".format(data))

    schema = {

            "type" : "array",
            "items" : {
                "type" : "object",
                "properties" : {
                    "ethernet": {"type" : "string", "pattern": "^[0-9a-fA-F]{12}$"},
                    "password": {"type" : "string", "pattern": "^[0-9a-fA-F]{12}$"}
                                },
                "required": ["ethernet","password"]
            }

          }
    try :
        jsonschema.validate(instance=data, schema=schema)

    except jsonschema.exceptions.ValidationError as v:
            logger.critical ( v )
            sys.exit(1)
    else:
        logger.info( "JSON File validated.")

    # Convert json validated to simple dictionary

    TMP_HOSTS = {}

    for item in data:
        logger.debug ("secured mac : {} : {}".format( item['ethernet'], item['password'] ))
        TMP_HOSTS[ item['ethernet'] ] = item['password']
    #
    logger.debug( "Authorized Ethernets: '{}'".format( TMP_HOSTS ))
    return TMP_HOSTS
#

if __name__ == '__main__':
    logFormatter = logging.Formatter("%(asctime)s [%(levelname)s] - %(message)s")
    logger = logging.getLogger()

    LOGLEVEL = os.environ.get('LOGLEVEL','INFO')
    
    logger.setLevel(LOGLEVEL)

    log = logging.getLogger( __name__ )

    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(logFormatter)
    logger.addHandler(consoleHandler)

    try:
        opts, args = getopt.getopt(sys.argv[1:],'hi:p:f:l:s:t:r:v:')
    except getopt.GetoptError:
        logger.critical( "Error en las opciones" )
        show_help( 2 )
    
    logger.debug( "opts: {}".format( opts))
    logger.debug( "args: {}".format( args))

    for opt, arg in opts:
        if opt == '-h':
            show_help( 0 )

        elif opt == '-i':
            BIND_ADDRESS = arg
            logger.debug( "New BIND Address:{}".format( BIND_ADDRESS ))

        elif opt == '-p':
            BIND_PORT = int( arg )
            logger.debug( "New BIND Port:{}".format( BIND_PORT ))

        elif opt == '-t':
            TARGET_ADDRESS = arg
            logger.debug( "New TARGET Address:{}".format( TARGET_ADDRESS ))

        elif opt == '-r':
            TARGET_PORT = int( arg )
            logger.debug( "New TARGET Port:{}".format( TARGET_PORT ))

        elif opt == '-s':
            if ETHER_REGEX.match(arg):
                FORWARD_PASS = arg
                logger.debug( "FORWARD_PASS: '{}' like ethernet 'aabbccddeeff' ".format(FORWARD_PASS))
            else:
                logger.critical( "Invalid FORWARD_PASS: '{}', ethernet like needed 'aabbccddeeff' ".format(arg))
                sys.exit (1)
            #

        elif opt == "-f":
            MAC_PASS_FILE = arg
            logger.debug( "File mac and passwords: {}".format( MAC_PASS_FILE ))

            if  not os.path.isfile( MAC_PASS_FILE ) :
                logger.critical ("{} Not found.".format( MAC_PASS_FILE ))
                sys.exit()
            #
            json_content=""
            try :
                with open( MAC_PASS_FILE ) as json_file:
                    json_content = json.load(json_file)
                #
            #    
            except Exception as e:
                log.critical("Error al usar el fichero : '{}' {}".format( MAC_PASS_FILE, type(e).__name__ ))
                sys.exit(1)

            FORCED_AUTH_HOSTS = json_validation ( json_content )

        elif opt == '-z':
            if ETHER_REGEX.match(arg):
                GLOBAL_PASS = arg
                logger.debug( "GLOBAL_PASS: '{}' like ethernet 'aabbccddeeff' ".format(GLOBAL_PASS))
            else:
                logger.critical( "Invalid GLOBAL_PASS: '{}', ethernet like needed 'aabbccddeeff' ".format(arg))
                sys.exit (1)
            #
        elif opt == "-l":
            LOG_FILE = arg
            logger.debug( "Log File:{}".format( LOG_FILE ))

            fileHandler = logging.FileHandler( LOG_FILE )
            fileHandler.setFormatter(logFormatter)
            logger.addHandler(fileHandler)

        elif opt == '-v':
            LOGLEVEL = arg
            try :
                logger.setLevel(LOGLEVEL)
                logger.debug( "Set new LOGLEVEL:{}".format( LOGLEVEL ))
            except:
                logger.critical( "LOGLEVEL ERROR ON ID '{}'".format(LOGLEVEL))
                show_help(3)
            #
        #
        #
    #
    
    # Show configuration by default
    logger.info( "BIND Address:{}".format( BIND_ADDRESS ))
    logger.info( "BIND Port:{}".format( BIND_PORT ))
    logger.info( "TARGET Port:{}".format( TARGET_PORT ))
    logger.debug( "FORWARD_PASS: '{}' like ethernet 'aabbccddeeff' ".format(FORWARD_PASS))
    logger.info( "File mac and passwords: {}".format( MAC_PASS_FILE ))
    logger.debug( "GLOBAL_PASS: '{}' like ethernet 'aabbccddeeff' ".format(GLOBAL_PASS))
    logger.info( "Log File:{}".format( LOG_FILE ))
    logger.info( "LOG LEVEL:{}".format( LOGLEVEL ))

    try:
        start_listener()
    except KeyboardInterrupt:
        logger.debug("Exiting because of keyboard interrupt")
        sys.exit()
