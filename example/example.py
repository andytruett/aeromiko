import aeromiko
import argparse
import getpass
import natsort
import operator
from pyfiglet import Figlet
import re
import sys
import tabulate
import warnings
import pprint

#                     #
#     ## #    ####   ##    # ##
#     # # #  #   #    #    ##  #
#     # # #  #   #    #    #   #
#     # # #  #  ##    #    #   #
#     #   #   ## #   ###   #   #


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "ip_addresses",
        nargs="+",
        help="<Required> Provide space-separated list of IP addresses",
    )
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    def isgoodipv4(s):
        pieces = s.split(".")
        if len(pieces) != 4:
            return False
        try:
            return all(0 <= int(p) < 256 for p in pieces)
        except ValueError:
            return False

    for ip_address in args.ip_addresses:
        if isgoodipv4(ip_address):
            get_info(ip_address)


def get_info(ip):
    # ignore self-signed cert error
    warnings.filterwarnings(action="ignore", module=".*paramiko.*")

    # define username and passwords to be used to connect to APs
    username = "admin"
    password = getpass.getpass()

    access_point = aeromiko.AP(ip, username, password)
    access_point.connect()

    ap_hostname(access_point)
    ap_cpu(access_point)
    ap_channels(access_point)
    ap_neighbors(access_point)
    ap_stations(access_point)
    ap_radios(access_point)

    #     #                      #
    #     #                      #
    #     ####    ###    ####  #####  # ##    ####  ## #    ###
    #     #   #  #   #  #        #    ##  #  #   #  # # #  #   #
    #     #   #  #   #   ###     #    #   #  #   #  # # #  #####
    #     #   #  #   #      #    #    #   #  #  ##  # # #  #
    #     #   #   ###   ####      ##  #   #   ## #  #   #   ###


def ap_hostname(access_point):
    try:
        # get hostname via Aeromiko
        access_point.hostname = access_point.get_hostname()
        # print hostname with Figlet and plain text
        figlet = Figlet(font="big")
        print(colorize(figlet.renderText(access_point.hostname), Cyan))
        print(colorize(access_point.hostname, Cyan))

        # get model# and uptime info via Aeromiko
        version_info = access_point.show_version()
        access_point.platform = version_info["PLATFORM"]
        access_point.uptime = version_info["UPTIME"]
        # format uptime for display
        # input :  1 weeks, 3 days, 6 hours, 45 minutes, 33 seconds
        # output: 1w 3d 6h 45m 33s
        #
        # remove commas
        access_point.uptime = re.sub(",", "", access_point.uptime)
        # keep only the first letter of each word
        access_point.uptime = re.sub("([a-z])[a-z]+", r"\1", access_point.uptime)
        # remove spaces immediately following numbers
        access_point.uptime = re.sub(r"(\d+) ", r"\1", access_point.uptime)
        # print model number and uptime
        print("\nModel: " + colorize(access_point.platform, Cyan))
        print("Uptime: " + colorize(access_point.uptime, Cyan))

        # get lldp information via Aeromiko
        lldp_info = access_point.show_lldp_neighbor()
        access_point.lldp_neighbor = lldp_info["SYSTEM_NAME"]
        access_point.lldp_neighbor_port = lldp_info["PORT_DESC"]
        # print port and system descriptions
        print(
            "\nport "
            + colorize(access_point.lldp_neighbor_port, Magenta)
            + " on "
            + colorize(access_point.lldp_neighbor, Magenta)
        )

        # get eth0 information via Aeromiko
        eth0_info = access_point.show_int_eth("eth0")
        access_point.link_duplex = eth0_info["DUPLEX"]
        access_point.link_speed = eth0_info["SPEED"]
        # print link speed and duplex
        print(
            colorize(access_point.link_speed, Magenta)
            + ", "
            + colorize(access_point.link_duplex, Magenta)
            + "\n\n"
        )
    except IndexError:
        pass

    #      ###   ####   #   #
    #     #   #  #   #  #   #
    #     #      #   #  #   #
    #     #      ####   #   #
    #     #      #      #   #
    #     #   #  #      #   #
    #      ###   #       ###


def ap_cpu(access_point):
    snapshot_cpu = access_point.show_cpu()

    print("Snapshot CPU Util")

    access_point.cpu_total = snapshot_cpu["CPU_TOTAL"]
    if float(access_point.cpu_total) > 75:
        access_point.cpu_total = colorize(access_point.cpu_total, Red)
    elif float(access_point.cpu_total) > 50:
        access_point.cpu_total = colorize(access_point.cpu_total, Yellow)
    access_point.cpu_system = snapshot_cpu["CPU_SYSTEM"]
    access_point.cpu_user = snapshot_cpu["CPU_USER"]

    cpu_table = [["Total", access_point.cpu_total]]
    cpu_table.append(["System", access_point.cpu_system])
    cpu_table.append(["User", access_point.cpu_user])

    print(tabulate.tabulate(cpu_table, tablefmt="psql"))
    print("\n")

    #            #                                   ##
    #            #                                    #
    #      ####  ####    ####  # ##   # ##    ###     #     ####
    #     #      #   #  #   #  ##  #  ##  #  #   #    #    #
    #     #      #   #  #   #  #   #  #   #  #####    #     ###
    #     #      #   #  #  ##  #   #  #   #  #        #        #
    #      ####  #   #   ## #  #   #  #   #   ###    ###   ####


def ap_channels(access_point):
    # get and output channel and power information for each radio
    parsed_acsp = access_point.show_acsp()

    # for each
    for radio in parsed_acsp:
        for (key, value) in radio.items():
            key = radio["INTERFACE"] + "_" + key
            key = key.lower()
            setattr(access_point, key, value)

    channels_table = [["Int", "CH", "TX Power"]]

    for radio in ("wifi0", "wifi1"):
        # use getattr cause string + variable concat getting used as var name
        channel_select_state = getattr(
            access_point, radio + "_channel_select_state", ""
        )
        primary_channel = radio + "_primary_channel"

        # ensure asterisk decoration if channel is manually set
        if channel_select_state == "Disable(User disable)":
            if "*" not in getattr(access_point, primary_channel):
                man_chan = getattr(access_point, primary_channel) + "*"
                setattr(access_point, primary_channel, man_chan)

        color = Yellow
        if radio == "wifi1":
            color = Blue

        # use getattr cause string + variable concat getting used as var name
        interface = colorize(getattr(access_point, radio + "_interface"), color)
        chan = colorize(getattr(access_point, primary_channel), color)
        txpower = colorize(getattr(access_point, radio + "_tx_power_dbm"), color)

        channels_table.append([interface, chan, txpower])

    print(tabulate.tabulate(channels_table, headers="firstrow", tablefmt="psql"))
    print("* denotes manual setting")

    #                    #           #      #
    #                                #      #
    #    # ##    ###    ##     ####  ####   ####    ###   # ##    ####
    #    ##  #  #   #    #    #   #  #   #  #   #  #   #  ##     #
    #    #   #  #####    #    #   #  #   #  #   #  #   #  #       ###
    #    #   #  #        #     ####  #   #  #   #  #   #  #          #
    #    #   #   ###    ###       #  #   #  ####    ###   #      ####
    #                          ###


def ap_neighbors(access_point):
    parsed_neighbors = access_point.show_acsp_neighbor()
    bssid_list = []

    neighbor_table = []
    neighbor_table.append(["BSSID", "CH", "RSSI", "SSID", "CU", "CRC", "STA"])

    parsed_neighbors.sort(key=operator.itemgetter("RSSI"))
    parsed_neighbors = natsort.natsorted(
        parsed_neighbors, key=operator.itemgetter("CHANNEL")
    )

    print("\n\nACSP Neighbors >= -85dBm")
    for neighbor in parsed_neighbors:
        # if BBSID !unique, drop it
        if neighbor["BSSID"] not in bssid_list:
            bssid_list.append(neighbor["BSSID"])

            # only show neighbors that we have to share airtime with
            if int(neighbor["RSSI"]) >= -85:

                # copy radio channel so we can decorate the copy and still
                #   use the original for comparison with neighboring APs
                neighbor["DECORATED_CHANNEL"] = neighbor["CHANNEL"]

                # decorate neighbors with > 20 MHz channel usage
                if neighbor["CHANNEL_WIDTH"] != "20":
                    neighbor["DECORATED_CHANNEL"] += (
                        " (" + neighbor["CHANNEL_WIDTH"] + "MHz)"
                    )

                # columns to be output into table
                print_columns = [
                    neighbor["BSSID"],
                    neighbor["DECORATED_CHANNEL"],
                    neighbor["RSSI"],
                    neighbor["SSID"],
                    neighbor["CU"],
                    neighbor["CRC"],
                    neighbor["STA"],
                ]

                w0_channel = re.sub("[*]", "", access_point.wifi0_primary_channel)
                w1_channel = re.sub("[*]", "", access_point.wifi1_primary_channel)

                if neighbor["CHANNEL"] == w0_channel:
                    print_columns = column_colorize(print_columns, Yellow)
                elif neighbor["CHANNEL"] == w1_channel:
                    print_columns = column_colorize(print_columns, Blue)

                neighbor_table.append(print_columns)

    print(tabulate.tabulate(neighbor_table, headers="firstrow", tablefmt="psql"))
    print("\n")

    #              #             #      #
    #              #             #
    #      ####  #####   ####  #####   ##     ###   # ##
    #     #        #    #   #    #      #    #   #  ##  #
    #      ###     #    #   #    #      #    #   #  #   #
    #         #    #    #  ##    #      #    #   #  #   #
    #     ####      ##   ## #     ##   ###    ###   #   #


def ap_stations(access_point):
    parsed_stations = access_point.show_station()
    print("Stations on this AP")
    station_table = [
        [
            "SSID",
            "MAC",
            "IP",
            "Ch",
            "Tx Rate",
            "Rx Rate",
            "Pow(SNR)",
            "Assoc",
            "PHY",
            "State",
        ]
    ]

    parsed_stations.sort(key=operator.itemgetter("MAC_ADDR"))
    parsed_stations = natsort.natsorted(
        parsed_stations, key=operator.itemgetter("SSID")
    )

    for station in parsed_stations:
        if station["IP_ADDR"] == "0.0.0.0":
            station["IP_ADDR"] = colorize(station["IP_ADDR"], Red)

        print_columns = [
            station["SSID"],
            station["MAC_ADDR"],
            station["IP_ADDR"],
            station["CHAN"],
            station["TX_RATE"],
            station["RX_RATE"],
            station["POW_SNR"],
            station["ASSOC_TIME"],
            station["PHYMODE"],
            station["STATION_STATE"],
        ]

        w0_channel = re.sub("[*]", "", access_point.wifi0_primary_channel)
        w1_channel = re.sub("[*]", "", access_point.wifi1_primary_channel)

        if station["CHAN"] == w0_channel:
            print_columns = column_colorize(print_columns, Yellow)
        elif station["CHAN"] == w1_channel:
            print_columns = column_colorize(print_columns, Blue)

        station_table.append(print_columns)

    print(tabulate.tabulate(station_table, headers="firstrow", tablefmt="psql"))

    #                       #    #
    #                       #
    #     # ##    ####   ####   ##     ###
    #     ##     #   #  #   #    #    #   #
    #     #      #   #  #   #    #    #   #
    #     #      #  ##  #   #    #    #   #
    #     #       ## #   ####   ###    ###


def ap_radios(access_point):
    for radio in ("wifi0", "wifi1"):

        color = Yellow
        if radio == "wifi1":
            color = Blue

        parsed_radio_int = access_point.show_int_wifi(radio)
        # prepend wifiN_ before conversion to  properties
        for (key, value) in parsed_radio_int[0].items():
            key = radio + "_" + key
            key = key.lower()
            setattr(access_point, key, value)

        def AP_info(info):
            return getattr(access_point, radio + "_" + info)

        def percent(numerator, denominator):
            answer = int(AP_info(numerator)) / int(AP_info(denominator))
            rounded = round(answer, 2)
            stringified = str(rounded) + "%"
            return stringified

        # build a list for tabulate to print as a table
        data_table = [
            [colorize(radio, color), "", "", ""],
            ["", "Rx", "Tx", ""],
            ["Bytes", AP_info("rx_bytes"), AP_info("tx_bytes"), "", ""],
            [
                "Drops",
                percent("rx_drops", "rx_packets"),
                percent("tx_drops", "tx_packets"),
            ],
            [
                "Errors",
                percent("rx_err", "rx_packets"),
                percent("tx_err", "tx_packets"),
            ],
            [],
            {"Utilization"},
            ["Rx", "Tx", "Interference", "Total"],
            [
                AP_info("rx_util"),
                AP_info("tx_util"),
                AP_info("interference_util"),
                AP_info("total_util"),
            ],
            [],
            ["", "Snapshot", "Short Avg", "Running Avg"],
            [
                "Rx CU",
                AP_info("snap_rx_cu"),
                AP_info("stma_rx_cu"),
                AP_info("run_avg_rx_cu"),
                "",
            ],
            [
                "Tx CU",
                AP_info("snap_tx_cu"),
                AP_info("stma_tx_cu"),
                AP_info("run_avg_tx_cu"),
                "",
            ],
            [
                "Interference",
                AP_info("snap_interference_cu"),
                AP_info("stma_interference_cu"),
                AP_info("run_avg_interference_cu"),
                "",
            ],
            [
                "Noise",
                AP_info("snap_noise"),
                AP_info("stma_noise"),
                AP_info("run_avg_noise"),
                "",
            ],
        ]
        print("\n" + tabulate.tabulate(data_table, headers="firstrow", tablefmt="psql"))


#                    ##                    #
#                     #
#      ####   ###     #     ###   # ##    ##    #####   ###
#     #      #   #    #    #   #  ##       #       #   #   #
#     #      #   #    #    #   #  #        #      #    #####
#     #      #   #    #    #   #  #        #     #     #
#      ####   ###    ###    ###   #       ###   #####   ###


Black = "\u001b[30;1m"  # Black
Red = "\u001b[31;1m"  # Red
Green = "\u001b[32;1m"  # Green
Yellow = "\u001b[33;1m"  # Yellow
Blue = "\u001b[34;1m"  # Blue
Magenta = "\u001b[35;1m"  # Magenta
Cyan = "\u001b[36;1m"  # Cyan
White = "\u001b[37;1m"  # White
End = "\033[0m"

OPERATOR_SYMBOLS = {
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "in": operator.contains,
}


def colorize(what_to_color, color):
    return color + what_to_color + End


def column_colorize(print_columns, color):
    new_columns = []
    for column in print_columns:
        new_column = colorize(column, color)
        new_columns.append(new_column)
    return new_columns


#                            #
#            ## #    ####   ##    # ##
#            # # #  #   #    #    ##  #
#            # # #  #   #    #    #   #
#            # # #  #  ##    #    #   #
#    ######  #   #   ## #   ###   #   # ######

if __name__ == "__main__":
    sys.exit(main())
