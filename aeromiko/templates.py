class templates:
    #     #                      #
    #     #                      #
    #     ####    ###    ####  #####  # ##    ####  ## #    ###
    #     #   #  #   #  #        #    ##  #  #   #  # # #  #   #
    #     #   #  #   #   ###     #    #   #  #   #  # # #  #####
    #     #   #  #   #      #    #    #   #  #  ##  # # #  #
    #     #   #   ###   ####      ##  #   #   ## #  #   #   ###

    get_hostname_template = r"""Value HOSTNAME (.*)

Start
  ^.*hostname -> AP_HOSTNAME

AP_HOSTNAME
  ^hostname\s*${HOSTNAME} -> Record
"""
    #                                   #
    #     ## ##   ###   # ##    ####   ##     ###   # ##
    #      # #   #   #  ##     #        #    #   #  ##  #
    #      # #   #####  #       ###     #    #   #  #   #
    #       #    #      #          #    #    #   #  #   #
    #       #     ###   #      ####    ###    ###   #   #

    show_version_template = r"""Value PLATFORM (.*)
Value UPTIME (.*)

Start
  ^\s*Platform:\s*${PLATFORM}
  ^\s*Uptime:\s*${UPTIME} -> Record
"""
    #      ####  ####   #   #
    #     #      #   #  #   #
    #     #      #   #  #   #
    #     #      #   #  #  ##
    #      ####  ####    ## #
    #            #

    show_cpu_template = r"""Value CPU_TOTAL ([\d.]+)
Value CPU_USER ([\d.]+)
Value CPU_SYSTEM ([\d.]+)

Start
  ^\s*CPU total utilization:\s+${CPU_TOTAL}%
  ^\s*CPU user utilization:\s+${CPU_USER}%
  ^\s*CPU system utilization:\s+${CPU_SYSTEM}% -> Record
"""
    #              #             #      #
    #              #             #
    #      ####  #####   ####  #####   ##     ###   # ##
    #     #        #    #   #    #      #    #   #  ##  #
    #      ###     #    #   #    #      #    #   #  #   #
    #         #    #    #  ##    #      #    #   #  #   #
    #     ####      ##   ## #     ##   ###    ###   #   #

    show_station_template = r"""Value Filldown IFNAME (wifi\d\.\d)
Value Filldown SSID (.+)
Value Required MAC_ADDR ([0-9a-f:]+)
Value IP_ADDR ([\.0-9]+)
Value CHAN (\d+)
Value TX_RATE (\d+.?\d*M)
Value RX_RATE (\d+.?\d*M)
Value POW_SNR (-\d+\(\s?\d+\))
Value ASSOC_MODE ([\w\-\d]+)
Value CIPHER ([\w ]+)
Value ASSOC_TIME (\d{2,}:\d{2}:\d{2})
Value VLAN (\d+)
Value AUTH (Yes|No)
Value UPID (\d+)
Value PHYMODE (11(\w+))
Value LDPC (Yes|No)
Value TX_STBC (Yes|No)
Value RX_STBC (Yes|No)
Value SM_PS (\w+)
Value CHAN_WIDTH (\d{2,}MHz)
Value MUMIMO (Yes|No)
Value RELEASE (Yes|No)
Value STATION_STATE (.*)

Start
  ^\s*Ifname=${IFNAME}.*SSID=${SSID}:
  ^\s*${MAC_ADDR}\s*${IP_ADDR}\s*${CHAN}\s*${TX_RATE}\s*${RX_RATE}\s*${POW_SNR}\s*${ASSOC_MODE}\s*${CIPHER}\s*${ASSOC_TIME}\s*${VLAN}\s*${AUTH}\s*${UPID}\s*${PHYMODE}\s*${LDPC}\s*${TX_STBC}\s*${RX_STBC}\s*${SM_PS}\s*${CHAN_WIDTH}(\s*${MUMIMO})?\s*${RELEASE}\s*${STATION_STATE} -> Record
"""

    #      ##     ##        #
    #       #      #        #
    #       #      #     ####  ####
    #       #      #    #   #  #   #
    #       #      #    #   #  #   #
    #       #      #    #   #  #   #
    #      ###    ###    ####  ####
    #                          #

    show_lldp_neighbor_template = r"""Value SYSTEM_NAME (([\+]|[\w-])+)
Value PORT_DESC (\w+)

Start
  ^.*LLDP neighbor -> LLDP

LLDP
  ^Port description:\s+${PORT_DESC}
  ^System name:\s+${SYSTEM_NAME} -> Record
"""
    #       #             #                    #    #
    #                     #                    #    #
    #      ##    # ##   #####          ###   #####  ####
    #       #    ##  #    #           #   #    #    #   #
    #       #    #   #    #           #####    #    #   #
    #       #    #   #    #           #        #    #   #
    #      ###   #   #     ##          ###      ##  #   #

    show_eth_template = r"""Value DUPLEX ([\w\-]+)
Value SPEED (\d+Mbps)

Start
  ^.*Duplex=${DUPLEX};\s*Speed=${SPEED}; -> Record
"""
    #       #             #                    #      ###    #
    #                     #                          #
    #      ##    # ##   #####         #   #   ##    ####    ##
    #       #    ##  #    #           # # #    #     #       #
    #       #    #   #    #           # # #    #     #       #
    #       #    #   #    #           # # #    #     #       #
    #      ###   #   #     ##          # #    ###    #      ###

    show_wifi_template = r"""Value RX_PACKETS (\d+)
Value RX_ERR (.+)
Value RX_DROPS (\d+)
Value TX_PACKETS (\d+)
Value TX_ERR (\d+)
Value TX_DROPS (\d+)
Value RX_BYTES (.+)
Value TX_BYTES (.+)
Value RX_AIRTIME_PCT ((\d|\.)+)
Value TX_AIRTIME_PCT ((\d|\.)+)
Value CRC_ERROR_AIRTIME_PCT ((\d|\.)+)
Value TX_UTIL (\d+%)
Value RX_UTIL (\d+%)
Value INTERFERENCE_UTIL (\d+%)
Value TOTAL_UTIL (\d+%)
Value RUN_AVG_TX_CU (\d+%)
Value RUN_AVG_RX_CU (\d+%)
Value RUN_AVG_INTERFERENCE_CU (\d+%)
Value RUN_AVG_NOISE (-\d+dBm)
Value STMA_TX_CU (\d+%)
Value STMA_RX_CU (\d+%)
Value STMA_INTERFERENCE_CU (\d+%)
Value STMA_NOISE (-\d+dBm)
Value SNAP_TX_CU (\d+%)
Value SNAP_RX_CU (\d+%)
Value SNAP_INTERFERENCE_CU (\d+%)
Value SNAP_NOISE (-\d+dBm)

Start
  ^.*AC=access category -> INT

INT
  ^\s*Rx packets=\s*${RX_PACKETS};\s*errors=\s*${RX_ERR};\s*dropped=\s*${RX_DROPS};
  ^\s*Tx packets=\s*${TX_PACKETS};\s*errors=\s*${TX_ERR};\s*dropped=\s*${TX_DROPS};
  ^\s*Rx bytes=.*\(${RX_BYTES}\);\s+Tx bytes=.*\(${TX_BYTES}\);
  ^\s*Rx airtime percent=\s*${RX_AIRTIME_PCT}%;\s+Tx.*=\s*${TX_AIRTIME_PCT}%;\s+CRC.*\s*=${CRC_ERROR_AIRTIME_PCT}%
  ^\s*Tx utilization=\s*${TX_UTIL};\s+Rx.*=\s*${RX_UTIL};\s+Interference.*\s*=${INTERFERENCE_UTIL};\s+Total.*=\s*${TOTAL_UTIL}
  ^\s*Running average Tx CU=\s*${RUN_AVG_TX_CU};\s+Rx CU=\s*${RUN_AVG_RX_CU};\s+Interference.*\s*=${RUN_AVG_INTERFERENCE_CU};\s+Noise.*=\s*${RUN_AVG_NOISE}
  ^\s*Short term means average Tx CU=\s*${STMA_TX_CU};\s+Rx CU=\s*${STMA_RX_CU};\s+Interference.*\s*=${STMA_INTERFERENCE_CU};\s+Noise.*=\s*${STMA_NOISE}
  ^\s*Snapshot Tx CU=\s*${SNAP_TX_CU};\s+Rx CU=\s*${SNAP_RX_CU};\s+Interference.*\s*=${SNAP_INTERFERENCE_CU};\s+Noise.*=\s*${SNAP_NOISE} -> Record
"""
    #      ####   ####   ####  ####
    #     #   #  #      #      #   #
    #     #   #  #       ###   #   #
    #     #  ##  #          #  #   #
    #      ## #   ####  ####   ####
    #                          #

    show_acsp_template = r"""Value INTERFACE (Wifi[01])
Value CHANNEL_SELECT_STATE (Enable|Disable|Disable\(User disable\)|Disable\(Link down\)|Scanning|DFS CAC|Listening|Init)
Value PRIMARY_CHANNEL ((\d{1,3}\*?)|ACSP|Down)
Value CHANNEL_WIDTH (\d{1,3})
Value POWER_CTRL_STATE (Enable|Disable|Disable\(User disable\)|Disable\(Link down\)|Scanning|DFS CAC|Listening|Init)
Value TX_POWER_DBM ((\d{1,2}\*?)|ACSP|Down)

Start
  ^.*Interface -> ACSP

ACSP
  ^${INTERFACE}\s+${CHANNEL_SELECT_STATE}\s+${PRIMARY_CHANNEL}(\s*${CHANNEL_WIDTH})?\s*${POWER_CTRL_STATE}\s*${TX_POWER_DBM} -> Record
"""
    #                                                        #           #      #
    #                                                                    #      #
    #      ####   ####   ####  ####          # ##    ###    ##     ####  ####   ####    ###   # ##
    #     #   #  #      #      #   #         ##  #  #   #    #    #   #  #   #  #   #  #   #  ##
    #     #   #  #       ###   #   #         #   #  #####    #    #   #  #   #  #   #  #   #  #
    #     #  ##  #          #  #   #         #   #  #        #     ####  #   #  #   #  #   #  #
    #      ## #   ####  ####   ####          #   #   ###    ###       #  #   #  ####    ###   #
    #                          #                                   ###

    show_acsp_neighbor_template = r"""Value BSSID ([0-9A-Fa-f:]{14})
Value MODE (\w+)
Value SSID ((?!\s{2,})[\w\W]*?)
Value CHANNEL (\d{1,3})
Value RSSI (-\d{1,3})
Value AEROHIVE (yes|no)
Value CU (--|(\d{1,3}))
Value CRC (--|(\d{1,3}))
Value STA (--|(\d{1,3}))
Value CHANNEL_WIDTH (\d{1,3}\+?)

Start
  ^.*Bssid -> BSSID

BSSID
  ^\s*${BSSID}\s+${MODE}\s+${SSID}\s+${CHANNEL}\s+${RSSI}\s+${AEROHIVE}\s+${CU}\s+${CRC}\s+${STA}\s+${CHANNEL_WIDTH} -> Record
"""
