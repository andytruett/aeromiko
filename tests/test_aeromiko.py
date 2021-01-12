import aeromiko
from pytest_mock import mocker

ip = "172.17.11.12"
username = "admin"
password = "password"

my_ap = aeromiko.AP(ip, username, password)


def test_initial_values():
    assert my_ap.ip == ip, f'self.ip should be "{ip}"'
    assert my_ap.username == username, f'self.username should be "{username}"'
    assert my_ap.password == password, f'self.password should be "{password}"'


def test_fsm_parse_raw():
    command_response = r"""
Copyright (c) 2006-2019 Aerohive Networks, Inc.

Version:            HiveOS 10.0r5 build-228634
Build time:         Sun Apr 28 07:09:28 UTC 2019
Build cookie:       1904280009-228634
Platform:           AP6Bootloader ver:     v0.0.4.3c
TPM ver:            v1.2.66.16
Uptime:             1 weeks, 6 days, 6 hours, 35 minutes, 22 seconds
    """
    test_template = r"""Value PLATFORM (.*)
Value UPTIME (.*)

Start
  ^\s*Platform:\s*${PLATFORM}
  ^\s*Uptime:\s*${UPTIME} -> Record
    """
    parsed = my_ap.fsm_parse(command_response, template=test_template)
    assert parsed == [
        {
            "PLATFORM": "AP6Bootloader ver:     v0.0.4.3c",
            "UPTIME": "1 weeks, 6 days, 6 hours, 35 minutes, 22 seconds",
        }
    ]


def test_get_hostname(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command", return_value="hostname Campus-Building-105"
    )
    # expects string
    assert my_ap.get_hostname() == "Campus-Building-105"


def test_show_version(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Copyright (c) 2006-2019 Aerohive Networks, Inc.

Version:            HiveOS 10.0r5 build-228634
Build time:         Sun Apr 28 07:09:28 UTC 2019
Build cookie:       1904280009-228634
Platform:           AP6Bootloader ver:     v0.0.4.3c
TPM ver:            v1.2.66.16
Uptime:             1 weeks, 6 days, 6 hours, 35 minutes, 22 seconds""",
    )
    # expects dictionary
    assert my_ap.show_version() == {
        "PLATFORM": "AP6Bootloader ver:     v0.0.4.3c",
        "UPTIME": "1 weeks, 6 days, 6 hours, 35 minutes, 22 seconds",
        "VERSION": "HiveOS 10.0r5 build-228634",
    }


def test_show_cpu(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""CPU total utilization:                8.457%
CPU user utilization:                 2.487%
CPU system utilization:               3.980%""",
    )
    # expects dicionary
    assert my_ap.show_cpu() == {
        "CPU_SYSTEM": "3.980",
        "CPU_TOTAL": "8.457",
        "CPU_USER": "2.487",
    }


def test_show_temperature(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value="Current temperature:               51(degree C)",
    )
    # expects string
    assert my_ap.show_temperature() == "51"


def test_show_station(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Chan=channel number; Pow=Power in dBm;
A-Mode=Authentication mode; Cipher=Encryption mode;
A-Time=Associated time; Auth=Authenticated;
UPID=User profile Identifier; Phymode=Physical mode;
Ifname=wifi0.1, Ifindex=19, SSID=MyHive:
Mac Addr       IP Addr         Chan Tx Rate Rx Rate Pow(SNR)         A-Mode   Cipher  A-Time  VLAN Auth UPID Phymode LDPC Tx-STBC Rx-STBC    SM-PS Chan-width   MU-MIMO Release Station-State
-------------- --------------- ---- ------- ------- -------- -------------- -------- -------- ---- ---- ---- ------- ---- ------- ------- -------- ---------- --------- ------- -------------
Ifname=wifi1.1, Ifindex=21, SSID=MyHive:
Mac Addr       IP Addr         Chan Tx Rate Rx Rate Pow(SNR)         A-Mode   Cipher  A-Time  VLAN Auth UPID Phymode LDPC Tx-STBC Rx-STBC    SM-PS Chan-width   MU-MIMO Release Station-State
-------------- --------------- ---- ------- ------- -------- -------------- -------- -------- ---- ---- ---- ------- ---- ------- ------- -------- ---------- --------- ------- -------------
ffff:eeee:aaaa 127.0.2.14      56    156M     24M  -61(31)     wpa2-8021x aes ccmp 08:15:35  422  Yes    4    11b/g  Yes   Yes     Yes     static    20MHz          No      No data collecting...
ffff:eeee:aaaa 127.0.2.25      56    234M     24M  -57(35)     wpa2-8021x aes ccmp 11:19:02  422  Yes    4    11ac  Yes   Yes     Yes     static    20MHz          No      No Good
ffff:eeee:aaaa 127.0.2.24      56   72.2M      6M  -53(39)     wpa2-8021x aes ccmp 126:44:23  422  Yes    4    11na   No    No     Yes     static    20MHz          No      No Good
Ifname=wifi0.2, Ifindex=22, SSID=MyHive-PPSK:
Mac Addr       IP Addr         Chan Tx Rate Rx Rate Pow(SNR)         A-Mode   Cipher  A-Time  VLAN Auth UPID Phymode LDPC Tx-STBC Rx-STBC    SM-PS Chan-width   MU-MIMO Release Station-State
-------------- --------------- ---- ------- ------- -------- -------------- -------- -------- ---- ---- ---- ------- ---- ------- ------- -------- ---------- --------- ------- -------------
Ifname=wifi1.2, Ifindex=23, SSID=MyHive-PPSK:
Mac Addr       IP Addr         Chan Tx Rate Rx Rate Pow(SNR)         A-Mode   Cipher  A-Time  VLAN Auth UPID Phymode LDPC Tx-STBC Rx-STBC    SM-PS Chan-width   MU-MIMO Release Station-State
-------------- --------------- ---- ------- ------- -------- -------------- -------- -------- ---- ---- ---- ------- ---- ------- ------- -------- ---------- --------- ------- -------------
Ifname=wifi0.3, Ifindex=24, SSID=MyHive-AUX:
Mac Addr       IP Addr         Chan Tx Rate Rx Rate Pow(SNR)         A-Mode   Cipher  A-Time  VLAN Auth UPID Phymode LDPC Tx-STBC Rx-STBC    SM-PS Chan-width   MU-MIMO Release Station-State
-------------- --------------- ---- ------- ------- -------- -------------- -------- -------- ---- ---- ---- ------- ---- ------- ------- -------- ---------- --------- ------- -------------
Ifname=wifi1.3, Ifindex=25, SSID=MyHive-AUX:
Mac Addr       IP Addr         Chan Tx Rate Rx Rate Pow(SNR)         A-Mode   Cipher  A-Time  VLAN Auth UPID Phymode LDPC Tx-STBC Rx-STBC    SM-PS Chan-width   MU-MIMO Release Station-Sta-------------- --------------- ---- ------- ------- -------- -------------- -------- -------- ---- ---- ---- ------- ---- ------- ------- -------- ---------- --------- ------- -------------""",
    )
    # expects dicionary
    assert my_ap.show_station() == [
        {
            "ASSOC_MODE": "wpa2-8021x",
            "ASSOC_TIME": "08:15:35",
            "AUTH": "Yes",
            "CHAN": "56",
            "CHAN_WIDTH": "20MHz",
            "CIPHER": "aes ccmp",
            "IFNAME": "wifi1.1",
            "IP_ADDR": "127.0.2.14",
            "LDPC": "Yes",
            "MAC_ADDR": "ffff:eeee:aaaa",
            "MUMIMO": "No",
            "PHYMODE": "11b/g",
            "POW_SNR": "-61(31)",
            "RELEASE": "No",
            "RX_RATE": "24M",
            "RX_STBC": "Yes",
            "SM_PS": "static",
            "SSID": "MyHive",
            "STATION_STATE": "data collecting...",
            "TX_RATE": "156M",
            "TX_STBC": "Yes",
            "UPID": "4",
            "VLAN": "422",
        },
        {
            "ASSOC_MODE": "wpa2-8021x",
            "ASSOC_TIME": "11:19:02",
            "AUTH": "Yes",
            "CHAN": "56",
            "CHAN_WIDTH": "20MHz",
            "CIPHER": "aes ccmp",
            "IFNAME": "wifi1.1",
            "IP_ADDR": "127.0.2.25",
            "LDPC": "Yes",
            "MAC_ADDR": "ffff:eeee:aaaa",
            "MUMIMO": "No",
            "PHYMODE": "11ac",
            "POW_SNR": "-57(35)",
            "RELEASE": "No",
            "RX_RATE": "24M",
            "RX_STBC": "Yes",
            "SM_PS": "static",
            "SSID": "MyHive",
            "STATION_STATE": "Good",
            "TX_RATE": "234M",
            "TX_STBC": "Yes",
            "UPID": "4",
            "VLAN": "422",
        },
        {
            "ASSOC_MODE": "wpa2-8021x",
            "ASSOC_TIME": "126:44:23",
            "AUTH": "Yes",
            "CHAN": "56",
            "CHAN_WIDTH": "20MHz",
            "CIPHER": "aes ccmp",
            "IFNAME": "wifi1.1",
            "IP_ADDR": "127.0.2.24",
            "LDPC": "No",
            "MAC_ADDR": "ffff:eeee:aaaa",
            "MUMIMO": "No",
            "PHYMODE": "11na",
            "POW_SNR": "-53(39)",
            "RELEASE": "No",
            "RX_RATE": "6M",
            "RX_STBC": "Yes",
            "SM_PS": "static",
            "SSID": "MyHive",
            "STATION_STATE": "Good",
            "TX_RATE": "72.2M",
            "TX_STBC": "No",
            "UPID": "4",
            "VLAN": "422",
        },
    ]


def test_show_lldp_neighbor(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""LLDP neighbor table: Total number = 1
--------------------------------
Incoming Port: eth0
Chassis ID(mac address): ffff:aaaa:eeee
Port ID(locally assigned): 1
Hold time(seconds): 116
Port description: A1
System name: Campus-Building-106-5406R
System description: HP J9850A Switch 5406Rzl2, revision KB.15.18.0013, ROM KB.15.01.0001 (/ws/swbuildm/rel_quebec_qaoff/code/build/bom(swbuildm_rel_quebec_qaoff_rel_quebec))
System capabilities: bridge, router
Enables capabilities: bridge
Management address:
        IP address: 127.0.1.1
        interface subtype:Interface index, number:0
802.1 port VLAN identifier: 1422
802.3 MAC/PHY status:
        auto-negotiation support/status: 0x03
                auto-negotiation: supported
                auto-negotiation: enabled
        PMD auto-negotiation: 0x6c01
                Bit on: 10BASE-T(half duplex)
                Bit on: 10BASE-T(full duplex)
                Bit on: 100BASE-TX(half duplex)
                Bit on: 100BASE-TX(full duplex)
                Bit on: 1000BASE-T full duplex
        MAU: 1000BaseTFD - Four-pair Category 5 UTP, full duplex
TIA - Media Capabilities:
        Capabilities: 0xf
                LLDP-MED capabilities
                network policy
                location identification
                extended power via MDI - PSE
        Device Type: Network Connectivity
Extended Power-via-MDI:
        power type: PSE devi        power source: unknown
        power priority: low
        power value: 130""",
    )
    # expects dicionary
    assert my_ap.show_lldp_neighbor() == {
        "SYSTEM_NAME": "Campus-Building-106-5406R",
        "PORT_DESC": "A1",
    }


def test_show_int_eth(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Parent interface=none;
Mode=backhaul; Mac learning= disabled; Admin state=enabled;
WEB server=disable; NAT support=disable; DHCP client=disable; DHCP server=disable; DNS server=disable;
IP addr=0.0.0.0; Netmask=0.0.0.0;
Internal station traffic state=enabled;
Operational state=up; Duplex=full-duplex; Speed=1000Mbps;
LLDP state=enabled; CDP state=enabled;
Hiveid="HiveManager NG Virtual Appliance"; Native-vlan=400;
MAC addr=ffff:aaaa:7500; MTU=1500 Rx packets=  63157666; errors=0; dropped=6;
Tx packets=4319628068; errors=0; dropped=0;
Rx bytes=45431034860 (42.311 GB); Tx bytes=14004707141 (13.043 GB);
""",
    )
    # expects dicionary
    assert my_ap.show_int_eth("eth0") == {"DUPLEX": "full-duplex", "SPEED": "1000Mbps"}


def test_show_int_wifi(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Campus-Building-105#show int wifi0
AC=access category; be=best-effort; bg=background; vi=video; vo=voice;
AIFS=Arbitration Inter-Frame Space; Txoplimit=transmission opportunity limit;
IDP=Intrusion detection and prevention; BGSCAN=background scan; PS=Power save;
HT=High throughput; A-MPDU=Aggregate MAC protocol data unit;
DFS=Dynamic Frequency Selection; CU=channel Utilization;
EIRP=Effective Isotropic Radiated Power (Transmit Power + Max Antenna Gain + Max TX Chains Gain);

Summary state=High collision;
Mode=access; Radio disabled=no;
Admin state=enabled; Operational state=up;
MAC addr=ffff:aaaa:dddd; MTU=1500;
Freq(Chan)=2462Mhz(11); EIRP power=15.27dBm(5dBm + 4.25dBi + 6.02dBi); Diversity=disabled;
Tx range=300m; Noise floor=-96dBm; Tx power control=disabled;
Radio profile=MyHive-ax-2.4; IDP profile=Campus-WIPS;
Presence profile=N/A; Presence state=disabled;
Beacon interval=100; Max clients number=100;
Phymode=11ax-2g; Short preamble mode=enabled;
Tx Chain=static 4; Rx Chain=static 4;
A-MPDU=enabled; Short guard interval=enabled;
channel width=20Mhz; HT-protection=Green field; Deny client=11b;
AC=be; CWmin=4; CWmax=6; AIFS=3; Txoplimit=0; NoACK=disabled;
AC=bg; CWmin=4; CWmax=10; AIFS=7; Txoplimit=0; NoACK=disabled;
AC=vi; CWmin=3; CWmax=4; AIFS=1; Txoplimit=3008; NoACK=disabled;
AC=vo; CWmin=2; CWmax=3; AIFS=1; Txoplimit=1504; NoACK=disabled;
Rx packets=24794326; errors=161988137; dropped=161988027;
Tx packets= 1586017; errors=   212397; dropped=        2;
Rx bytes=3202100101 (2.982 GB); Tx bytes=1353411518 (1.260 GB);
ACSP use last selection=disabled;
BGSCAN allow=enabled; BGSCAN during voice=disabled; BGSCAN interval=10 minutes;
BGSCAN with client=enabled; BGSCAN with PS client=disabled;
Number of BGSCAN=18801; Number of BGSCAN requested=20591; Number of BGSCAN missed=1790;
DFS=disabled; Number of detected radar signals=0; DFS static-channel restore=disabled;
LLDP state=N/A; CDP state=N/A;
Rx airtime=67.38 s; Tx airtime=639.30 s; CRC error airtime=2707.37 s;
Rx airtime percent=0.00%; Tx airtime percent=0.00%; CRC error airtime percent=0.61%;
Tx utilization=2%; Rx utilization=0%; Interference utilization=3%; Total utilization=5%;
Backhaul failover=disable;
Running average Tx CU=1%; Rx CU=4%; Interference CU=3%; Noise=-95dBm;
Short term means average Tx CU=1%; Rx CU=4%; Interference CU=3%; Noise=-95dBm;
Snapshot Tx CU=1%; Rx CU=4%; Interference CU=3%; Noise=-95dBm;
CRC error rate=0.63%;
Benchmark 11a score=222000; 11b score=50500; 11g score=222000; 11n score=501000; 11ac score=889000; 11ax score=889000;
OFDMA downlink=disabled;
A-MSDU=disabled; A-MPDU limit=1048575;
Tx beamforming=disabled;
Frameburst=enabled;
MU-MIMO=disabled;
Alternate radio profile=disabled;
Primary radio profile=MyHive-ax-2.4;
DSSS 20Mhz power:
Board limit=20dBm(1) 20dBm(2) 20dBm(3) 20dBm(4); Regulatory limit=23dBm(1) 23dBm(2) 23dBm(3) 23(4);
Spectral scan=off;
The signal go through BPF.""",
    )
    # expects dicionary
    assert my_ap.show_int_wifi("wifi0") == [
        {
            "CRC_ERROR_AIRTIME_PCT": "0.61",
            "INTERFERENCE_UTIL": "3%",
            "RUN_AVG_INTERFERENCE_CU": "3%",
            "RUN_AVG_NOISE": "-95dBm",
            "RUN_AVG_RX_CU": "4%",
            "RUN_AVG_TX_CU": "1%",
            "RX_AIRTIME_PCT": "0.00",
            "RX_BYTES": "2.982 GB",
            "RX_DROPS": "161988027",
            "RX_ERR": "161988137",
            "RX_PACKETS": "24794326",
            "RX_UTIL": "0%",
            "SNAP_INTERFERENCE_CU": "3%",
            "SNAP_NOISE": "-95dBm",
            "SNAP_RX_CU": "4%",
            "SNAP_TX_CU": "1%",
            "STMA_INTERFERENCE_CU": "3%",
            "STMA_NOISE": "-95dBm",
            "STMA_RX_CU": "4%",
            "STMA_TX_CU": "1%",
            "TOTAL_UTIL": "5%",
            "TX_AIRTIME_PCT": "0.00",
            "TX_BYTES": "1.260 GB",
            "TX_DROPS": "2",
            "TX_ERR": "212397",
            "TX_PACKETS": "1586017",
            "TX_UTIL": "2%",
        }
    ]


def test_show_acsp(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Interface channel select state  Primary channel  channel width Power ctrl state      Tx power(dbm) Use Last Selection
--------- --------------------- ---------------- ------------- --------------------- ------------- ---------------------
Wifi0     Enable                11               20            Enable                5          channel:No  Power:No
Wifi1     Enable                56               20            Enable                17            channel:Yes Power:No""",
    )
    # expects dicionary
    assert my_ap.show_acsp() == [
        {
            "CHANNEL_SELECT_STATE": "Enable",
            "CHANNEL_WIDTH": "20",
            "INTERFACE": "Wifi0",
            "POWER_CTRL_STATE": "Enable",
            "PRIMARY_CHANNEL": "11",
            "TX_POWER_DBM": "5",
        },
        {
            "CHANNEL_SELECT_STATE": "Enable",
            "CHANNEL_WIDTH": "20",
            "INTERFACE": "Wifi1",
            "POWER_CTRL_STATE": "Enable",
            "PRIMARY_CHANNEL": "56",
            "TX_POWER_DBM": "17",
        },
    ]


def test_show_acsp_neighbor(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""wifi0(7) ACSP neighbor list (52/384):
Bssid           Mode     Ssid/Hive                Chan Rssi(dBm) Aerohive AP  CU  CRC STA Channel-width VID  NVI
ffff:aaaa:13d4  Access   MyHive                      6    -84       yes          33  15  1   20            3  3
ffff:aaaa:9a2b  Access                            1    -82       no           --  --  --  20            -    -
ffff:aaaa:6985  Access   Blacks-846985      1    -91       no           --  --  --  40+           -    -
ffff:aaaa:00e6  Access   Hotspot00E6              1    -84       no           --  --  --  20            -    -

wifi1(8) ACSP neighbor list (31/384):
Bssid           Mode     Ssid/Hive                Chan Rssi(dBm) Aerohive AP  CU  CRC STA Channel-width VID  NVI
ffff:bbbb:db14  Access   MyHive-Guest                52   -57       yes          4   43  1   20            3  3
ffff:bbbb:71a4  Access   MyHive                      136  -75       yes          6   1   7   20            3  3
""",
    )
    # expects dicionary
    assert my_ap.show_acsp_neighbor() == [
        {
            "AEROHIVE": "yes",
            "BSSID": "ffff:aaaa:13d4",
            "CHANNEL": "6",
            "CHANNEL_WIDTH": "20",
            "CRC": "15",
            "CU": "33",
            "MODE": "Access",
            "RSSI": "-84",
            "SSID": "MyHive",
            "STA": "1",
        },
        {
            "AEROHIVE": "no",
            "BSSID": "ffff:aaaa:9a2b",
            "CHANNEL": "1",
            "CHANNEL_WIDTH": "20",
            "CRC": "--",
            "CU": "--",
            "MODE": "Access",
            "RSSI": "-82",
            "SSID": "",
            "STA": "--",
        },
        {
            "AEROHIVE": "no",
            "BSSID": "ffff:aaaa:6985",
            "CHANNEL": "1",
            "CHANNEL_WIDTH": "40+",
            "CRC": "--",
            "CU": "--",
            "MODE": "Access",
            "RSSI": "-91",
            "SSID": "Blacks-846985",
            "STA": "--",
        },
        {
            "AEROHIVE": "no",
            "BSSID": "ffff:aaaa:00e6",
            "CHANNEL": "1",
            "CHANNEL_WIDTH": "20",
            "CRC": "--",
            "CU": "--",
            "MODE": "Access",
            "RSSI": "-84",
            "SSID": "Hotspot00E6",
            "STA": "--",
        },
        {
            "AEROHIVE": "yes",
            "BSSID": "ffff:bbbb:db14",
            "CHANNEL": "52",
            "CHANNEL_WIDTH": "20",
            "CRC": "43",
            "CU": "4",
            "MODE": "Access",
            "RSSI": "-57",
            "SSID": "MyHive-Guest",
            "STA": "1",
        },
        {
            "AEROHIVE": "yes",
            "BSSID": "ffff:bbbb:71a4",
            "CHANNEL": "136",
            "CHANNEL_WIDTH": "20",
            "CRC": "1",
            "CU": "6",
            "MODE": "Access",
            "RSSI": "-75",
            "SSID": "MyHive",
            "STA": "7",
        },
    ]


def test_show_boot_param(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""boot parameters:
Device IP:          0.0.0.0
Netmask:            0.0.0.0
TFTP Server IP:     0.0.0.0
Gateway IP:         0.0.0.0
VLAN ID:            0
Native-VLAN ID:     0
Netboot Always:     Disabled
Netboot:            Disabled
Boot File:
Netdump:            Disable
Netdump File:       06301805230088.netdump
Region Code:        FCC
Country Code:       840""",
    )
    # expects dicionary
    assert my_ap.show_boot_param() == [
        {
            "BOOT_FILE": "",
            "COUNTRY_CODE": "840",
            "DEVICE_IP": "0.0.0.0",
            "GATEWAY_IP": "0.0.0.0",
            "NATIVE_VLAN_ID": "",
            "NETBOOT": "Disabled",
            "NETBOOT_ALWAYS": "Disabled",
            "NETDUMP": "Disable",
            "NETDUMP_FILE": "06301805230088.netdump",
            "NETMASK": "0.0.0.0",
            "REGION_CODE": "FCC",
            "TFTP_SERVER_IP": "0.0.0.0",
            "VLAN_ID": "0",
        }
    ]


def test_show_acsp_channel_info(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""wifi0 (12):
State: RUN
Lowest cost channel: 11, lowest-cost: 17
channel   1 Cost: 56
channel   2 Cost: 32767 (overlap)


wifi1 (13):
State: RUN
Lowest cost channel: 48, lowest-cost: 0
Channel  44 Cost: 25
channel  48 Cost: 0
channel 165 Cost: 0""",
    )
    # expects dicionary
    assert my_ap.show_acsp_channel_info() == [
        {
            "CHANNEL": "1",
            "CHANNEL_COST": "56",
            "CHANNEL_OVERLAP": "",
            "INT": "wifi0",
            "INT_VALUE": "12",
            "LOWEST_COST": "17",
            "LOWEST_COST_CHANNEL": "11",
            "STATE": "RUN",
        },
        {
            "CHANNEL": "2",
            "CHANNEL_COST": "32767",
            "CHANNEL_OVERLAP": "overlap",
            "INT": "wifi0",
            "INT_VALUE": "12",
            "LOWEST_COST": "17",
            "LOWEST_COST_CHANNEL": "11",
            "STATE": "RUN",
        },
        {
            "CHANNEL": "44",
            "CHANNEL_COST": "25",
            "CHANNEL_OVERLAP": "",
            "INT": "wifi1",
            "INT_VALUE": "13",
            "LOWEST_COST": "0",
            "LOWEST_COST_CHANNEL": "48",
            "STATE": "RUN",
        },
        {
            "CHANNEL": "48",
            "CHANNEL_COST": "0",
            "CHANNEL_OVERLAP": "",
            "INT": "wifi1",
            "INT_VALUE": "13",
            "LOWEST_COST": "0",
            "LOWEST_COST_CHANNEL": "48",
            "STATE": "RUN",
        },
        {
            "CHANNEL": "165",
            "CHANNEL_COST": "0",
            "CHANNEL_OVERLAP": "",
            "INT": "wifi1",
            "INT_VALUE": "13",
            "LOWEST_COST": "0",
            "LOWEST_COST_CHANNEL": "48",
            "STATE": "RUN",
        },
    ]


def test_show_capwap_client(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""CAPWAP client:   Enabled
CAPWAP transport mode:  UDP
RUN state: Connected securely to the CAPWAP server
CAPWAP client IP:        127.0.1.12
CAPWAP server IP:        127.0.0.2
HiveManager Primary Name:hivemanager.MyHive.edu
HiveManager Backup Name: hivemanager.MyHive.edu
CAPWAP Default Server Name: redirector.aerohive.com
Virtual HiveManager Name: HiveManager Virtual Appliance
Server destination Port: 12222
CAPWAP send event:       Enabled
CAPWAP DTLS state:       Enabled
CAPWAP DTLS negotiation: Disabled
     DTLS next connect status:   Enable
     DTLS always accept bootstrap passphrase: Enabled
     DTLS session status: Connected
     DTLS key type: passphrase
     DTLS session cut interval:     5 seconds
     DTLS Buildingdshake wait interval: 60 seconds
     DTLS Max retry count:          3
     DTLS authorize failed:         0
     DTLS reconnect count:          0
Discovery interval:      5 seconds
Heartbeat interval:     30 seconds
Max discovery interval: 10 seconds
Neighbor dead interval:105 seconds
Silent interval:        15 seconds
Wait join interval:     60 seconds
Discovery count:         0
Max discovery count:     3
Retransmit count:        0
Max retransmit count:    2
Primary server tries:    0
Backup server tries:     3
Keepalives lost/sent:    26/73138
Event packet drop due to buffer shortage: 0
Event packet drop due to loss connection: 6""",
    )
    # expects dicionary
    assert my_ap.show_capwap_client() == [
        {
            "BACKUP_SERVER_TRIES": "3",
            "CAPWAP_CLIENT": "Enabled",
            "CAPWAP_CLIENT_IP": "127.0.1.12",
            "CAPWAP_DEFAULT_SERVER_NAME": "redirector.aerohive.com",
            "CAPWAP_DTLS_NEGOTIATION": "Disabled",
            "CAPWAP_DTLS_STATE": "Enabled",
            "CAPWAP_SEND_EVENT": "Enabled",
            "CAPWAP_SERVER_IP": "127.0.0.2",
            "CAPWAP_TRANSPORT_MODE": "UDP",
            "DISCOVERY_COUNT": "0",
            "DISCOVERY_INTERVAL": "5 seconds",
            "DTLS_ALWAYS_ACCEPT_BOOTSTRAP_PASSPHRASE": "Enabled",
            "DTLS_AUTHORIZE_FAILED": "0",
            "DTLS_HANDSHAKE_WAIT_INTERVAL": "",
            "DTLS_KEY_TYPE": "passphrase",
            "DTLS_MAX_RETRY_COUNT": "3",
            "DTLS_NEXT_CONNECT_STATUS": "Enable",
            "DTLS_RECONNECT_COUNT": "0",
            "DTLS_SESSION_CUT_INTERVAL": "5 seconds",
            "DTLS_SESSION_STATUS": "Connected",
            "EVENT_PACKET_DROP_DUE_TO_BUFFER_SHORTAGE": "0",
            "EVENT_PACKET_DROP_DUE_TO_LOSS_CONNECTION": "6",
            "HEARTBEAT_INTERVAL": "30 seconds",
            "HIVEMANAGER_BACKUP_NAME": "hivemanager.MyHive.edu",
            "HIVEMANAGER_PRIMARY_NAME": "hivemanager.MyHive.edu",
            "KEEPALIVES_LOST_SENT": "26/73138",
            "MAX_DISCOVERY_COUNT": "3",
            "MAX_DISCOVERY_INTERVAL": "10 seconds",
            "MAX_RETRANSMIT_COUNT": "2",
            "NEIGHBOR_DEAD_INTERVAL": "105 seconds",
            "PRIMARY_SERVER_TRIES": "0",
            "RETRANSMIT_COUNT": "0",
            "RUN_STATE": "Connected securely to the CAPWAP server",
            "SERVER_DESTINATION_PORT": "12222",
            "SILENT_INTERVAL": "15 seconds",
            "VIRTUAL_HIVEMANAGER_NAME": "HiveManager Virtual Appliance",
            "WAIT_JOIN_INTERVAL": "60 seconds",
        }
    ]


def test_show_console(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Console page lines:            Disable
Console timeout in minutes:    10
Serial port status:            Enabled
Console echo obscure-passwords:Enabled""",
    )
    # expects dicionary
    assert my_ap.show_console() == [
        {
            "CONSOLE_LINES": "Disable",
            "CONSOLE_OBSCURE_PASSWORDS": "Enabled",
            "CONSOLE_TIMEOUT": "10",
            "SERIAL_STATUS": "Enabled",
        }
    ]


def test_show_dns(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""DNS server from DHCP:
Domain name suffix: MyHive.edu
Primary   : 127.0.1.212
Secondary : 127.0.1.216
Tertiary  : 0.0.0.0""",
    )
    # expects dicionary
    assert my_ap.show_dns() == [
        {
            "DNS_SERVER_FROM_DHCP": "",
            "DOMAIN_NAME_SUFFIX": "MyHive.edu",
            "PRIMARY": "127.0.1.212",
            "SECONDARY": "127.0.1.216",
            "TERTIARY": "0.0.0.0",
        }
    ]


def test_show_hivemanager(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""HiveManager Primary:    hivemanager.MyHive.edu
HiveManager Backup:     hivemanager.MyHive.edu
HiveManager connection: Connected securely to Aerohive""",
    )
    # expects dicionary
    assert my_ap.show_hivemanager() == [
        {
            "HM_BACKUP": "hivemanager.MyHive.edu",
            "HM_CONNECTION": "Connected securely to Aerohive",
            "HM_PRIMARY": "hivemanager.MyHive.edu",
        }
    ]


def test_show_hw_info(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Ethernet MAC address:         ffff:eeee:0f80
Serial number:                01234567891234
Hardware revision:            01
Product name:                 AP230
Hardware ID:                  0
Manufacturing date:           20140922
Number of MAC addresses:      64
Manufacturing version:        1
Antenna ID:                   0
Aerohive hardware key:
HW Auth Device Status:        success
TPM Status:                   success""",
    )
    # expects dicionary
    assert my_ap.show_hw_info() == [
        {
            "AEROHIVE_HARDWARE_KEY": "",
            "ANTENNA_ID": "0",
            "ETHERNET_MAC_ADDRESS": "ffff:eeee:0f80",
            "HARDWARE_ID": "0",
            "HARDWARE_REVISION": "01",
            "HW_AUTH_DEVICE_STATUS": "success",
            "MANUFACTURING_DATE": "20140922",
            "MANUFACTURING_VERSION": "1",
            "NUMBER_OF_MAC_ADDRESSES": "64",
            "PRODUCT_NAME": "AP230",
            "SERIAL_NUMBER": "01234567891234",
            "TPM_STATUS": "success",
        }
    ]


def test_show_idm(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""IDM client: Enabled Per SSID
IDM Proxy IP: 127.0.1.3
IDM proxy: Disabled
RadSec Certificate state: Valid
RadSec Certificate Issued: 2019-08-14 00:30:52 GMT
RadSec Certificate Expires: 2020-08-13 00:30:52 GMT""",
    )
    # expects dicionary
    assert my_ap.show_idm() == [
        {
            "IDM_CLIENT": "Enabled Per SSID",
            "IDM_PROXY": "Disabled",
            "IDM_PROXY_IP": "127.0.1.3",
            "RADSEC_CERTIFICATE_EXPIRE": "",
            "RADSEC_CERTIFICATE_ISSUED": "2019-08-14 00:30:52 GMT",
            "RADSEC_CERTIFICATE_STATE": "Valid",
        }
    ]


def test_show_ip_route(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Ref=references; Iface=interface;
U=route is up;H=target is a host; G=use gateway;
Destination     Gateway         Netmask         Flags Metric Ref    Use Iface
--------------- --------------- --------------- ----- ------ ------ --- -----
0.0.0.0         127.0.1.1       0.0.0.0         UG    0      0        0 mgt0
127.0.0.0       0.0.0.0         255.255.255.0   U     0      0        0
127.0.1.0       0.0.0.0         255.255.255.0   U     0      0        0 mgt0
198.18.4.0      0.0.0.0         255.255.254.0   U     0      0        0 wifi0.2
198.18.36.0     0.0.0.0         255.255.254.0   U     0      0        0 wifi1.2""",
    )
    # expects dictionary
    assert my_ap.show_ip_route() == [
        {
            "DESTINATION": "0.0.0.0",
            "FLAGS": "UG",
            "GATEWAY": "127.0.1.1",
            "IFACE": "mgt0",
            "METRIC": "0",
            "NETMASK": "0.0.0.0",
            "REF": "0",
            "USE": "0",
        },
        {
            "DESTINATION": "127.0.1.0",
            "FLAGS": "U",
            "GATEWAY": "0.0.0.0",
            "IFACE": "mgt0",
            "METRIC": "0",
            "NETMASK": "255.255.255.0",
            "REF": "0",
            "USE": "0",
        },
        {
            "DESTINATION": "198.18.4.0",
            "FLAGS": "U",
            "GATEWAY": "0.0.0.0",
            "IFACE": "wifi0.2",
            "METRIC": "0",
            "NETMASK": "255.255.254.0",
            "REF": "0",
            "USE": "0",
        },
        {
            "DESTINATION": "198.18.36.0",
            "FLAGS": "U",
            "GATEWAY": "0.0.0.0",
            "IFACE": "wifi1.2",
            "METRIC": "0",
            "NETMASK": "255.255.254.0",
            "REF": "0",
            "USE": "0",
        },
    ]


def test_show_memory(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Total Memory:       921652 KB
Free Memory:        449092 KB
Used Memory:        472560 KB
""",
    )
    # expects dictionary
    assert my_ap.show_memory() == [
        {"FREE_MEMORY": "449092", "TOTAL_MEMORY": "921652", "USED_MEMORY": "472560"}
    ]


def test_show_route(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Route table:
flag: (S)tatic, (I)nterface (L)ocal (T)unnel (O)wn
sta             nhop            oif      metric upid flag
---------------------------------------------------------
0000:0000:0000  1234:5678:7500  eth0        0    0   L O
1234:5678:7524  1234:5678:7500  wifi1.1     0 4096  IL
1234:5678:7515  1234:5678:7500  wifi0.2     0 4096  IL
1234:5678:7501  1234:5678:7500  eth1        0 4096  IL
1234:5678:7503  1234:5678:7500  agg0        0 4096  IL
1234:5678:7502  1234:5678:7500  red0        0 4096
1234:5678:bcda  3485:8401:7500  wifi1.1     0    4   L O
1234:5678:50b9  1234:5678:7500  wifi1.1     0    4   L O
Total route entries: 10
""",
    )
    # expects dictionary
    assert my_ap.show_route() == [
        {
            "FLAG": "L O",
            "METRIC": "0",
            "NHOP": "1234:5678:7500",
            "OIF": "eth0",
            "STA": "0000:0000:0000",
            "UPID": "0",
        },
        {
            "FLAG": "IL",
            "METRIC": "0",
            "NHOP": "1234:5678:7500",
            "OIF": "wifi1.1",
            "STA": "1234:5678:7524",
            "UPID": "4096",
        },
        {
            "FLAG": "IL",
            "METRIC": "0",
            "NHOP": "1234:5678:7500",
            "OIF": "wifi0.2",
            "STA": "1234:5678:7515",
            "UPID": "4096",
        },
        {
            "FLAG": "IL",
            "METRIC": "0",
            "NHOP": "1234:5678:7500",
            "OIF": "eth1",
            "STA": "1234:5678:7501",
            "UPID": "4096",
        },
        {
            "FLAG": "IL",
            "METRIC": "0",
            "NHOP": "1234:5678:7500",
            "OIF": "agg0",
            "STA": "1234:5678:7503",
            "UPID": "4096",
        },
        {
            "FLAG": "",
            "METRIC": "0",
            "NHOP": "1234:5678:7500",
            "OIF": "red0",
            "STA": "1234:5678:7502",
            "UPID": "4096",
        },
        {
            "FLAG": "L O",
            "METRIC": "0",
            "NHOP": "3485:8401:7500",
            "OIF": "wifi1.1",
            "STA": "1234:5678:bcda",
            "UPID": "4",
        },
        {
            "FLAG": "L O",
            "METRIC": "0",
            "NHOP": "1234:5678:7500",
            "OIF": "wifi1.1",
            "STA": "1234:5678:50b9",
            "UPID": "4",
        },
    ]


def test_show_snmp(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""location:           Campus-Building|Campus-Building-1
Syscontact:         admin@aerohive.com
Community numbers:  1
""",
    )
    # expects dictionary
    assert my_ap.show_snmp() == [
        {
            "COMMUNITY_NUMBERS": "1",
            "SYSCONTACT": "admin@aerohive.com",
            "SYSLOCATION": "",
        }
    ]


def test_show_ssid(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""Frag=fragment threshold; RTS=request to send;
DTIM=delivery traffic indication map;

No. Name                             Frag    RTS     DTIM period Max client  Mac filter
--- ----                             ----    ---     ----------- ---------- --------
1   MyHive                              2346    2346    1           100         MyHive
2   MyHive-PPSK                         2346    2346    1           100         MyHive-PPSK
3   MyHive-AUX                          2346    2346    1           100         MyHive-AUX
""",
    )
    # expects dictionary
    assert my_ap.show_ssid() == [
        {
            "DTIM_PERIOD": "1",
            "FRAG": "2346",
            "MAC_FILTER": "MyHive",
            "MAX_CLIENT": "100",
            "NAME": "MyHive",
            "NO": "1",
            "RTS": "2346",
        },
        {
            "DTIM_PERIOD": "1",
            "FRAG": "2346",
            "MAC_FILTER": "MyHive-PPSK",
            "MAX_CLIENT": "100",
            "NAME": "MyHive-PPSK",
            "NO": "2",
            "RTS": "2346",
        },
        {
            "DTIM_PERIOD": "1",
            "FRAG": "2346",
            "MAC_FILTER": "MyHive-AUX",
            "MAX_CLIENT": "100",
            "NAME": "MyHive-AUX",
            "NO": "3",
            "RTS": "2346",
        },
    ]


def test_show_clock(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command", return_value=r"""2019-12-02  21:38:18  Monday"""
    )
    # expects dictionary
    assert my_ap.show_clock() == [
        {"DATE": "2019-12-02", "DAY": "Monday", "TIME": "21:38:18"}
    ]


def test_show_ntp(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command",
        return_value=r"""State:              Enable
Interval:           180 minutes
  First             127.0.1.10(active)
  Second            127.0.1.212
  Third
  Four
Daylight Saving Time: No
    Start             03-10 01:59:59
    End               11-03 01:59:59""",
    )
    # expects dictionary
    assert my_ap.show_ntp() == [
        {
            "DST": "No",
            "DST_END": "11-03 01:59:59",
            "DST_START": "03-10 01:59:59",
            "FIRST": "127.0.1.10(active)",
            "FOURTH": "",
            "INTERVAL": "180 minutes",
            "SECOND": "127.0.1.212",
            "STATE": "Enable",
            "THIRD": "",
        }
    ]


def test_show_timezone(mocker):
    m = mocker.patch(
        "aeromiko.AP.send_command", return_value=r"""Timezone:           GMT-5:00"""
    )
    # expects dictionary
    assert my_ap.show_timezone() == [{"TIMEZONE": "GMT-5:00"}]
