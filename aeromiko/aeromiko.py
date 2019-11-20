# import aeromiko.templates
import logging
import tempfile
import textfsm
import netmiko
import re
from . import templates

try:
    import importlib.resources as pkg_resources
except ImportError:
    import importlib_resources as pkg_resources


class AP:
    def __init__(self, ip: str, username: str, password: str):
        self.ip = ip
        self.password = password
        self.username = username

    def connect(self, verbosity=False):
        """Establish SSH connection to the access point

        Parameters
        ----------
        verbosity : bool, optional
            Toggle verbose SSH connection information, by default False
        """

        switch = {
            "device_type": "cisco_ios",
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "port": 22,
            "verbose": verbosity,
        }

        self.net_connect = netmiko.ConnectHandler(**switch)

        self.net_connect.find_prompt()
        self.net_connect.send_command("console page 0")

    def disconnect(self):
        return self.net_connect.disconnect()

    def send_command(self, command: str):
        """Send CLI command to AP and return raw response

        Parameters
        ----------
        command : str
            CLI command to send

        Returns
        -------
        str
            raw CLI response
        """
        return self.net_connect.send_command(command)

    def get_info(self, command: str, template: str):
        """Get structured data from CLI command response, via textFSM template

        Parameters
        ----------
        command : str
            response string from CLI
        template : str
            textFSM template string

        Returns
        -------
        dict
            structured data extracted from CLI response
        """

        textfsm_template = pkg_resources.read_text(templates, template)

        command_response = self.send_command(command)

        tmp = tempfile.NamedTemporaryFile(delete=False)
        with open(tmp.name, "w") as file:
            file.write(textfsm_template)
        with open(tmp.name, "r") as file:
            fsm = textfsm.TextFSM(file)
            fsm_results = fsm.ParseText(command_response)
            info = [dict(zip(fsm.header, row)) for row in fsm_results]
        for information in info:
            for (key, value) in information.items():
                information[key] = value.strip()
        return info

    def show_config_running(self):
        """Get running configuration (returns unstructured string)

        Returns
        -------
        str
            unstructured CLI response to "show config running"
        """

        command = "show config running"

        config_running = self.send_command(command)
        return config_running

    def get_hostname(self):
        """Get hostname

        Returns
        -------
        str
            access point hostname as defined in running configuration
        """

        command = "show config running | i hostname"
        template = "get_hostname.textfsm"

        hostname_info = self.get_info(command, template)
        hostname = hostname_info[0]["HOSTNAME"]
        return hostname

    def show_version(self):
        """Get version information

        Returns
        -------
        dict
            PLATFORM, AP model
            UPTIME  , time since last reboot
        """
        command = "show version"
        template = "show_version.textfsm"

        version = self.get_info(command, template)
        return version[0]

    def show_cpu(self):
        """Get CPU details

        Returns
        -------
        dict
            CPU_TOTAL , current aggregate CPU utilization
            CPU_USER  , current user CPU utilization
            CPU_SYSTEM, current system CPU utilization
        """

        command = "show cpu"
        template = "show_cpu.textfsm"

        cpu = self.get_info(command, template)
        return cpu[0]

    def show_station(self):
        """Get stations currently associated to this AP

        Returns
        -------
        dict
            IFNAME       , interface station is associated to
            SSID         , SSID station is associated to
            MAC_ADDR     , MAC address of station
            IP_ADDR      , IP address of station
            CHAN         , channel station is on
            TX_RATE      , transmit rate to station
            RX_RATE      , receive rate from station
            POW_SNR      , power level (d) and signal-to-noise ratio of station
            ASSOC_MODE   , association mode of station
            CIPHER       , cipher mode of station
            ASSOC_TIME   , association time of station
            VLAN         , user VLAN of station
            AUTH         , authentication mode of station
            UPID         , user profile ID assigned to station
            PHYMODE      , PHY mode of station
            LDPC         , LDPC code usage by station
            TX_STBC      , STBC code usage to station
            RX_STBC      , STBC code usage from station
            SM_PS        , Spatial Multiplexing Power Save usage by station
            CHAN_WIDTH   , channel width in use by station
            MUMIMO       , MUMIMO usage of station
            RELEASE      , release state of station
            STATION_STATE, state of station
        """

        command = "show station"
        template = "show_station.textfsm"

        stations = self.get_info(command, template)
        return stations

    def show_lldp_neighbor(self):
        """Get LLDP neighbor information

        Returns
        -------
        dict
            PORT_DESC  , interface description on LLDP neighbor
            SYSTEM_NAME, system name of LLDP neighbor
        """

        command = "show lldp neighbor"
        template = "show_lldp_neighbor.textfsm"

        lldp_neighbor = self.get_info(command, template)
        return lldp_neighbor[0]

    def show_int_eth(self, interface: str):
        """Get ethernet inferface details

        Parameters
        ----------
        interface : str
            eth interface #

        Returns
        -------
        dict
            DUPLEX, ethernet link duplex
            SPEED , ethernet link speed
        """

        command = "sh int " + interface
        template = "show_eth.textfsm"

        int_eth = self.get_info(command, template)
        return int_eth[0]

    def show_int_wifi(self, interface: str):
        """Get WiFi interface details

        Parameters
        ----------
        interface : str
            WiFi interface #

        Returns
        -------
        dict
            RX_PACKETS             , receive packets
            RX_ERR                 , receive errors
            RX_DROPS               , receive drops
            TX_PACKETS             , transmit packets
            TX_ERR                 , transmit errors
            TX_DROPS               , transmit drops
            RX_BYTES               , receive bytes
            TX_BYTES               , transmit bytes
            RX_AIRTIME_PCT         , receive airtime %
            TX_AIRTIME_PCT         , transmit airtime %
            CRC_ERROR_AIRTIME_PCT  , CRC error airtime %
            TX_UTIL                , receive utilization %
            RX_UTIL                , transmit utilization %
            INTERFERENCE_UTIL      , interference utilization %
            TOTAL_UTIL             , total utilization %
            RUN_AVG_TX_CU          , running average transmit utilization
            RUN_AVG_RX_CU          , running average receive utilization
            RUN_AVG_INTERFERENCE_CU, running average interference utilization
            RUN_AVG_NOISE          , running average noise utilization
            STMA_TX_CU             , short time mean average transmit utilization
            STMA_RX_CU             , short time mean average receive utilization
            STMA_INTERFERENCE_CU   , short time mean average interference utilization
            STMA_NOISE             , short time mean average noise utilization
            SNAP_TX_CU             , snapshot transmit utilization
            SNAP_RX_CU             , snapshot receive utilization
            SNAP_INTERFERENCE_CU   , snapshot interference utilization
            SNAP_NOISE             , snapshot noise utilization
        """

        command = "show int " + interface
        template = "show_wifi.textfsm"

        int_wifi = self.get_info(command, template)
        return int_wifi

    def show_acsp(self):
        """Get Aerohive Channel Selection Protocol information

        Returns
        -------
        dict
            INTERFACE           , WiFi interface
            CHANNEL_SELECT_STATE, channel select state
            PRIMARY_CHANNEL     , primary channel
            CHANNEL_WIDTH       , channel width
            POWER_CTRL_STATE    , power control state
            TX_POWER_DBM        , Transmit power in dBm
        """
        command = "sh acsp"
        template = "show_acsp.textfsm"

        acsp = self.get_info(command, template)
        return acsp

    def show_acsp_neighbor(self):
        """Get ACSP neighbors (other APs this device can hear)

        Returns
        -------
        dict
            BSSID        , BSSID of neighbor
            MODE         , PHY of neighbor
            SSID         , SSID of neighbor
            CHANNEL      , channel used by neighbor
            RSSI         , RSSI of neighbor
            AEROHIVE     , is neighbor an Aerohive device?
            CU           , current utilization of neighboring Aerohive device
            CRC          , CRC erros to/from neighboring Aerohive device
            STA          , stations on neighboring Aerohive device
            CHANNEL_WIDTH, channel width of neighbor
        """

        command = "show acsp neighbor"
        template = "show_acsp_neighbor.textfsm"

        acsp_neighbors = self.get_info(command, template)
        return acsp_neighbors

    def send_config(self, command_list):
        """Send list of CLI commands to access point

        Parameters
        ----------
        command_list : list
            list of CLI commands to send to AP

        Returns
        -------
        str
            CLI output resulting from AP
        """
        return self.net_connect.send_config_set(command_list)

