# import aeromiko.templates
import tempfile
import textfsm
import netmiko
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

    def connect(self, port=22, verbosity=False):
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
            "port": port,
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

    def send_config(self, command_list: list):
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

    def fsm_parse(self, command_response: str, template=str):
        """Get structured data from CLI command response, via textFSM template

        Parameters
        ----------
        command : str
            response string from CLI
        template : str
            raw textFSM template string
            or
            name of predefined template from aeromiko package
        raw : boolean

        Returns
        -------
        dict
            structured data extracted from CLI response
        """
        if template.startswith("Value"):
            textfsm_template = template
        else:
            textfsm_template = pkg_resources.read_text(templates, template)

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

        command = "show config running | i ^hostname"
        template = "get_hostname.textfsm"

        command_response = self.send_command(command)
        hostname_info = self.fsm_parse(command_response, template)
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

        command_response = self.send_command(command)
        version = self.fsm_parse(command_response, template)
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

        command_response = self.send_command(command)
        cpu = self.fsm_parse(command_response, template)
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

        command_response = self.send_command(command)
        stations = self.fsm_parse(command_response, template)
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

        command_response = self.send_command(command)
        lldp_neighbor = self.fsm_parse(command_response, template)
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

        command_response = self.send_command(command)
        int_eth = self.fsm_parse(command_response, template)
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

        command_response = self.send_command(command)
        int_wifi = self.fsm_parse(command_response, template)
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

        command_response = self.send_command(command)
        acsp = self.fsm_parse(command_response, template)
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

        command_response = self.send_command(command)
        acsp_neighbors = self.fsm_parse(command_response, template)
        return acsp_neighbors

    def show_boot_param(self):
        """Show boot parameters

        Returns
        -------
        dict
            DEVICE_IP
            NETMASK
            TFTP_SERVER_IP
            GATEWAY_IP
            VLAN_ID
            NATIVE_VLAN_ID
            NETBOOT_ALWAYS
            NETBOOT
            BOOT_FILE
            NETDUMP
            NETDUMP_FILE
            REGION_CODE
            COUNTRY_CODE
        """
        command = "show boot-param"
        template = "show_boot_param.textfsm"

        command_response = self.send_command(command)
        boot_params = self.fsm_parse(command_response, template)
        return boot_params

    def show_acsp_channel_info(self):
        """Show ACSP decision details for all radios

        Returns
        -------
        dict
            INT
            INT_VALUE
            STATE
            LOWEST_COST_CHANNEL
            LOWEST_COST
            CHANNEL
            CHANNEL_OVERLAP
            CHANNEL_COST
        """
        command = "show acsp channel-info"
        template = "show_acsp_channel_info.textfsm"

        command_response = self.send_command(command)
        acsp_neighbor_info = self.fsm_parse(command_response, template)
        return acsp_neighbor_info

    def show_capwap_client(self):
        """Show capwap client information

        Returns
        -------
        dict
            CAPWAP_CLIENT
            CAPWAP_TRANSPORT_MODE
            RUN_STATE
            CAPWAP_CLIENT_IP
            CAPWAP_SERVER_IP
            HIVEMANAGER_PRIMARY_NAME
            HIVEMANAGER_BACKUP_NAME
            CAPWAP_DEFAULT_SERVER_NAME
            VIRTUAL_HIVEMANAGER_NAME
            SERVER_DESTINATION_PORT
            CAPWAP_SEND_EVENT
            CAPWAP_DTLS_STATE
            CAPWAP_DTLS_NEGOTIATION
            DTLS_NEXT_CONNECT_STATUS
            DTLS_ALWAYS_ACCEPT_BOOTSTRAP_PASSPHRASE
            DTLS_SESSION_STATUS
            DTLS_KEY_TYPE
            DTLS_SESSION_CUT_INTERVAL
            DTLS_HANDSHAKE_WAIT_INTERVAL
            DTLS_MAX_RETRY_COUNT
            DTLS_AUTHORIZE_FAILED
            DTLS_RECONNECT_COUNT
            DISCOVERY_INTERVAL
            HEARTBEAT_INTERVAL
            MAX_DISCOVERY_INTERVAL
            NEIGHBOR_DEAD_INTERVAL
            SILENT_INTERVAL
            WAIT_JOIN_INTERVAL
            DISCOVERY_COUNT
            MAX_DISCOVERY_COUNT
            RETRANSMIT_COUNT
            MAX_RETRANSMIT_COUNT
            PRIMARY_SERVER_TRIES
            BACKUP_SERVER_TRIES
            KEEPALIVES_LOST_SENT
            EVENT_PACKET_DROP_DUE_TO_BUFFER_SHORTAGE
            EVENT_PACKET_DROP_DUE_TO_LOSS_CONNECTION
        """
        command = "show capwap client"
        template = "show_capwap_client.textfsm"

        command_response = self.send_command(command)
        capwap_client = self.fsm_parse(command_response, template)
        return capwap_client

    def show_console(self):
        """Show console port information

        Returns
        -------
        dict
            CONSOLE_LINES            , # lines in console output
            CONSOLE_TIMEOUT          , console timeout (seconds)
            SERIAL_STATUS            , status of serial port
            CONSOLE_OBSCURE_PASSWORDS, obscure console passwords?
        """
        command = "show console"
        template = "show_console.textfsm"

        command_response = self.send_command(command)
        console = self.fsm_parse(command_response, template)
        return console

    def show_dns(self):
        """Show DNS information

        Returns
        -------
        dict
            DNS_SERVER_FROM_DHCP
            DOMAIN_NAME_SUFFIX
            PRIMARY
            SECONDARY
            TERTIARY
        """
        command = "show dns"
        template = "show_dns.textfsm"

        command_response = self.send_command(command)
        dns = self.fsm_parse(command_response, template)
        return dns

    def show_hivemanager(self):
        """Show HiveManager information

        Returns
        -------
        dict
            HM_PRIMARY
            HM_BACKUP
            HM_CONNECTION
        """
        command = "show hivemanager"
        template = "show_hivemanager.textfsm"

        command_response = self.send_command(command)
        hivemanager = self.fsm_parse(command_response, template)
        return hivemanager

    def show_hw_info(self):
        """Show hardware information

        Returns
        -------
        dict
            ETHERNET_MAC_ADDRESS
            SERIAL_NUMBER
            HARDWARE_REVISION
            PRODUCT_NAME
            HARDWARE_ID
            MANUFACTURING_DATE
            NUMBER_OF_MAC_ADDRESSES
            MANUFACTURING_VERSION
            ANTENNA_ID
            AEROHIVE_HARDWARE_KEY
            HW_AUTH_DEVICE_STATUS
            TPM_STATUS
        """
        command = "show hw info"
        template = "show_hw_info.textfsm"

        command_response = self.send_command(command)
        hw_info = self.fsm_parse(command_response, template)
        return hw_info

    def show_idm(self):
        """Show ID Manager information

        Returns
        -------
        dict
            IDM_CLIENT
            IDM_PROXY_IP
            IDM_PROXY
            RADSEC_CERTIFICATE_STATE
            RADSEC_CERTIFICATE_ISSUED
            RADSEC_CERTIFICATE_EXPIRE
        """
        command = "show idm"
        template = "show_idm.textfsm"

        command_response = self.send_command(command)
        idm = self.fsm_parse(command_response, template)
        return idm

    def show_ip_route(self):
        """Show IP route information

        Returns
        -------
        dict
            DESTINATION
            GATEWAY
            NETMASK
            FLAGS
            METRIC
            REF
            USE
            IFACE
        """
        command = "show ip route"
        template = "show_ip_route.textfsm"

        command_response = self.send_command(command)
        ip_route = self.fsm_parse(command_response, template)
        return ip_route

    def show_memory(self):
        """Show RAM information

        Returns
        -------
        dict
            TOTAL_MEMORY
            FREE_MEMORY
            USED_MEMORY
        """
        command = "show memory"
        template = "show_memory.textfsm"

        command_response = self.send_command(command)
        memory = self.fsm_parse(command_response, template)
        return memory

    def show_route(self):
        """Show route information

        Returns
        -------
        dict
            STA
            NHOP
            OIF
            METRIC
            UPID
            FLAG
        """
        command = "show route"
        template = "show_route.textfsm"

        command_response = self.send_command(command)
        route = self.fsm_parse(command_response, template)
        return route

    def show_snmp(self):
        """Show SNMP information

        Returns
        -------
        dict
            SYSLOCATION
            SYSCONTACT
            COMMUNITY_NUMBERS
        """
        command = "show snmp"
        template = "show_snmp.textfsm"

        command_response = self.send_command(command)
        snmp = self.fsm_parse(command_response, template)
        return snmp

    def show_ssid(self):
        """Show SSID information

        Returns
        -------
        dict
            NO
            NAME
            FRAG
            RTS
            DTIM_PERIOD
            MAX_CLIENT
            MAC_FILTER
        """
        command = "show ssid"
        template = "show_ssid.textfsm"

        command_response = self.send_command(command)
        ssid = self.fsm_parse(command_response, template)
        return ssid

    def show_clock(self):
        """Show AP internal clock

        Returns
        -------
        dict
            DATE,   date
            TIME,   time of day
            DAY ,   day of week
        """
        command = "show clock"
        template = "show_clock.textfsm"

        command_response = self.send_command(command)
        clock = self.fsm_parse(command_response, template)
        return clock

    def show_ntp(self):
        """Show NTP information

        Returns
        -------
        dict
            STATE
            INTERVAL
            FIRST
            SECOND
            THIRD
            FOURTH
            DST
            DST_START
            DST_END
        """
        command = "show ntp"
        template = "show_ntp.textfsm"

        command_response = self.send_command(command)
        ntp = self.fsm_parse(command_response, template)
        return ntp

    def show_timezone(self):
        """Show timezone

        Returns
        -------
        str
            TIMEZONE
        """
        command = "show timezone"
        template = "show_timezone.textfsm"

        command_response = self.send_command(command)
        timezone = self.fsm_parse(command_response, template)
        return timezone
