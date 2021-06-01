import json
from typing import Optional, Dict, List, Any, Set
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from time import sleep, time
from math import floor
from requests import Session

from assemblyline.common.str_utils import safe_str
from assemblyline.common.isotime import epoch_to_local, epoch_to_iso
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.icap import IcapClient
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection, BODY_FORMAT

ICAP_METHOD = "icap"
HTTP_METHOD = "http"
VALID_METHODS = [ICAP_METHOD, HTTP_METHOD]
DEFAULT_WAIT_TIME_BETWEEN_RETRIES = 60  # in seconds
DEFAULT_WAIT_TIME_BETWEEN_COMPLETION_CHECKS = 500  # in milliseconds

# Specific signature names
REVISED_SIG_SCORE_MAP = {}

# Specific keywords found in a signature name
REVISED_KW_SCORE_MAP = {}


class AntiVirusHost:
    """
    This class represents the antivirus product host and how it should be interacted with
    """
    def __init__(self, group: str, ip: str, port: int, method: str, update_period: int,
                 endpoint: Optional[str] = None) -> None:
        """
        This method initializes the AntiVirusHost class and performs a couple validity checks
        @param group: The name of the antivirus product
        @param ip: The IP at which the antivirus product is hosted on and is listening on
        @param port: The port at which the antivirus product is listening on
        @param method: The method with which this class should interact with the antivirus product
        @param update_period: The number of minutes between when the product polls for updates
        @param endpoint: The endpoint that the antivirus product will scan a file at
        @return: None
        """
        if method not in VALID_METHODS:
            raise ValueError(f"Given method '{method}' is not one of {VALID_METHODS}.")

        self.group = group
        self.ip = ip
        self.port = port
        self.method = method
        self.update_period = update_period
        self.endpoint = endpoint
        self.client = IcapClient(
            host=self.ip,
            port=self.port,
            respmod_service=self.endpoint
        ) \
            if self.method == ICAP_METHOD else Session()
        self.sleeping = False

    def __eq__(self, other) -> bool:
        """
        This method verifies the equality between class instances by their attributes
        @param other: The other class instance which this class instance will be compared with
        @return: A boolean indicating if the two class instances are equal
        """
        return self.group == other.group and self.ip == other.ip and \
               self.port == other.port and self.method == other.method and \
               self.update_period == other.update_period and self.endpoint == other.endpoint and \
               type(self.client) == type(other.client) and self.sleeping == other.sleeping

    def sleep(self, timeout: int) -> None:
        """
        This method raises a flag and sleeps for a given period of time. This is used for diverting submissions away
        from this host in case the host goes down
        @param timeout: The period of time (in seconds) for the method to sleep
        """
        self.sleeping = True
        sleep(timeout)
        self.sleeping = False


class AvHitSection(ResultSection):
    """
    This class represents an Assemblyline Service ResultSection specifically for antivirus products
    """
    def __init__(self, av_name: str, av_version: Optional[str], virus_name: str, engine: Dict[str, str], heur_id: int) -> None:
        """
        This method initializes the AvResultSection class and performs a couple validity checks
        @param av_name: The name of the antivirus product
        @param av_version: A string detailing the version of the antivirus product, if applicable
        @param virus_name: The name of the virus, determined by the antivirus product
        @param engine: The details of the engine that detected the virus
        @param heur_id: Essentially an integer flag that indicates if the scanned file is "infected" or "suspicious"
        @return: None
        """
        title = f"{av_name} identified the file as {virus_name}"
        json_body = dict(
            av_name=av_name,
            virus_name=virus_name,
            scan_result="infected" if heur_id == 1 else "suspicious",
        )
        if engine:
            json_body["engine_version"] = engine['version']
            json_body["engine_definition_time"] = engine['def_time']

        if av_version:
            json_body["av_version"] = av_version

        super(AvHitSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body),
        )
        signature_name = f'{av_name}.{virus_name}'
        section_heur = Heuristic(heur_id)
        if signature_name in REVISED_SIG_SCORE_MAP:
            section_heur.add_signature_id(signature_name, REVISED_SIG_SCORE_MAP[signature_name])
        elif any(kw in signature_name.lower() for kw in REVISED_KW_SCORE_MAP):
            section_heur.add_signature_id(
                signature_name,
                max([REVISED_KW_SCORE_MAP[kw] for kw in REVISED_KW_SCORE_MAP if kw in signature_name.lower()])
            )
        else:
            section_heur.add_signature_id(signature_name)
        self.heuristic = section_heur
        self.add_tag('av.virus_name', virus_name)
        if heur_id == 2:
            self.add_tag("av.heuristic", virus_name)

        # TODO: Isolate parts of X-Virus-ID/virus_name according https://encyclopedia.kaspersky.com/knowledge/rules-for-naming/
        # So that we can tag more items of interest


# TODO: This is here until we phase out the use of Python 3.7 (https://github.com/python/cpython/pull/9844)
# Then we can put type hinting in the execute() method
# Global variables
av_hit_result_sections: List[AvHitSection] = []


class AntiVirus(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(AntiVirus, self).__init__(config)
        self.hosts: List[AntiVirusHost] = []
        self.retry_period: int = 0
        self.check_completion_interval: float = 0.0

    def start(self) -> None:
        products = self.config["av_config"].get("products", [])
        self.retry_period = self.config.get("retry_period", DEFAULT_WAIT_TIME_BETWEEN_RETRIES)
        self.check_completion_interval = self.config.get("check_completion_interval", DEFAULT_WAIT_TIME_BETWEEN_COMPLETION_CHECKS) / 1000  # Converting to seconds
        if len(products) < 1:
            raise ValueError(f"There does not appear to be any products loaded in the 'products' config "
                             f"variable in the service configurations.")
        self.hosts = self._get_hosts(products)
        if len(self.hosts) < 1:
            raise ValueError(f"There does not appear to be any hosts loaded in the 'products' config "
                             f"variable in the service configurations.")

    def execute(self, request: ServiceRequest) -> None:
        global av_hit_result_sections
        # Reset globals for each request
        av_hit_result_sections = []

        request.result = Result()
        max_workers = len(self.hosts)
        AntiVirus._determine_service_context(request, self.hosts)
        selected_hosts = AntiVirus._determine_hosts_to_use(self.hosts)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self._thr_process_file, host, request.file_name, request.file_contents)
                for host in selected_hosts
            ]
            while not all(future.done() for future in futures):
                sleep(self.check_completion_interval)

        AntiVirus._gather_results(selected_hosts, av_hit_result_sections, request.result)

    @staticmethod
    def _get_hosts(products: List[Dict[str, Any]]) -> List[AntiVirusHost]:
        """
        This method creates a list of AntiVirusHost class instances for each entry in the
        service_manifest.yaml
        @param products: A list of product entries from the service manifest
        @return: A list of AntiVirusHost class instances
        """
        return [
            AntiVirusHost(
                product["product"], host["ip"], host["port"], host["method"], host["update_period"], host.get("endpoint")
            )
            for product in products for host in product["hosts"]
        ]

    def _thr_process_file(self, host: AntiVirusHost, file_name: str, file_contents: bytes) -> None:
        """
        This method handles the file scanning and result parsing
        @param host: The class instance representing an antivirus product
        @param file_name: The name of the file to scan
        @param file_contents: The contents of the file to scan
        @return: None
        """
        global av_version_result_sections
        global av_hit_result_sections

        # Step 1: Scan file
        result, version, host = self._scan_file(host, file_name, file_contents)

        # Step 2: Parse results
        av_version = self._parse_version(version) if version is not None else None
        av_hit_result_section = self._parse_result(result, host.method, host.group, av_version) if result is not None else None

        # Step 3: Add parsed results to result section lists
        if av_hit_result_section is not None:
            av_hit_result_sections.append(av_hit_result_section)

    def _scan_file(self, host: AntiVirusHost, file_name: str, file_contents: bytes)\
            -> (Optional[str], Optional[str], AntiVirusHost):
        """
        This method scans the file and could get the product version using the host's client
        @param host: The class instance representing an antivirus product
        @param file_name: The name of the file to scan
        @param file_contents: The contents of the file to scan
        @return: The results from scanning the file, the results from querying the product version,
        the AntiVirusHost instance
        """
        results: Optional[str] = None
        version: Optional[str] = None
        if host.method == ICAP_METHOD and host:
            try:
                version = host.client.options_respmod()
                results = host.client.scan_data(file_contents, file_name)
            except Exception as e:
                self.log.warning(f"{host.group} timed out due to {safe_str(e)}. Going to sleep for {self.retry_period}s.")
                Thread(target=host.sleep, args=[self.retry_period]).start()
        elif host.method == HTTP_METHOD:
            # TODO
            pass
        return results, version, host

    @staticmethod
    def _parse_result(av_results: str, av_method: str, av_name: str, av_version: Optional[str]) -> Optional[AvHitSection]:
        """
        This method sends the results to the appropriate parser based on the method
        @param av_results: The results of scanning the file
        @param av_method: The method in which the file was scanned
        @param av_name: The name of the antivirus product
        @param av_version: A string detailing the version of the antivirus product, if applicable
        @result: An AvHitSection detailing the results of the scan, if applicable
        """
        if av_method == ICAP_METHOD:
            return AntiVirus._parse_icap_results(av_results, av_name, av_version)
        elif av_method == HTTP_METHOD:
            return AntiVirus._parse_http_results(av_results, av_name)

    @staticmethod
    def _parse_version(version_result: str) -> Optional[str]:
        """
        This method parses the response of the version request
        @param version_result: The response of the version request
        @return: A string detailing the version of the antivirus product, if applicable
        """
        version: Optional[str] = None
        for line in version_result.splitlines():
            if any(line.startswith(item) for item in ['Server:', 'Service:']):
                version = line[line.index(':')+1:].strip()
                break
        return version

    @staticmethod
    def _parse_icap_results(icap_results: str, av_name: str, av_version: Optional[str]) -> Optional[AvHitSection]:
        """
        This method parses the results of the ICAP response from scanning the file
        @param icap_results: The results of scanning the file, from the ICAP server
        @param av_name: The name of the antivirus product
        @param av_version: A string detailing the version of the antivirus product, if applicable
        @return: An AvHitSection detailing the results of the scan, if applicable
        """
        virus_name: Optional[str] = None
        result_lines = icap_results.strip().splitlines()
        if len(result_lines) <= 3 and "204" not in result_lines[0]:
            raise Exception(f'Invalid result from ICAP server: {safe_str(str(icap_results))}')

        xvirus_key = 'X-Virus-ID:'
        for line in result_lines:
            if line.startswith(xvirus_key):
                virus_name = line[len(xvirus_key):].strip()
                break

        if virus_name and "HEUR:" in virus_name:
            virus_name = virus_name.replace("HEUR:", "")
            return AvHitSection(av_name, av_version, virus_name, {}, 2)
        elif virus_name:
            return AvHitSection(av_name, av_version, virus_name, {}, 1)

    @staticmethod
    def _parse_http_results(http_results: str, av_name: str) -> Optional[AvHitSection]:
        """
        This method parses the results of the HTTP response from scanning the file
        @param http_results: The results of scanning the file, from the HTTP server
        @param av_name: The name of the antivirus product
        @return: An AvHitSection detailing the results of the scan, if applicable
        """
        # TODO
        pass

    @staticmethod
    def _gather_results(hosts: List[AntiVirusHost], hit_result_sections: List[AvHitSection], result: Result) -> None:
        """
        This method puts the ResultSections and AvHitSections together into the Result object
        @param hosts: A list of AntiVirusHost class instances
        @param hit_result_sections: A list of AvHitSections detailing the results from the antivirus product
        @param result: The Result object that the ResultSections will go into
        @return: None
        """
        # If no AV hit ResultSections, do nothing
        if len(hit_result_sections) < 1:
            return

        for result_section in hit_result_sections:
            result.add_section(result_section)
        if len(hit_result_sections) < len(hosts):
            no_result_hosts = [host.group for result_section in hit_result_sections
                               for host in hosts if host.group not in result_section.body]
            no_threat_sec = ResultSection("Failed to Scan or No Threat Detected by AV Engine(s)",
                                          body_format=BODY_FORMAT.KEY_VALUE,
                                          body=json.dumps(dict(no_threat_detected=[host for host in no_result_hosts])))
            result.add_section(no_threat_sec)

    @staticmethod
    def _determine_service_context(request: ServiceRequest, hosts: List[AntiVirusHost]) -> None:
        """
        This method determines the service context based on the following logic:
        Since we are not able to get the definition times via AV products, we will use the user-provided
        update polling period as a benchmark for the service context. We will take the current time in seconds and
        determine a time range where at least one AV update has occurred
        @param request: The ServiceRequest which we will be setting the service context for
        @param hosts: A list of AntivirusHost class instances
        @return: None
        """
        min_update_period = min([host.update_period for host in hosts]) * 60  # Convert to seconds
        current_epoch_time = int(time())
        floor_of_epoch_multiples = floor(current_epoch_time/min_update_period)
        lower_range = floor_of_epoch_multiples * min_update_period
        upper_range = lower_range + min_update_period
        request.set_service_context(f"Engine Update Range: {epoch_to_local(lower_range)} - {epoch_to_local(upper_range)}")

    @staticmethod
    def _determine_hosts_to_use(hosts: List[AntiVirusHost]) -> List[AntiVirusHost]:
        """
        This method takes a list of hosts, and determines which hosts are going to have files sent to them
        @param hosts: the list of antivirus hosts registered in the service
        @return: a list of antivirus hosts that will have files sent to them
        """
        selected_hosts: List[AntiVirusHost] = []
        groups: Set[str] = set()

        # First eliminate sleeping hosts
        hosts_that_are_awake = [host for host in hosts if not host.sleeping]

        # Next choose the first host per group
        for host in hosts_that_are_awake:
            if host.group and host.group not in groups:
                groups.add(host.group)
                selected_hosts.append(host)
            elif host.group and host.group in groups:
                # Maybe next time!
                # TODO determine queues on awake hosts in the same node set to determine which host to send a file to
                pass
            else:
                # If the host does not have a group, then we definitely want to send files to it, because this
                # indicates that the host is not part of a node set
                selected_hosts.append(host)
        return selected_hosts
