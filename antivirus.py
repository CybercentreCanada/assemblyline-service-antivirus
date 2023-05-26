import json
from abc import ABC, abstractmethod
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, wait
from copy import deepcopy
from math import floor
from os.path import getsize
from random import choice
from threading import Thread
from time import sleep, time
from typing import Any, Dict, List, Optional, Set, Union

from assemblyline.common.exceptions import RecoverableError
from assemblyline.common.isotime import epoch_to_local
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.ontology.results.antivirus import Antivirus
from assemblyline_service_utilities.common.icap import IcapClient
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase, is_recoverable_runtime_error
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultKeyValueSection
from requests import Session

ICAP_METHOD = "icap"
HTTP_METHOD = "http"
VALID_METHODS = [ICAP_METHOD, HTTP_METHOD]
POST_JSON = "json"
POST_DATA = "data"
VALID_POST_TYPES = [POST_JSON, POST_DATA]
DEFAULT_SLEEP_TIME = 60  # in seconds
DEFAULT_CONNECTION_TIMEOUT = 60  # in seconds
DEFAULT_NUMBER_OF_RETRIES = 3
CHARS_TO_STRIP = [";", ":", "=", '"']
MIN_SCAN_TIMEOUT_IN_SECONDS = 30
MIN_POST_SCAN_TIME_IN_SECONDS = 10
MAX_FILE_SIZE_IN_MEGABYTES = 100
ERROR_RESULT = "ERROR"
# If the AV product blocks the file but doesn't provide a Virus ID
NO_AV_PROVIDED = "Unknown"
# Generic ICAP response text indicating a virus was found
VIRUS_FOUND = "VirusFound"
DEFAULT_MERCY_LIMIT = 5


class AvHitSection(ResultKeyValueSection):
    """
    This class represents an Assemblyline Service ResultKeyValueSection specifically for antivirus products
    """

    def __init__(self, av_name: str, av_version: Optional[str], virus_name: str, engine: Dict[str, str],
                 heur_id: int, sig_score_revision_map: Dict[str, int], kw_score_revision_map: Dict[str, int],
                 safelist_match: List[str]) -> None:
        """
        This method initializes the AvResultSection class and performs a couple validity checks
        :param av_name: The name of the antivirus product
        :param av_version: A string detailing the version of the antivirus product, if applicable
        :param virus_name: The name of the virus, determined by the antivirus product
        :param engine: The details of the engine that detected the virus
        :param heur_id: Essentially an integer flag that indicates if the scanned file is "infected" or "suspicious"
        :param sig_score_revision_map: A dictionary containing non-safelisted signature names that have a revised score
        :param kw_score_revision_map: A dictionary containing key words that hav revised scores that should be applied
        to all signatures containing any of these keywords
        :param safelist_match: A list of antivirus vendor virus names that are determined to be safe
        :return: None
        """
        for char_to_strip in CHARS_TO_STRIP:
            virus_name = virus_name.replace(char_to_strip, "")

        super(AvHitSection, self).__init__(f"{av_name} identified the file as {virus_name}")
        self.set_item("av_name", av_name)
        self.set_item("virus_name", virus_name)
        self.set_item("scan_result", "infected" if heur_id == 1 else "suspicious")

        if engine:
            self.set_item("engine_version", engine['version'])
            self.set_item("engine_definition_time", engine['def_time'])

        if av_version:
            self.set_item("av_version", av_version)

        signature_name = f'{av_name}.{virus_name}'
        self.set_heuristic(heur_id)
        if signature_name in sig_score_revision_map:
            self.heuristic.add_signature_id(signature_name, sig_score_revision_map[signature_name])
        elif any(kw in signature_name.lower() for kw in kw_score_revision_map):
            self.heuristic.add_signature_id(
                signature_name,
                max([kw_score_revision_map[kw] for kw in kw_score_revision_map if kw in signature_name.lower()])
            )
        elif virus_name in safelist_match:
            self.heuristic.add_signature_id(signature_name, 0)
        else:
            self.heuristic.add_signature_id(signature_name)
        self.add_tag('av.virus_name', virus_name)
        if heur_id == 2:
            self.add_tag("av.heuristic", virus_name)

        # TODO: Isolate parts of X-Virus-ID/virus_name according
        # https://encyclopedia.kaspersky.com/knowledge/rules-for-naming/
        # So that we can tag more items of interest


class HostClient(ABC):
    """
    An abstract class that specifies the required methods for a host client
    """
    @abstractmethod
    def __init__(self, scan_details: Dict[str, Any], ip: str, port: int) -> None:
        """
        This method initializes the host client
        :param scan_details: A dictionary containing details required to scan a file via the client
        :param ip: The IP address where the antivirus product is listening
        :param port: The port where the antivirus product is listening
        :return: None
        """
        raise NotImplementedError

    @abstractmethod
    def get_version(self) -> Optional[str]:
        """
        This method gets the version of the antivirus product
        :return: The version of the antivirus product
        """
        raise NotImplementedError

    @abstractmethod
    def scan_data(self, file_contents: bytes, file_hash: str) -> Optional[str]:
        """
        This method sends the file contents to the antivirus product for scanning
        :param file_contents: The contents of the file to be scanned
        :param file_hash: The SHA256 hash of the file contents
        :return: The scan result from the antivirus product
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def parse_version(version_result: Optional[str], version_header: Optional[str] = None) -> Optional[str]:
        """
        This method parses the response of the version request
        :param version_result: The response of the version request
        :param version_header: The name of the header of the line in the version results that contains the antivirus
                               engine version.
        :return: A string detailing the version of the antivirus product, if applicable
        """
        raise NotImplementedError

    @abstractmethod
    def parse_scan_result(
            self,
            av_results: str,
            av_name: str,
            virus_name_header: str,
            heuristic_analysis_keys: List[str],
            av_version: Optional[str],
            sig_score_revision_map: Dict[str, int],
            kw_score_revision_map: Dict[str, int],
            safelist_match: List[str]) -> List[AvHitSection]:
        """
        This method sends the results to the appropriate parser based on the method
        :param av_results: The results of scanning the file
        :param av_name: The name of the antivirus product
        :param virus_name_header: The name of the header of the line in the results that contains the antivirus hit name
        :param heuristic_analysis_keys: A list of strings that are found in the antivirus product's signatures that
        :                               indicate that heuristic analysis caused the signature to be raised
        :param av_version: A string detailing the version of the antivirus product, if applicable
        :param sig_score_revision_map: A dictionary containing non-safelisted signature names that have a revised score
        :param kw_score_revision_map: A dictionary containing key words that hav revised scores that should be applied
        :                             to all signatures containing any of these keywords
        :param safelist_match: A list of antivirus vendor virus names that are determined to be safe
        :return: A list of AvHitSections detailing the results of the scan, if applicable
        """
        raise NotImplementedError


class IcapHostClient(HostClient):
    def __init__(self, scan_details: Dict, ip: str, port: int) -> None:
        self.scan_details = IcapScanDetails(**scan_details)
        self.client = IcapClient(
            host=ip,
            port=port,
            respmod_service=self.scan_details.scan_endpoint,
            timeout=MIN_SCAN_TIMEOUT_IN_SECONDS
        )

    def get_version(self) -> Optional[str]:
        if not self.scan_details.no_version:
            return self.client.options_respmod()
        else:
            return None

    def scan_data(self, file_contents: bytes, file_hash: str) -> Optional[str]:
        return self.client.scan_data(file_contents, file_hash)

    @staticmethod
    def parse_version(version_result: Optional[str], version_header: Optional[str] = None) -> Optional[str]:
        version: Optional[str] = None
        if not version_result:
            return version

        if version_header:
            version_headers = [version_header]
        else:
            version_headers = ['Server:', 'Service:']

        for line in version_result.splitlines():
            if any(line.startswith(item) for item in version_headers):
                version = line[line.index(':') + 1:].strip()
                break
        return version

    def parse_scan_result(
            self,
            av_results: str,
            av_name: str,
            virus_name_header: str,
            heuristic_analysis_keys: List[str],
            av_version: Optional[str],
            sig_score_revision_map: Dict[str, int],
            kw_score_revision_map: Dict[str, int],
            safelist_match: List[str]) -> List[AvHitSection]:
        global av_errors
        virus_name: Optional[str] = None
        av_hits = []

        result_lines = av_results.strip().splitlines()
        if 0 < len(result_lines) <= 3 and "204" not in result_lines[0]:
            if av_name not in av_errors:
                av_errors.append(av_name)
            raise Exception(
                f'Invalid result from {av_name} ICAP '
                f'server {self.client.host}:{self.client.port} -> {safe_str(str(av_results))}'
            )

        for line in result_lines:
            if line.startswith(virus_name_header):
                virus_name = line[len(virus_name_header) + 1:].strip()
                break

        if not virus_name:
            for line in result_lines:
                if VIRUS_FOUND in line:
                    virus_name = NO_AV_PROVIDED
                    break

        if not virus_name:
            return av_hits

        if all(char in CHARS_TO_STRIP for char in virus_name):
            virus_name = NO_AV_PROVIDED

        virus_names: Set[str] = set()
        if "," in virus_name:
            virus_names = {vname.strip() for vname in virus_name.split(",")}
        # For cases such as "Blah.blahblah (HTML)" and "Blah.blah/Generic Backdoor"
        elif " " in virus_name and (" (" not in virus_name and "Generic ".lower() not in virus_name.lower()):
            virus_names = {vname.strip() for vname in virus_name.split(" ")}
        else:
            virus_names = {virus_name}
        for virus_name in virus_names:
            av_hits.append(
                AntiVirus._handle_virus_hit_section(
                    av_name, av_version, virus_name, heuristic_analysis_keys, sig_score_revision_map,
                    kw_score_revision_map, safelist_match))
        return av_hits

    def close(self) -> None:
        """
        This method closes the IcapClient's socket connection
        :return: None
        """
        self.client.close()

    def set_timeout(self, timeout: int) -> None:
        """
        This method sets the timeout of the IcapClient's socket connections
        :param timeout: The timeout to be set
        :return: None
        """
        if isinstance(timeout, int) and timeout > 0:
            self.client.timeout = timeout

    def set_number_of_retries(self, number_of_retries: int) -> None:
        """
        This method sets the number_of_retries of the IcapClient's socket connections
        :param number_of_retries: The number_of_retries to be set
        :return: None
        """
        if isinstance(number_of_retries, int) and number_of_retries > 0:
            self.client.number_of_retries = number_of_retries


class HttpHostClient(HostClient):
    def __init__(self, scan_details: Dict, ip: str, port: int) -> None:
        self.scan_details = HttpScanDetails(**scan_details)
        self.client = Session()
        self.base_url = f"{HTTP_METHOD}://{ip}:{port}"

    def get_version(self) -> Optional[str]:
        if self.scan_details.version_endpoint:
            return self.client.get(f"{self.base_url}/{self.scan_details.version_endpoint}").text
        else:
            return None

    def scan_data(self, file_contents: bytes, _) -> Optional[str]:
        # Setting up the POST based on the user's configurations
        if self.scan_details.base64_encode:
            file_contents = b64encode(file_contents)

        scan_url = f"{self.base_url}/{self.scan_details.scan_endpoint}"
        resp = None

        if self.scan_details.post_data_type == POST_DATA:
            resp = self.client.post(scan_url, data=file_contents)
        elif self.scan_details.post_data_type == POST_JSON:
            # If we are posting to JSON, the file contents must be base64 encoded and converted to str
            file_contents = file_contents.decode(
                "utf-8") if self.scan_details.base64_encode else b64encode(file_contents).decode("utf-8")
            json_to_post = {self.scan_details.json_key_for_post: file_contents}
            resp = self.client.post(scan_url, json=json_to_post)

        if resp is not None and self.scan_details.result_in_headers:
            return json.dumps(dict(resp.headers))
        elif resp is not None and not self.scan_details.result_in_headers:
            return resp.text
        else:
            return None

    @staticmethod
    def parse_version(version_result: Optional[str]) -> Optional[str]:
        if version_result:
            return safe_str(version_result)
        else:
            return None

    def parse_scan_result(
            self,
            av_results: str,
            av_name: str,
            virus_name_header: str,
            heuristic_analysis_keys: List[str],
            av_version: Optional[str],
            sig_score_revision_map: Dict[str, int],
            kw_score_revision_map: Dict[str, int],
            safelist_match: List[str]) -> List[AvHitSection]:
        http_results_as_json = json.loads(av_results)
        av_hits = []
        product_name = av_name
        if http_results_as_json.get(virus_name_header):
            virus_name = http_results_as_json[virus_name_header]
            # If there is more than one signature returned, let's grab all of them
            # The assumption here is that antivirus providers will
            # return a virus name of the format <str> or <str>,<str>,...
            virus_names = virus_name.split(",")
            for virus_name in virus_names:
                virus_name = virus_name.strip()
                # The assumption here is that antivirus providers will return a
                # virus name of the format <av_name>:<virus_name>
                temp_av_name = None
                heur_analysis = False
                if any(heuristic_analysis_key in virus_name for heuristic_analysis_key in heuristic_analysis_keys):
                    heur_analysis = True
                    for heuristic_analysis_key in heuristic_analysis_keys:
                        virus_name = virus_name.replace(heuristic_analysis_key, "")
                if ":" in virus_name:
                    temp_av_name, virus_name = virus_name.split(":")
                    temp_av_name = temp_av_name.strip()
                    virus_name = virus_name.strip()
                av_name = temp_av_name if temp_av_name else product_name
                if heur_analysis:
                    av_hits.append(AvHitSection(av_name, av_version, virus_name, {}, 2, sig_score_revision_map,
                                                kw_score_revision_map, safelist_match))
                else:
                    av_hits.append(AvHitSection(av_name, av_version, virus_name, {}, 1, sig_score_revision_map,
                                                kw_score_revision_map, safelist_match))
        return av_hits


class AntiVirusHost:
    """
    This class represents the antivirus product host and how it should be interacted with
    """

    def __init__(self, group: str, ip: str, port: int, method: str, update_period: int, file_size_limit: int = 0,
                 heuristic_analysis_keys: List[str] = None, scan_details: Dict[str, Any] = None) -> None:
        """
        This method initializes the AntiVirusHost class and performs a couple of validity checks
        :param group: The name of the antivirus product
        :param ip: The IP at which the antivirus product is hosted on and is listening on
        :param port: The port at which the antivirus product is listening on
        :param method: The method with which this class should interact with the antivirus product ("icap" or "http")
        :param update_period: The number of minutes between when the product polls for updates
        :param file_size_limit: The maximum file size that an AV should accept
        :param heuristic_analysis_keys: A list of strings that are found in the antivirus product's signatures that
        indicate that heuristic analysis caused the signature to be raised
        :param scan_details: The details regarding scanning and parsing a file
        :return: None
        """
        if method not in VALID_METHODS:
            raise ValueError(f"Given method '{method}' is not one of {VALID_METHODS}.")

        if heuristic_analysis_keys is None:
            heuristic_analysis_keys = []

        self.group = group
        self.ip = ip
        self.port = port
        self.method = method
        self.update_period = update_period
        self.file_size_limit = file_size_limit
        self.heuristic_analysis_keys = heuristic_analysis_keys

        if scan_details is None:
            scan_details: Dict = {}

        if method == ICAP_METHOD:
            self.host_client = IcapHostClient(
                scan_details=scan_details,
                ip=self.ip,
                port=self.port,
            )
        else:
            self.host_client = HttpHostClient(
                scan_details=scan_details,
                ip=self.ip,
                port=self.port
            )

        self.sleeping = False
        # This will be used to increment how many times this host has let us down in a row. If the mercy counter
        # exceeds the limit, we will show it no more mercy.
        self.mercy_counter = 0

    def __eq__(self, other) -> bool:
        """
        This method verifies the equality between class instances by their attributes
        :param other: The other class instance which this class instance will be compared with
        :return: A boolean indicating if the two class instances are equal
        """
        if not isinstance(other, AntiVirusHost):
            return NotImplemented
        return self.group == other.group and self.ip == other.ip and \
            self.port == other.port and self.method == other.method and \
            self.update_period == other.update_period and self.file_size_limit == other.file_size_limit and \
            isinstance(self.host_client, type(other.host_client)) and self.sleeping == other.sleeping and \
            self.heuristic_analysis_keys == other.heuristic_analysis_keys

    def sleep(self, timeout: int) -> None:
        """
        This method raises a flag and sleeps for a given period of time. This is used for diverting submissions away
        from this host in case the host goes down
        :param timeout: The period of time (in seconds) for the method to sleep
        """
        self.sleeping = True
        sleep(timeout)
        self.sleeping = False


class IcapScanDetails:
    """
    This class contains details regarding scanning and parsing a file via ICAP
    """

    def __init__(self, virus_name_header: str = "X-Virus-ID",
                 scan_endpoint: str = "", no_version: bool = False, version_header: Optional[str] = None) -> None:
        """
        This method initializes the IcapScanDetails class
        :param virus_name_header: The name of the header of the line in the results that contains the antivirus hit name
        :param scan_endpoint: The URI endpoint at which the service is listening
                              for file contents to be submitted or OPTIONS to be queried.
        :param no_version: A boolean indicating if a product version will be returned if you query OPTIONS.
        :param version_header: The name of the header of the line in the version results that contains the antivirus
                               engine version.
        :return: None
        """
        self.virus_name_header = virus_name_header
        self.scan_endpoint = scan_endpoint
        self.no_version = no_version
        self.version_header = version_header

    def __eq__(self, other):
        """
        This method verifies the equality between class instances by their attributes
        :param other: The other class instance which this class instance will be compared with
        :return: A boolean indicating if the two class instances are equal
        """
        if not isinstance(other, IcapScanDetails):
            return NotImplemented
        return self.virus_name_header == other.virus_name_header and self.scan_endpoint == other.scan_endpoint and \
            self.no_version == other.no_version and self.version_header == other.version_header


class HttpScanDetails:
    """
    This class contains details regarding scanning and parsing a file via HTTP
    """

    def __init__(self, post_data_type: str = "data", json_key_for_post: str = "file", result_in_headers: bool = False,
                 virus_name_header: str = "X-Virus-ID", version_endpoint: str = "",
                 scan_endpoint: str = "", base64_encode: bool = False) -> None:
        """
        This method initializes the HttpScanDetails class and performs a validity check
        :param post_data_type: The format in which the file contents will be POSTed to
                               the antivirus product server (value must be one of "json" or "data").
        :param json_key_for_post: If the file contents will be POSTed to the antivirus product as the
                                  value in a JSON key-value pair, this value is the key.
        :param result_in_headers: A boolean indicating if the antivirus signature will be found in the response headers.
        :param virus_name_header: The name of the header of the line in the results that
                                  contains the antivirus hit name.
        :param version_endpoint: The URI endpoint at which the service is listening for a GET for the
                                 antivirus product service version.
        :param scan_endpoint: The URI endpoint at which the service is listening for file contents to be POSTed
                              or OPTIONS to be queried.
        :param base64_encode: A boolean indicating if the file contents should be base64 encoded prior to being
                              POSTed to the antivirus product server.
        :return: None
        """
        if post_data_type not in VALID_POST_TYPES:
            raise ValueError(f"Given data type for POST '{post_data_type}' is not one of {VALID_POST_TYPES}.")

        self.post_data_type = post_data_type
        self.json_key_for_post = json_key_for_post
        self.result_in_headers = result_in_headers
        self.virus_name_header = virus_name_header
        self.version_endpoint = version_endpoint
        self.scan_endpoint = scan_endpoint
        self.base64_encode = base64_encode

    def __eq__(self, other):
        """
        This method verifies the equality between class instances by their attributes
        :param other: The other class instance which this class instance will be compared with
        :return: A boolean indicating if the two class instances are equal
        """
        if not isinstance(other, HttpScanDetails):
            return NotImplemented
        return self.post_data_type == other.post_data_type and self.base64_encode == other.base64_encode and \
            self.result_in_headers == other.result_in_headers and \
            self.virus_name_header == other.virus_name_header and \
            self.json_key_for_post == other.json_key_for_post and \
            self.version_endpoint == other.version_endpoint and self.scan_endpoint == other.scan_endpoint


# TODO: This is here until we phase out the use of Python 3.7 (https://github.com/python/cpython/pull/9844)
# Then we can put type hinting in the execute() method
# Global variables
av_hit_result_sections: List[AvHitSection] = []
av_errors: List[str] = []


class AntiVirus(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(AntiVirus, self).__init__(config)
        self.log.debug("Initializing the AntiVirus service...")
        self.hosts: List[AntiVirusHost] = []
        self.sleep_time: int = 0
        self.connection_timeout: int = 0
        self.number_of_retries: int = 0
        self.mercy_limit: int = 0
        self.sleep_on_version_error: bool = True
        self.safelist_match: List[str] = []
        self.kw_score_revision_map: Optional[Dict[str, int]] = None
        self.sig_score_revision_map: Optional[Dict[str, int]] = None

        try:
            safelist = self.get_api_interface().get_safelist(["av.virus_name"])
            [self.safelist_match.extend(match_list) for _, match_list in safelist.get('match', {}).items()]
        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service: {e}. Continuing without it..")

    def start(self) -> None:
        self.log.debug("Starting the AntiVirus service...")
        products = self.config["av_config"].get("products", [])
        self.kw_score_revision_map = self.config["av_config"].get("kw_score_revision_map", {})
        self.sig_score_revision_map = self.config["av_config"].get("sig_score_revision_map", {})
        self.sleep_time = self.config.get("sleep_time", DEFAULT_SLEEP_TIME)
        self.connection_timeout = self.config.get("connection_timeout", DEFAULT_CONNECTION_TIMEOUT)
        self.number_of_retries = self.config.get("number_of_retries", DEFAULT_NUMBER_OF_RETRIES)
        self.mercy_limit = self.config.get("mercy_limit", DEFAULT_MERCY_LIMIT)
        self.sleep_on_version_error = self.config.get("sleep_on_version_error", True)
        if len(products) < 1:
            raise ValueError("There does not appear to be any products loaded in the 'products' config "
                             "variable in the service configurations.")
        self.log.debug("Creating the host objects based on the provided product configurations")
        self.hosts = self._get_hosts(products)
        if len(self.hosts) < 1:
            raise ValueError("There does not appear to be any hosts loaded in the 'products' config "
                             "variable in the service configurations.")
        if self.service_attributes.timeout < MIN_SCAN_TIMEOUT_IN_SECONDS + MIN_POST_SCAN_TIME_IN_SECONDS:
            raise ValueError(f"The service timeout must be greater than or equal to "
                             f"{MIN_SCAN_TIMEOUT_IN_SECONDS + MIN_POST_SCAN_TIME_IN_SECONDS} seconds!")

        # Set the IcapClient details on start
        for host in [host for host in self.hosts if host.method == ICAP_METHOD]:
            host.host_client.set_timeout(self.connection_timeout)
            host.host_client.set_number_of_retries(self.number_of_retries)

    def execute(self, request: ServiceRequest) -> None:
        self.log.debug(f"[{request.sid}/{request.sha256}] Executing the AntiVirus service...")
        global av_hit_result_sections
        global av_errors
        # Reset globals for each request
        av_hit_result_sections = []
        av_errors = []

        request.result = Result()
        max_workers = len(self.hosts)
        self.log.debug(f"[{request.sid}/{request.sha256}] Determining the service context.")
        AntiVirus._determine_service_context(request, self.hosts)
        self.log.debug(f"[{request.sid}/{request.sha256}] Determining the hosts to use.")
        file_size = getsize(request.file_path)
        selected_hosts = AntiVirus._determine_hosts_to_use(self.hosts, file_size)
        if not selected_hosts:
            message = "All hosts are unavailable!"
            self.log.warning(f"[{request.sid}/{request.sha256}] {message}")
            raise RecoverableError(message)

        scan_timeout = AntiVirus._determine_scan_timeout_by_size(self.service_attributes.timeout, file_size)
        self.log.debug(
            f"[{request.sid}/{request.sha256}] Using the ThreadPoolExecutor to submit tasks to the thread pool")
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._thr_process_file, host, request.sha256, request.file_contents, ): host
                    for host in selected_hosts
                }
                self.log.debug(
                    f"[{request.sid}/{request.sha256}] {len(selected_hosts)} tasks have been submitted to "
                    f"the thread pool with a scan timeout of {scan_timeout}s.")
                sets = wait(futures, timeout=scan_timeout)
                for future in sets.not_done:
                    host = futures[future]
                    self.log.warning(
                        f"[{request.sid}/{request.sha256}] {host.group} host {host.ip}:{host.port} was "
                        f"unable to complete in {scan_timeout}s.")
                    host.mercy_counter += 1
                    if host.method == ICAP_METHOD:
                        if host.group not in av_errors:
                            av_errors.append(host.group)
                        host.host_client.close()

                    # NO MERCY
                    if host.mercy_counter > self.mercy_limit:
                        self.log.warning(
                            f"{host.group} host {host.ip}:{host.port} errored for the {host.mercy_counter}th time in a row. Going to sleep for {self.sleep_time}s.")
                        Thread(target=host.sleep, args=[self.sleep_time]).start()

                # Reset the mercy counter on a successful run
                for future in sets.done:
                    host = futures[future]
                    host.mercy_counter = 0
                    # If there is an exception in a thread pool submitter, we will find out with this call
                    future.result()

        except Exception as e:
            if not is_recoverable_runtime_error(e):
                message = f"[{request.sid}/{request.sha256}] Thread pool error: {e}"
                self.log.error(message)
            else:
                raise

        self.log.debug(f"[{request.sid}/{request.sha256}] Checking if any virus names should be safelisted")
        for result_section in av_hit_result_sections[:]:
            if all(virus_name in self.safelist_match for virus_name in result_section.tags["av.virus_name"]):
                av_hit_result_sections.remove(result_section)

        self.log.debug(
            f"[{request.sid}/{request.sha256}] Adding the {len(av_hit_result_sections)} AV hit "
            "result sections to the Result")
        AntiVirus._gather_results(selected_hosts, av_hit_result_sections, av_errors, request.result)
        data = AntiVirus._preprocess_ontological_result(request.result.sections)
        [self.ontology.add_result_part(Antivirus, d) for d in data]
        self.log.debug(f"[{request.sid}/{request.sha256}] Completed execution!")

    def stop(self) -> None:
        self.log.debug("Stopping the AntiVirus service...")
        # Close all ICAP connections
        for host in self.hosts:
            if host.method == ICAP_METHOD:
                host.host_client.close()

    @staticmethod
    def _get_hosts(products: List[Dict[str, Any]]) -> List[AntiVirusHost]:
        """
        This method creates a list of AntiVirusHost class instances for each entry in the
        service_manifest.yaml
        :param products: A list of product entries from the service manifest
        :return: A list of AntiVirusHost class instances
        """
        # Check if products have the same name
        unique_product_names = set()
        for product in products:
            unique_product_names.add(product["product"])
        if len(products) > len(unique_product_names):
            raise ValueError(f"There are {len(products)} products but only {len(unique_product_names)} unique "
                             f"product names. Please rename the duplicate antivirus product to something unique, or "
                             f"add it as an additional host to another product.")

        return [
            AntiVirusHost(
                group=product["product"],
                ip=host["ip"],
                port=host["port"],
                method=host["method"],
                update_period=host["update_period"],
                file_size_limit=host.get("file_size_limit", 0),
                heuristic_analysis_keys=product.get("heuristic_analysis_keys"),
                scan_details=host.get("scan_details"),
            )
            for product in products for host in product["hosts"]
        ]

    def _thr_process_file(self, host: AntiVirusHost, file_hash: str, file_contents: bytes) -> None:
        """
        This method handles the file scanning and result parsing
        :param host: The class instance representing an antivirus product
        :param file_hash: The hash of the file to scan
        :param file_contents: The contents of the file to scan
        :return: None
        """
        global av_hit_result_sections
        global av_errors

        # Step 1: Scan file
        start_scan_time = time()
        result, version, host = self._scan_file(host, file_hash, file_contents)
        elapsed_scan_time = time() - start_scan_time
        # Step 2: Parse results
        start_parse_time = time()
        av_version = host.host_client.parse_version(
            version,
            getattr(host.host_client.scan_details, "version_header", None)
        )
        if result == ERROR_RESULT:
            av_errors.append(host.group)
            av_hits = []
        elif result is not None:
            av_hits = host.host_client.parse_scan_result(
                av_results=result,
                av_name=host.group,
                virus_name_header=host.host_client.scan_details.virus_name_header,
                heuristic_analysis_keys=host.heuristic_analysis_keys,
                av_version=av_version,
                sig_score_revision_map=self.sig_score_revision_map,
                kw_score_revision_map=self.kw_score_revision_map,
                safelist_match=self.safelist_match
            )
        else:
            av_hits = []

        elapsed_parse_time = time() - start_parse_time
        self.log.debug(
            f"{host.group} {host.ip}:{host.port} Time elapsed for scanning: {elapsed_scan_time}s; "
            f"Time elapsed for parsing: {elapsed_parse_time}s")

        # Step 3: Add parsed results to result section lists
        for av_hit in av_hits:
            av_hit_result_sections.append(av_hit)

    def _scan_file(self, host: AntiVirusHost, file_hash: str,
                   file_contents: bytes) -> Union[Optional[str], Optional[str], AntiVirusHost]:
        """
        This method scans the file and could get the product version using the host's client
        :param host: The class instance representing an antivirus product
        :param file_hash: The hash of the file to scan
        :param file_contents: The contents of the file to scan
        :return: The results from scanning the file, the results from querying the product version,
        the AntiVirusHost instance
        """
        results: Optional[str] = None
        version: Optional[str] = None

        self.log.info(f"Scanning {file_hash} on {host.group} host {host.ip}:{host.port}.")
        try:
            if not self.sleep_on_version_error:
                try:
                    version = host.host_client.get_version()
                except Exception as e:
                    # If we are unable to grab the version of the engine,
                    # this is not reason enough to stop scanning for malware
                    self.log.info(f"Unable to get the engine version due to '{e}'")
                    version = None
            else:
                version = host.host_client.get_version()

            results = host.host_client.scan_data(file_contents, file_hash)
        except Exception as e:
            self.log.warning(
                f"{host.group} host {host.ip}:{host.port} errored due to '{safe_str(e)}'. "
                f"Going to sleep for {self.sleep_time}s.")
            Thread(target=host.sleep, args=[self.sleep_time], daemon=True).start()
            results = ERROR_RESULT

        return results, version, host

    @staticmethod
    def _handle_virus_hit_section(
            av_name: str, av_version: str, virus_name: str, heuristic_analysis_keys: List[str],
            sig_score_revision_map: Dict[str, int], kw_score_revision_map: Dict[str, int],
            safelist_match: List[str]) -> None:
        """
        This method handles the creation of AvHitSections
        :param av_name: The name of the antivirus product
        :param av_version: A string detailing the version of the antivirus product, if applicable
        :param virus_name: The name of the virus, determined by the antivirus product
        :param heuristic_analysis_keys: A list of strings that are found in the antivirus product's signatures that
                                        indicate that heuristic analysis caused the signature to be raised
        :param sig_score_revision_map: A dictionary containing non-safelisted signature names that have a revised score
        :param kw_score_revision_map: A dictionary containing key words that hav revised scores that should be applied
        to all signatures containing any of these keywords
        :param safelist_match: A list of antivirus vendor virus names that are determined to be safe
        :return: None
        """
        heur_analysis = False
        if any(heuristic_analysis_key in virus_name for heuristic_analysis_key in heuristic_analysis_keys):
            heur_analysis = True
            for heuristic_analysis_key in heuristic_analysis_keys:
                virus_name = virus_name.replace(heuristic_analysis_key, "")
        if heur_analysis:
            return AvHitSection(
                av_name, av_version, virus_name, {},
                2, sig_score_revision_map, kw_score_revision_map, safelist_match)
        else:
            return AvHitSection(
                av_name, av_version, virus_name, {},
                1, sig_score_revision_map, kw_score_revision_map, safelist_match)

    @staticmethod
    def _gather_results(
            hosts: List[AntiVirusHost],
            hit_result_sections: List[AvHitSection],
            av_errors: List[str],
            result: Result) -> None:
        """
        This method puts the ResultSections and AvHitSections together into the Result object
        :param hosts: A list of AntiVirusHost class instances
        :param hit_result_sections: A list of AvHitSections detailing the results from the antivirus product
        :param av_errors: A list of host groups that errored during the scan
        :param result: The Result object that the ResultSections will go into
        :return: None
        """
        # If no AV hit ResultSections, do nothing
        if len(hit_result_sections) < 1 and not av_errors:
            return

        for result_section in hit_result_sections:
            result.add_section(result_section)
        if len(hit_result_sections) < len(hosts):
            host_groups = [host.group for host in hosts]
            no_result_hosts = [host_group for host_group in host_groups if host_group not in av_errors and not any(
                host_group in result_section.body for result_section in hit_result_sections)]
            no_threat_sec = ResultKeyValueSection("Failed to Scan or No Threat Detected by AV Engine(s)")
            if no_result_hosts:
                no_threat_sec.set_item("no_threat_detected", [host for host in no_result_hosts])
            if av_errors:
                no_threat_sec.set_item("errors_during_scanning", [host for host in av_errors])
            result.add_section(no_threat_sec)

    @staticmethod
    def _determine_service_context(request: ServiceRequest, hosts: List[AntiVirusHost]) -> None:
        """
        This method determines the service context based on the following logic:
        Since we are not able to get the definition times via AV products, we will use the user-provided
        update polling period as a benchmark for the service context. We will take the current time in seconds and
        determine a time range where at least one AV update has occurred
        :param request: The ServiceRequest which we will be setting the service context for
        :param hosts: A list of AntivirusHost class instances
        :return: None
        """
        min_update_period = min([host.update_period for host in hosts]) * 60  # Convert to seconds
        current_epoch_time = int(time())
        floor_of_epoch_multiples = floor(current_epoch_time/min_update_period)
        lower_range = floor_of_epoch_multiples * min_update_period
        upper_range = lower_range + min_update_period
        request.set_service_context(
            f"Engine Update Range: {epoch_to_local(lower_range)} - {epoch_to_local(upper_range)}")

    @staticmethod
    def _determine_hosts_to_use(hosts: List[AntiVirusHost], file_size: int) -> List[AntiVirusHost]:
        """
        This method takes a list of hosts, and determines which hosts are going to have files sent to them
        :param hosts: the list of antivirus hosts registered in the service
        :param file_size: the size of the file in bytes
        :return: a list of antivirus hosts that will have files sent to them
        """
        selected_hosts: List[AntiVirusHost] = []
        groups: Set[str] = set()

        # First eliminate sleeping hosts
        hosts_that_are_awake = [host for host in hosts if not host.sleeping]

        # Second, only choose hosts that can handle the file size
        hosts_that_are_awake_and_can_handle_file_size = [
            host for host in hosts_that_are_awake if not host.file_size_limit or host.file_size_limit >= file_size]

        # Next choose a random host from the group in order to evenly distribute traffic
        groups = groups.union({host.group for host in hosts_that_are_awake_and_can_handle_file_size})
        for group in groups:
            selected_hosts.append(
                choice(
                    [host for host in hosts_that_are_awake_and_can_handle_file_size
                     if host.group == group]))
        return selected_hosts

    @staticmethod
    def _determine_scan_timeout_by_size(max_service_timeout: int, file_size: int) -> int:
        """
        This method determines the appropriate time to wait to scan a file based on its size
        :param max_service_timeout: the maximum time that we have to scan a file
        :param file_size: the size of the file in bytes
        :return: the timeout in seconds
        """
        additional_timeout = 0
        # For a file greater than 5MB, let's add another 60 seconds to the timeout
        if file_size > 5 * 1000 * 1000:
            additional_timeout = 60
        proportionality_constant = (max_service_timeout + MIN_SCAN_TIMEOUT_IN_SECONDS) / MAX_FILE_SIZE_IN_MEGABYTES
        suggested_scan_timeout = round(
            (file_size / 1000000) * proportionality_constant + additional_timeout + MIN_POST_SCAN_TIME_IN_SECONDS)
        if suggested_scan_timeout < MIN_SCAN_TIMEOUT_IN_SECONDS:
            suggested_scan_timeout = MIN_SCAN_TIMEOUT_IN_SECONDS
        elif suggested_scan_timeout > max_service_timeout:
            suggested_scan_timeout = max_service_timeout - MIN_POST_SCAN_TIME_IN_SECONDS
        return suggested_scan_timeout

    @staticmethod
    def _preprocess_ontological_result(sections: List[ResultKeyValueSection]) -> Dict[str, Any]:
        detections = []
        for section in sections:
            detection = {
                "engine_name":  None,
                "engine_version": None,
                "engine_definition_version": None,
                "category": None,
                "virus_name": None
            }
            details = section.section_body._data
            if "errors_during_scanning" in details:
                for host in details["errors_during_scanning"]:
                    failed_detection = deepcopy(detection)
                    failed_detection["engine_name"] = host
                    failed_detection["category"] = "failure"
                    detections.append(failed_detection)

            if "no_threat_detected" in details:
                for host in details["no_threat_detected"]:
                    undetected_detection = deepcopy(detection)
                    undetected_detection["engine_name"] = host
                    undetected_detection["category"] = "undetected"
                    detections.append(undetected_detection)

            if "errors_during_scanning" not in details and "no_threat_detected" not in details:
                detection["engine_name"] = details["av_name"]
                detection["engine_version"] = details.get("av_version")
                detection["engine_definition_version"] = details.get("engine_version")
                detection["category"] = "malicious" if details["scan_result"] == "infected" else details["scan_result"]
                detection["virus_name"] = details["virus_name"]
                detections.append(detection)
        return detections
