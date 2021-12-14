import json
from typing import Optional, Dict, List, Any, Set
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from time import sleep, time
from math import floor
from requests import Session
from base64 import b64encode
from re import search
from random import choice

from assemblyline.common.str_utils import safe_str
from assemblyline.common.isotime import epoch_to_local
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.icap import IcapClient
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection, BODY_FORMAT

ICAP_METHOD = "icap"
HTTP_METHOD = "http"
VALID_METHODS = [ICAP_METHOD, HTTP_METHOD]
POST_JSON = "json"
POST_DATA = "data"
VALID_POST_TYPES = [POST_JSON, POST_DATA]
DEFAULT_WAIT_TIME_BETWEEN_RETRIES = 60  # in seconds
DEFAULT_WAIT_TIME_BETWEEN_COMPLETION_CHECKS = 500  # in milliseconds
VERSION_REGEX = r"(?<=\().*?(?=\))"  # Grabs a substring found between parentheses
CHARS_TO_STRIP = [";", ":", "="]


class AntiVirusHost:
    """
    This class represents the antivirus product host and how it should be interacted with
    """
    def __init__(self, group: str, ip: str, port: int, method: str, update_period: int,
                 heuristic_analysis_keys: List[str] = None, icap_scan_details: Dict[str, Any] = None,
                 http_scan_details: Dict[str, Any] = None) -> None:
        """
        This method initializes the AntiVirusHost class and performs a couple of validity checks
        @param group: The name of the antivirus product
        @param ip: The IP at which the antivirus product is hosted on and is listening on
        @param port: The port at which the antivirus product is listening on
        @param method: The method with which this class should interact with the antivirus product (value must be one of "icap" or "http")
        @param update_period: The number of minutes between when the product polls for updates
        @param heuristic_analysis_keys: A list of strings that are found in the antivirus product's signatures that
        indicate that heuristic analysis caused the signature to be raised
        @param icap_scan_details: The details regarding scanning and parsing a file via ICAP
        @param http_scan_details: The details regarding scanning and parsing a file via HTTP
        @return: None
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
        self.heuristic_analysis_keys = heuristic_analysis_keys

        if method == ICAP_METHOD:
            if icap_scan_details is None:
                icap_scan_details = {}
            self.icap_scan_details = ICAPScanDetails(**icap_scan_details)
            self.http_scan_details = None
        elif method == HTTP_METHOD:
            if http_scan_details is None:
                http_scan_details = {}
            self.http_scan_details = HTTPScanDetails(**http_scan_details)
            self.icap_scan_details = None

        self.client = IcapClient(
            host=self.ip,
            port=self.port,
            respmod_service=self.icap_scan_details.scan_endpoint
        ) \
            if self.method == ICAP_METHOD else Session()
        self.sleeping = False

    def __eq__(self, other) -> bool:
        """
        This method verifies the equality between class instances by their attributes
        @param other: The other class instance which this class instance will be compared with
        @return: A boolean indicating if the two class instances are equal
        """
        if not isinstance(other, AntiVirusHost):
            return NotImplemented
        return self.group == other.group and self.ip == other.ip and \
               self.port == other.port and self.method == other.method and \
               self.update_period == other.update_period and self.icap_scan_details == other.icap_scan_details and \
               self.http_scan_details == other.http_scan_details and \
               type(self.client) == type(other.client) and self.sleeping == other.sleeping and \
               self.heuristic_analysis_keys == other.heuristic_analysis_keys

    def sleep(self, timeout: int) -> None:
        """
        This method raises a flag and sleeps for a given period of time. This is used for diverting submissions away
        from this host in case the host goes down
        @param timeout: The period of time (in seconds) for the method to sleep
        """
        self.sleeping = True
        sleep(timeout)
        self.sleeping = False


class ICAPScanDetails:
    """
    This class contains details regarding scanning and parsing a file via ICAP
    """
    def __init__(self, virus_name_header: str = "X-Virus-ID", scan_endpoint: str = "", no_version: bool = False) -> None:
        """
        This method initializes the ICAPScanDetails class
        @param virus_name_header: The name of the header of the line in the results that contains the antivirus hit name
        @param scan_endpoint: The URI endpoint at which the service is listening for file contents to be submitted or OPTIONS to be queried.
        @param no_version: A boolean indicating if a product version will be returned if you query OPTIONS.
        @return: None
        """
        self.virus_name_header = virus_name_header
        self.scan_endpoint = scan_endpoint
        self.no_version = no_version

    def __eq__(self, other):
        """
        This method verifies the equality between class instances by their attributes
        @param other: The other class instance which this class instance will be compared with
        @return: A boolean indicating if the two class instances are equal
        """
        if not isinstance(other, ICAPScanDetails):
            return NotImplemented
        return self.virus_name_header == other.virus_name_header and self.scan_endpoint == other.scan_endpoint


class HTTPScanDetails:
    """
    This class contains details regarding scanning and parsing a file via HTTP
    """
    def __init__(self, post_data_type: str = "data", json_key_for_post: str = "file", result_in_headers: bool = False,
                 via_proxy: bool = False, virus_name_header: str = "X-Virus-ID", version_endpoint: str = "",
                 scan_endpoint: str = "", base64_encode: bool = False) -> None:
        """
        This method initializes the HTTPScanDetails class and performs a validity check
        @param post_data_type: The format in which the file contents will be POSTed to the antivirus product server (value must be one of "json" or "data").
        @param json_key_for_post: If the file contents will be POSTed to the antivirus product as the value in a JSON key-value pair, this value is the key.
        @param result_in_headers: A boolean indicating if the antivirus signature will be found in the response headers.
        @param via_proxy: A boolean indicating if the antivirus product service is a proxy. This is used to grab the antivirus product service version from the response headers.
        @param virus_name_header: The name of the header of the line in the results that contains the antivirus hit name.
        @param version_endpoint: The URI endpoint at which the service is listening for a GET for the antivirus product service version.
        @param scan_endpoint: The URI endpoint at which the service is listening for file contents to be POSTed or OPTIONS to be queried.
        @param base64_encode: A boolean indicating if the file contents should be base64 encoded prior to being POSTed to the antivirus product server.
        @return: None
        """
        if post_data_type not in VALID_POST_TYPES:
            raise ValueError(f"Given data type for POST '{post_data_type}' is not one of {VALID_POST_TYPES}.")

        self.post_data_type = post_data_type
        self.json_key_for_post = json_key_for_post
        self.result_in_headers = result_in_headers
        self.via_proxy = via_proxy
        self.virus_name_header = virus_name_header
        self.version_endpoint = version_endpoint
        self.scan_endpoint = scan_endpoint
        self.base64_encode = base64_encode

    def __eq__(self, other):
        """
        This method verifies the equality between class instances by their attributes
        @param other: The other class instance which this class instance will be compared with
        @return: A boolean indicating if the two class instances are equal
        """
        if not isinstance(other, HTTPScanDetails):
            return NotImplemented
        return self.post_data_type == other.post_data_type and self.base64_encode == other.base64_encode and \
               self.result_in_headers == other.result_in_headers and self.via_proxy == other.via_proxy and \
               self.virus_name_header == other.virus_name_header and \
               self.json_key_for_post == other.json_key_for_post and \
               self.version_endpoint == other.version_endpoint and self.scan_endpoint == other.scan_endpoint


class AvHitSection(ResultSection):
    """
    This class represents an Assemblyline Service ResultSection specifically for antivirus products
    """
    def __init__(self, av_name: str, av_version: Optional[str], virus_name: str, engine: Dict[str, str],
                 heur_id: int, sig_score_revision_map: Dict[str, int], kw_score_revision_map: Dict[str, int],
                 safelist_match: List[str]) -> None:
        """
        This method initializes the AvResultSection class and performs a couple validity checks
        @param av_name: The name of the antivirus product
        @param av_version: A string detailing the version of the antivirus product, if applicable
        @param virus_name: The name of the virus, determined by the antivirus product
        @param engine: The details of the engine that detected the virus
        @param heur_id: Essentially an integer flag that indicates if the scanned file is "infected" or "suspicious"
        @param sig_score_revision_map: A dictionary containing non-safelisted signature names that have a revised score
        @param kw_score_revision_map: A dictionary containing key words that hav revised scores that should be applied
        to all signatures containing any of these keywords
        @param safelist_match: A list of antivirus vendor virus names that are determined to be safe
        @return: None
        """
        for char_to_strip in CHARS_TO_STRIP:
            virus_name = virus_name.replace(char_to_strip, "")

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
        if signature_name in sig_score_revision_map:
            section_heur.add_signature_id(signature_name, sig_score_revision_map[signature_name])
        elif any(kw in signature_name.lower() for kw in kw_score_revision_map):
            section_heur.add_signature_id(
                signature_name,
                max([kw_score_revision_map[kw] for kw in kw_score_revision_map if kw in signature_name.lower()])
            )
        elif virus_name in safelist_match:
            section_heur.add_signature_id(signature_name, 0)
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
        self.safelist_match: List[str] = []
        self.kw_score_revision_map: Optional[Dict[str, int]] = None
        self.sig_score_revision_map: Optional[Dict[str, int]] = None

        try:
            safelist = self.get_api_interface().get_safelist(["av.virus_name"])
            [self.safelist_match.extend(match_list) for _, match_list in safelist.get('match', {}).items()]
        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service: {e}. Continuing without it..")

    def start(self) -> None:
        products = self.config["av_config"].get("products", [])
        self.kw_score_revision_map = self.config["av_config"].get("kw_score_revision_map", {})
        self.sig_score_revision_map = self.config["av_config"].get("sig_score_revision_map", {})
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
                executor.submit(self._thr_process_file, host, request.sha256, request.file_contents)
                for host in selected_hosts
            ]
            while not all(future.done() for future in futures):
                sleep(self.check_completion_interval)

        for result_section in av_hit_result_sections[:]:
            if all(virus_name in self.safelist_match for virus_name in result_section.tags["av.virus_name"]):
                av_hit_result_sections.remove(result_section)

        AntiVirus._gather_results(selected_hosts, av_hit_result_sections, request.result)

    @staticmethod
    def _get_hosts(products: List[Dict[str, Any]]) -> List[AntiVirusHost]:
        """
        This method creates a list of AntiVirusHost class instances for each entry in the
        service_manifest.yaml
        @param products: A list of product entries from the service manifest
        @return: A list of AntiVirusHost class instances
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
                product["product"], host["ip"], host["port"], host["method"], host["update_period"], product.get("heuristic_analysis_keys"), host.get("icap_scan_details"), host.get("http_scan_details")
            )
            for product in products for host in product["hosts"]
        ]

    def _thr_process_file(self, host: AntiVirusHost, file_hash: str, file_contents: bytes) -> None:
        """
        This method handles the file scanning and result parsing
        @param host: The class instance representing an antivirus product
        @param file_hash: The hash of the file to scan
        @param file_contents: The contents of the file to scan
        @return: None
        """
        global av_version_result_sections
        global av_hit_result_sections

        # Step 1: Scan file
        result, version, host = self._scan_file(host, file_hash, file_contents)

        # Step 2: Parse results
        av_version = self._parse_version(version, host.method) if version is not None else None
        av_hits = self._parse_result(result, host, av_version, self.sig_score_revision_map, self.kw_score_revision_map,
                                     self.safelist_match) if result is not None else []

        # Step 3: Add parsed results to result section lists
        for av_hit in av_hits:
            av_hit_result_sections.append(av_hit)

    def _scan_file(self, host: AntiVirusHost, file_hash: str, file_contents: bytes)\
            -> (Optional[str], Optional[str], AntiVirusHost):
        """
        This method scans the file and could get the product version using the host's client
        @param host: The class instance representing an antivirus product
        @param file_hash: The hash of the file to scan
        @param file_contents: The contents of the file to scan
        @return: The results from scanning the file, the results from querying the product version,
        the AntiVirusHost instance
        """
        results: Optional[str] = None
        version: Optional[str] = None
        try:
            self.log.info(f"Scanning {file_hash} on {host.group} host {host.ip}:{host.port}.")
            if host.method == ICAP_METHOD:
                version = host.client.options_respmod() if not host.icap_scan_details.no_version else None
                results = host.client.scan_data(file_contents, file_hash)
            elif host.method == HTTP_METHOD:
                base_url = f"{HTTP_METHOD}://{host.ip}:{host.port}"
                # Setting up the POST based on the user's configurations
                if host.http_scan_details.base64_encode:
                    file_contents = b64encode(file_contents)

                if host.http_scan_details.version_endpoint:
                    version = host.client.get(f"{base_url}/{host.http_scan_details.version_endpoint}").text

                scan_url = f"{base_url}/{host.http_scan_details.scan_endpoint}"
                resp = None

                if host.http_scan_details.post_data_type == POST_DATA:
                    resp = host.client.post(scan_url, data=file_contents)
                elif host.http_scan_details.post_data_type == POST_JSON:
                    # If we are posting to JSON, the file contents must be base64 encoded and converted to str
                    file_contents = file_contents.decode("utf-8") if host.http_scan_details.base64_encode else b64encode(file_contents).decode("utf-8")
                    json_to_post = {host.http_scan_details.json_key_for_post: file_contents}
                    resp = host.client.post(scan_url, json=json_to_post)

                if host.http_scan_details.via_proxy:
                    # Remove the host IP from this header
                    via_header = resp.headers.get("Via")
                    if via_header:
                        version = search(VERSION_REGEX, via_header).group(0)

                if resp is not None and host.http_scan_details.result_in_headers:
                    results = json.dumps(dict(resp.headers))
                elif resp is not None and not host.http_scan_details.result_in_headers:
                    results = resp.text
        except Exception as e:
            self.log.info(f"{host.group} errored due to {safe_str(e)}. Going to sleep for {self.retry_period}s.")
            Thread(target=host.sleep, args=[self.retry_period]).start()
        return results, version, host

    @staticmethod
    def _parse_result(av_results: str, host: AntiVirusHost, av_version: Optional[str],
                      sig_score_revision_map: Dict[str, int], kw_score_revision_map: Dict[str, int],
                      safelist_match: List[str]) -> List[AvHitSection]:
        """
        This method sends the results to the appropriate parser based on the method
        @param av_results: The results of scanning the file
        @param host: The class instance representing an antivirus product
        @param av_version: A string detailing the version of the antivirus product, if applicable
        @param sig_score_revision_map: A dictionary containing non-safelisted signature names that have a revised score
        @param kw_score_revision_map: A dictionary containing key words that hav revised scores that should be applied
        to all signatures containing any of these keywords
        @param safelist_match: A list of antivirus vendor virus names that are determined to be safe
        @result: A list of AvHitSections detailing the results of the scan, if applicable
        """
        if host.method == ICAP_METHOD:
            return AntiVirus._parse_icap_results(av_results, host.group, host.icap_scan_details.virus_name_header,
                                                 host.heuristic_analysis_keys, av_version, sig_score_revision_map,
                                                 kw_score_revision_map, safelist_match)
        elif host.method == HTTP_METHOD:
            return AntiVirus._parse_http_results(av_results, host.group, host.http_scan_details.virus_name_header,
                                                 host.heuristic_analysis_keys, av_version, sig_score_revision_map,
                                                 kw_score_revision_map, safelist_match)
        else:
            return []

    @staticmethod
    def _parse_version(version_result: str, method: str) -> Optional[str]:
        """
        This method parses the response of the version request
        @param version_result: The response of the version request
        @param method: The method with which this class should interact with the antivirus product
        @return: A string detailing the version of the antivirus product, if applicable
        """
        version: Optional[str] = None
        if method == ICAP_METHOD:
            for line in version_result.splitlines():
                if any(line.startswith(item) for item in ['Server:', 'Service:']):
                    version = line[line.index(':') + 1:].strip()
                    break
        elif method == HTTP_METHOD:
            version = safe_str(version_result)
        return version

    @staticmethod
    def _parse_icap_results(icap_results: str, av_name: str, virus_name_header: str, heuristic_analysis_keys: List[str],
                            av_version: Optional[str], sig_score_revision_map: Dict[str, int],
                            kw_score_revision_map: Dict[str, int], safelist_match: List[str]) -> List[AvHitSection]:
        """
        This method parses the results of the ICAP response from scanning the file
        @param icap_results: The results of scanning the file, from the ICAP server
        @param av_name: The name of the antivirus product
        @param virus_name_header: The name of the header of the line in the results that contains the antivirus hit name
        @param heuristic_analysis_keys: A list of strings that are found in the antivirus product's signatures that
        indicate that heuristic analysis caused the signature to be raised@param av_version: A string detailing the version of the antivirus product, if applicable
        @param av_version: A string detailing the version of the antivirus product, if applicable
        @param sig_score_revision_map: A dictionary containing non-safelisted signature names that have a revised score
        @param kw_score_revision_map: A dictionary containing key words that hav revised scores that should be applied
        to all signatures containing any of these keywords
        @param safelist_match: A list of antivirus vendor virus names that are determined to be safe
        @return: A list of AvHitSections detailing the results of the scan, if applicable
        """
        virus_name: Optional[str] = None
        av_hits = []
        result_lines = icap_results.strip().splitlines()
        if len(result_lines) <= 3 and "204" not in result_lines[0]:
            raise Exception(f'Invalid result from ICAP server: {safe_str(str(icap_results))}')

        for line in result_lines:
            if line.startswith(virus_name_header):
                virus_name = line[len(virus_name_header) + 1:].strip()
                break

        if not virus_name:
            return av_hits

        heur_analysis = False
        if any(heuristic_analysis_key in virus_name for heuristic_analysis_key in heuristic_analysis_keys):
            heur_analysis = True
            for heuristic_analysis_key in heuristic_analysis_keys:
                virus_name = virus_name.replace(heuristic_analysis_key, "")
        if heur_analysis:
            av_hits.append(AvHitSection(av_name, av_version, virus_name, {}, 2, sig_score_revision_map, kw_score_revision_map, safelist_match))
        else:
            av_hits.append(AvHitSection(av_name, av_version, virus_name, {}, 1, sig_score_revision_map, kw_score_revision_map, safelist_match))
        return av_hits

    @staticmethod
    def _parse_http_results(http_results: str, av_name: str, virus_name_header: str,
                            heuristic_analysis_keys: List[str], av_version: Optional[str],
                            sig_score_revision_map: Dict[str, int], kw_score_revision_map: Dict[str, int],
                            safelist_match: List[str]) -> List[AvHitSection]:
        """
        This method parses the results of the HTTP response from scanning the file
        @param http_results: The results of scanning the file, from the HTTP server
        @param av_name: The name of the antivirus product
        @param virus_name_header: The name of the header of the line in the results that contains the antivirus hit name
        @param heuristic_analysis_keys: A list of strings that are found in the antivirus product's signatures that
        indicate that heuristic analysis caused the signature to be raised
        @param av_version: A string detailing the version of the antivirus product, if applicable
        @param sig_score_revision_map: A dictionary containing non-safelisted signature names that have a revised score
        @param kw_score_revision_map: A dictionary containing key words that hav revised scores that should be applied
        to all signatures containing any of these keywords
        @param safelist_match: A list of antivirus vendor virus names that are determined to be safe
        @return: A list of AvHitSectiona detailing the results of the scan, if applicable
        """
        http_results_as_json = json.loads(http_results)
        av_hits = []
        product_name = av_name
        if http_results_as_json.get(virus_name_header):
            virus_name = http_results_as_json[virus_name_header]
            # If there is more than one signature returned, let's grab all of them
            # The assumption here is that antivirus providers will return a virus name of the format <str> or <str>,<str>,...
            virus_names = virus_name.split(",")
            for virus_name in virus_names:
                virus_name = virus_name.strip()
                # The assumption here is that antivirus providers will return a virus name of the format <av_name>:<virus_name>
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
            host_groups = [host.group for host in hosts]
            no_result_hosts = [host_group for host_group in host_groups if not any(host_group in result_section.body for result_section in hit_result_sections)]
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

        # Next choose a random host from the group in order to evenly distribute traffic
        groups = groups.union({host.group for host in hosts_that_are_awake})
        for group in groups:
            selected_hosts.append(choice([host for host in hosts_that_are_awake if host.group == group]))
        return selected_hosts
