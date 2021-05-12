import json
from typing import Optional, Dict, List, Any
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from time import sleep
from requests import Session
from socket import timeout

from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.icap import IcapClient
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection, BODY_FORMAT

ICAP_METHOD = "icap"
HTTP_METHOD = "http"
VALID_METHODS = [ICAP_METHOD, HTTP_METHOD]
DEFAULT_WAIT_TIME_BETWEEN_RETRIES = 60

# Specific signature names
REVISED_SIG_SCORE_MAP = {}

# Specific keywords found in a signature name
REVISED_KW_SCORE_MAP = {}


class AntiVirusHost:
    def __init__(self, name: str, ip: str, port: int, method: str, endpoint: str) -> None:
        if method not in VALID_METHODS:
            raise ValueError(f"Given method '{method}' is not one of {VALID_METHODS}.")

        self.name = name
        self.ip = ip
        self.port = port
        self.method = method
        self.endpoint = endpoint
        self.client = IcapClient(
            host=self.ip,
            port=self.port,
            respmod_service=self.endpoint
        ) \
            if self.method == ICAP_METHOD else Session()
        self.sleeping = False

    def __eq__(self, other):
        return self.name == other.name and self.ip == other.ip and \
               self.port == other.port and self.method == other.method and \
               self.endpoint == other.endpoint and type(self.client) == type(other.client) and \
               self.sleeping == other.sleeping

    def sleep(self, timeout: int) -> None:
        self.sleeping = True
        sleep(timeout)
        self.sleeping = False


class AvHitSection(ResultSection):
    def __init__(self, av_name: str, virus_name: str, engine: Dict[str, str], heur_id: int) -> None:
        title = f"{av_name} identified the file as {virus_name}"
        json_body = dict(
            av_name=av_name,
            virus_name=virus_name,
            scan_result="infected" if heur_id == 1 else "suspicious",
            engine_version=engine['version'] if engine else "unknown",
            engine_definition_time=engine['def_time'] if engine else "unknown",
        )

        super(AvHitSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body),
        )
        signature_name = f'{av_name.upper()}.{virus_name}'
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


class AntiVirus(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(AntiVirus, self).__init__(config)
        self.hosts: List[AntiVirusHost] = []
        self.retry_period: int = 0

    def start(self) -> None:
        av_host_details = self.config.get("av_host_details", {})
        self.retry_period = self.config.get("retry_period", DEFAULT_WAIT_TIME_BETWEEN_RETRIES)
        if len(av_host_details) < 1:
            raise ValueError(f"There does not appear to be any hosts loaded in the 'av_host_details' config "
                             f"variable in the service configurations.")
        self.hosts = self._get_hosts(av_host_details["hosts"])

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()
        max_workers = len(self.hosts)
        result_sections = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit the file to each of the hosts
            futures = [
                executor.submit(self._scan_file, host, request.file_name, request.file_contents)
                for host in self.hosts if not host.sleeping
            ]
            for future in futures:
                result, host = future.result()
                result_section = AntiVirus._parse_result(result, host.method, host.name) if result is not None else None
                if result_section is not None:
                    result_sections.append(result_section)
        AntiVirus._gather_results(self.hosts, result_sections, request.result)

    @staticmethod
    def _get_hosts(hosts: List[Dict[str, Any]]) -> List[AntiVirusHost]:
        return [AntiVirusHost(host["name"], host["ip"], host["port"], host["method"], host["endpoint"]) for host in hosts]

    def _scan_file(self, host: AntiVirusHost, file_name: str, file_contents: bytes) -> (str, AntiVirusHost):
        results = None
        if host.method == ICAP_METHOD and host:
            try:
                results = host.client.scan_data(file_contents, file_name)
            except Exception as e:
                self.log.warning(f"{host.name} timed out due to {safe_str(e)}. Going to sleep for {self.retry_period}s.")
                Thread(target=host.sleep, args=[self.retry_period]).start()
        elif host.method == HTTP_METHOD:
            # TODO
            pass
        return results, host

    @staticmethod
    def _parse_result(av_results: str, av_method: str, av_name: str) -> Optional[ResultSection]:
        if av_method == ICAP_METHOD:
            return AntiVirus._parse_icap_results(av_results, av_name)
        elif av_method == HTTP_METHOD:
            return AntiVirus._parse_http_results(av_results, av_name)

    @staticmethod
    def _parse_icap_results(icap_results: str, av_name: str) -> Optional[ResultSection]:
        virus_name = None
        result_lines = icap_results.strip().splitlines()
        if len(result_lines) <= 3:
            raise Exception(f'Invalid result from ICAP server: {safe_str(str(icap_results))}')

        xvirus_key = 'X-Virus-ID:'
        for line in result_lines:
            if line.startswith(xvirus_key):
                virus_name = line[len(xvirus_key):].strip()
                break

        if virus_name and "HEUR:" in virus_name:
            virus_name = virus_name.replace("HEUR:", "")
            return AvHitSection(av_name, virus_name, {}, 2)
        elif virus_name:
            return AvHitSection(av_name, virus_name, {}, 1)

    @staticmethod
    def _parse_http_results(http_results: str, av_name: str) -> Optional[ResultSection]:
        # TODO
        pass

    @staticmethod
    def _gather_results(hosts: List[AntiVirusHost], result_sections: List[ResultSection], result: Result):
        if len(result_sections) < 1:
            no_threat_sec = ResultSection("Failed to Scan or No Threat Detected by AV Engine(s)",
                                          body_format=BODY_FORMAT.KEY_VALUE,
                                          body=json.dumps(dict(no_threat_detected=[host.name for host in hosts])))
            result.add_section(no_threat_sec)
        else:
            for result_section in result_sections:
                result.add_section(result_section)
            if len(result_sections) < len(hosts):
                no_result_hosts = [host.name for result_section in result_sections
                                   for host in hosts if host.name not in result_section.body]
                no_threat_sec = ResultSection("Failed to Scan or No Threat Detected by AV Engine(s)",
                                              body_format=BODY_FORMAT.KEY_VALUE,
                                              body=json.dumps(dict(no_threat_detected=[host for host in no_result_hosts])))
                result.add_section(no_threat_sec)
