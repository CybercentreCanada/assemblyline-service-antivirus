import os
import json
import pytest
import shutil

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples = [
    dict(
        sid=1,
        metadata={},
        service_name='antivirus',
        service_config={},
        fileinfo=dict(
            magic='ASCII text, with no line terminators',
            md5='fda4e701258ba56f465e3636e60d36ec',
            mime='text/plain',
            sha1='af2c2618032c679333bebf745e75f9088748d737',
            sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
            size=19,
            type='unknown',
        ),
        filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        min_classification='TLP:WHITE',
        max_files=501,  # TODO: get the actual value
        ttl=3600,
    ),
]


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        heuristic_equality = this.heuristic.definition.attack_id == that.heuristic.definition.attack_id and \
                             this.heuristic.definition.classification == that.heuristic.definition.classification and \
                             this.heuristic.definition.description == that.heuristic.definition.description and \
                             this.heuristic.definition.filetype == that.heuristic.definition.filetype and \
                             this.heuristic.definition.heur_id == that.heuristic.definition.heur_id and \
                             this.heuristic.definition.id == that.heuristic.definition.id and \
                             this.heuristic.definition.max_score == that.heuristic.definition.max_score and \
                             this.heuristic.definition.name == that.heuristic.definition.name and \
                             this.heuristic.definition.score == that.heuristic.definition.score and \
                             this.heuristic.definition.signature_score_map == \
                             that.heuristic.definition.signature_score_map

        result_heuristic_equality = heuristic_equality and \
                                    this.heuristic.attack_ids == that.heuristic.attack_ids and \
                                    this.heuristic.frequency == that.heuristic.frequency and \
                                    this.heuristic.heur_id == that.heuristic.heur_id and \
                                    this.heuristic.score == that.heuristic.score and \
                                    this.heuristic.score_map == that.heuristic.score_map and \
                                    this.heuristic.signatures == that.heuristic.signatures

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
                               this.body == that.body and \
                               this.body_format == that.body_format and \
                               this.classification == that.classification and \
                               this.depth == that.depth and \
                               len(this.subsections) == len(that.subsections) and \
                               this.title_text == that.title_text and \
                               this.tags == that.tags

    if not current_section_equality:
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def antivirushost_class():
    create_tmp_manifest()
    try:
        from antivirus import AntiVirusHost
        yield AntiVirusHost
    finally:
        remove_tmp_manifest()


@pytest.fixture
def antivirus_class_instance(mocker, dummy_api_interface):
    create_tmp_manifest()
    try:
        from antivirus import AntiVirus
        mocker.patch.object(AntiVirus, "get_api_interface", return_value=dummy_api_interface)
        yield AntiVirus()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_result_class_instance():
    create_tmp_manifest()
    try:
        class DummyResult(object):
            from assemblyline_v4_service.common.result import ResultSection

            def __init__(self):
                self.sections = []

            def add_section(self, res_sec: ResultSection):
                self.sections.append(res_sec)

        return DummyResult()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_requests_class_instance():
    class DummyRequests(object):
        def __init__(self, text):
            self.text = text
            self.headers = {"Via": "(blah)"}
    return DummyRequests


@pytest.fixture
def dummy_api_interface():
    class DummyApiInterface(object):
        def __int__(self):
            pass

        @staticmethod
        def get_safelist(*args):
            return {}
    return DummyApiInterface


class TestAntiVirusHost:
    @staticmethod
    def test_init(antivirushost_class):
        from requests import Session
        from antivirus import HTTPScanDetails, ICAPScanDetails
        from assemblyline_v4_service.common.icap import IcapClient
        with pytest.raises(ValueError):
            antivirushost_class("blah", "blah", 8008, "blah", 100)

        avhost_icap_with_no_details = antivirushost_class("blah", "blah", 8008, "icap", 100)
        assert avhost_icap_with_no_details.group == "blah"
        assert avhost_icap_with_no_details.ip == "blah"
        assert avhost_icap_with_no_details.port == 8008
        assert avhost_icap_with_no_details.method == "icap"
        assert avhost_icap_with_no_details.heuristic_analysis_keys == []
        assert type(avhost_icap_with_no_details.icap_scan_details) == ICAPScanDetails
        assert avhost_icap_with_no_details.icap_scan_details.virus_name_header == "X-Virus-ID"
        assert avhost_icap_with_no_details.icap_scan_details.scan_endpoint == ""
        assert avhost_icap_with_no_details.icap_scan_details.no_version is False
        assert avhost_icap_with_no_details.http_scan_details is None
        assert avhost_icap_with_no_details.update_period == 100
        assert type(avhost_icap_with_no_details.client) == IcapClient
        assert avhost_icap_with_no_details.sleeping is False

        avhost_icap_with_details = antivirushost_class("blah", "blah", 8008, "icap", 100, icap_scan_details={"virus_name_header": "blah", "scan_endpoint": "blah", "no_version": True})
        assert avhost_icap_with_details.group == "blah"
        assert avhost_icap_with_details.ip == "blah"
        assert avhost_icap_with_details.port == 8008
        assert avhost_icap_with_details.method == "icap"
        assert avhost_icap_with_details.heuristic_analysis_keys == []
        assert type(avhost_icap_with_details.icap_scan_details) == ICAPScanDetails
        assert avhost_icap_with_details.icap_scan_details.virus_name_header == "blah"
        assert avhost_icap_with_details.icap_scan_details.scan_endpoint == "blah"
        assert avhost_icap_with_details.icap_scan_details.no_version is True
        assert avhost_icap_with_details.http_scan_details is None
        assert avhost_icap_with_details.update_period == 100
        assert type(avhost_icap_with_details.client) == IcapClient
        assert avhost_icap_with_details.sleeping is False

        avhost_http_with_no_details = antivirushost_class("blah", "blah", 8008, "http", 100, ["blah"])
        assert avhost_http_with_no_details.group == "blah"
        assert avhost_http_with_no_details.ip == "blah"
        assert avhost_http_with_no_details.port == 8008
        assert avhost_http_with_no_details.method == "http"
        assert avhost_http_with_no_details.icap_scan_details is None
        assert type(avhost_http_with_no_details.http_scan_details) == HTTPScanDetails
        assert avhost_http_with_no_details.http_scan_details.post_data_type == "data"
        assert avhost_http_with_no_details.http_scan_details.json_key_for_post == "file"
        assert avhost_http_with_no_details.http_scan_details.result_in_headers is False
        assert avhost_http_with_no_details.http_scan_details.via_proxy is False
        assert avhost_http_with_no_details.http_scan_details.virus_name_header == "X-Virus-ID"
        assert avhost_http_with_no_details.http_scan_details.version_endpoint == ""
        assert avhost_http_with_no_details.http_scan_details.scan_endpoint == ""
        assert avhost_http_with_no_details.http_scan_details.base64_encode is False

        assert avhost_http_with_no_details.update_period == 100
        assert type(avhost_http_with_no_details.client) == Session
        assert avhost_http_with_no_details.sleeping is False

        avhost_http_with_details = antivirushost_class("blah", "blah", 8008, "http", 100, ["blah"], http_scan_details={"post_data_type": "json", "json_key_for_post": "blah", "result_in_headers": True, "via_proxy": True, "virus_name_header": "blah", "version_endpoint": "blah", "scan_endpoint": "blah", "base64_encode": True})
        assert avhost_http_with_details.group == "blah"
        assert avhost_http_with_details.ip == "blah"
        assert avhost_http_with_details.port == 8008
        assert avhost_http_with_details.method == "http"
        assert avhost_http_with_details.icap_scan_details is None
        assert type(avhost_http_with_details.http_scan_details) == HTTPScanDetails
        assert avhost_http_with_details.http_scan_details.post_data_type == "json"
        assert avhost_http_with_details.http_scan_details.json_key_for_post == "blah"
        assert avhost_http_with_details.http_scan_details.result_in_headers is True
        assert avhost_http_with_details.http_scan_details.via_proxy is True
        assert avhost_http_with_details.http_scan_details.virus_name_header == "blah"
        assert avhost_http_with_details.http_scan_details.version_endpoint == "blah"
        assert avhost_http_with_details.http_scan_details.scan_endpoint == "blah"
        assert avhost_http_with_details.http_scan_details.base64_encode is True
        assert avhost_http_with_details.update_period == 100
        assert type(avhost_http_with_details.client) == Session
        assert avhost_http_with_details.sleeping is False

    @staticmethod
    def test_eq(antivirus_class_instance):
        from antivirus import AntiVirusHost
        av_host1 = AntiVirusHost("blah", "blah", 1, "http", 1)
        av_host2 = AntiVirusHost("blah", "blah", 1, "http", 1)
        av_host3 = AntiVirusHost("blah", "blah", 2, "http", 1)
        assert av_host1 == av_host2
        assert av_host1 != av_host3

    @staticmethod
    def test_sleep(antivirushost_class):
        from time import sleep
        from threading import Thread
        av_host = antivirushost_class("blah", "blah", 8008, "http", 100)
        assert av_host.sleeping is False
        Thread(target=av_host.sleep, args=[2]).start()
        assert av_host.sleeping is True
        sleep(3)
        assert av_host.sleeping is False


class TestICAPScanDetails:
    @staticmethod
    def test_init():
        from antivirus import ICAPScanDetails
        no_details = ICAPScanDetails()
        assert no_details.virus_name_header == "X-Virus-ID"
        assert no_details.scan_endpoint == ""
        assert no_details.no_version is False

        with_details = ICAPScanDetails("blah", "blah", True)
        assert with_details.virus_name_header == "blah"
        assert with_details.scan_endpoint == "blah"
        assert with_details.no_version is True

    @staticmethod
    def test_eq():
        from antivirus import ICAPScanDetails
        icap1 = ICAPScanDetails()
        icap2 = ICAPScanDetails()
        icap3 = ICAPScanDetails("blah", "blah", True)
        assert icap1 == icap2
        assert icap1 != icap3


class TestHTTPScanDetails:
    @staticmethod
    def test_init():
        from antivirus import HTTPScanDetails
        no_details = HTTPScanDetails()
        assert no_details.virus_name_header == "X-Virus-ID"
        assert no_details.post_data_type == "data"
        assert no_details.json_key_for_post == "file"
        assert no_details.result_in_headers is False
        assert no_details.via_proxy is False
        assert no_details.version_endpoint == ""
        assert no_details.scan_endpoint == ""
        assert no_details.base64_encode is False

        with_details = HTTPScanDetails("json", "blah", True, True, "blah", "blah", "blah", True)
        assert with_details.post_data_type == "json"
        assert with_details.json_key_for_post == "blah"
        assert with_details.result_in_headers is True
        assert with_details.via_proxy is True
        assert with_details.virus_name_header == "blah"
        assert with_details.version_endpoint == "blah"
        assert with_details.scan_endpoint == "blah"
        assert with_details.base64_encode is True

        with pytest.raises(ValueError):
            HTTPScanDetails("blah")

    @staticmethod
    def test_eq():
        from antivirus import HTTPScanDetails
        http1 = HTTPScanDetails()
        http2 = HTTPScanDetails()
        http3 = HTTPScanDetails("json")
        assert http1 == http2
        assert http1 != http3


class TestAvHitSection:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    def test_init():
        from json import dumps
        from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection, Heuristic
        from antivirus import AvHitSection
        av_name = "blah"
        av_version = "blah"
        virus_name = "blah"
        engine = {}
        heur_id = 1
        sig_score_rev_map = {}
        kw_score_rev_map = {}
        safelist_match = []
        actual_res_sec = AvHitSection(av_name, av_version, virus_name, engine, heur_id, sig_score_rev_map,
                                     kw_score_rev_map, safelist_match)
        correct_result_section = ResultSection(f"{av_name} identified the file as {virus_name}")
        correct_result_section.heuristic = Heuristic(1)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}")
        correct_result_section.tags = {"av.virus_name": [virus_name]}
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "infected", "av_version": av_version})
        correct_result_section.body_format = BODY_FORMAT.KEY_VALUE
        assert check_section_equality(actual_res_sec, correct_result_section)

        temp_virus_name = ";:blah="
        engine = {"version": "blah", "def_time": 1}
        heur_id = 2
        safelist_match = ["blah"]
        actual_res_sec = AvHitSection(av_name, av_version, temp_virus_name, engine, heur_id, sig_score_rev_map,
                                      kw_score_rev_map, safelist_match)
        correct_result_section.tags = {"av.virus_name": [virus_name], "av.heuristic": [f"{virus_name}"]}
        correct_result_section.heuristic = Heuristic(2)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}", 0)
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": 1, "av_version": av_version})
        assert check_section_equality(actual_res_sec, correct_result_section)

        kw_score_rev_map = {"bla": 1}
        actual_res_sec = AvHitSection(av_name, av_version, virus_name, engine, heur_id, sig_score_rev_map,
                                      kw_score_rev_map, safelist_match)
        correct_result_section.heuristic = Heuristic(2)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}", 1)
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": 1, "av_version": av_version})
        assert check_section_equality(actual_res_sec, correct_result_section)

        kw_score_rev_map = {"bla": 1, "h": 2}
        actual_res_sec = AvHitSection(av_name, av_version, virus_name, engine, heur_id, sig_score_rev_map,
                                      kw_score_rev_map, safelist_match)
        correct_result_section.heuristic = Heuristic(2)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}", 2)
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": 1, "av_version": av_version})
        assert check_section_equality(actual_res_sec, correct_result_section)

        sig_score_rev_map = {f"{av_name}.{virus_name}": 10}
        actual_res_sec = AvHitSection(av_name, av_version, virus_name, engine, heur_id, sig_score_rev_map,
                                      kw_score_rev_map, safelist_match)
        correct_result_section.heuristic = Heuristic(2)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}", 10)
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": 1, "av_version": av_version})
        assert check_section_equality(actual_res_sec, correct_result_section)


class TestAntiVirus:
    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            if os.path.exists(temp_sample_path):
                os.remove(temp_sample_path)

    @staticmethod
    def test_init(antivirus_class_instance):
        assert antivirus_class_instance.hosts == []
        assert antivirus_class_instance.retry_period == 0

    @staticmethod
    def test_start(antivirus_class_instance):
        from antivirus import AntiVirusHost
        products = [{"product": "blah", "hosts": [{"ip": "blah", "port": 1, "method": "icap", "update_period": 1}]}]
        antivirus_class_instance.config["av_config"]["products"] = products
        correct_hosts = [
            AntiVirusHost(product["product"], host["ip"], host["port"], host["method"], host["update_period"], host.get("file_size_limit", 0), product.get("heuristic_analysis_keys"), host.get("icap_scan_details"), host.get("http_scan_details"))
            for product in products for host in product["hosts"]
        ]
        antivirus_class_instance.start()
        assert antivirus_class_instance.hosts == correct_hosts
        assert antivirus_class_instance.retry_period == 60

        antivirus_class_instance.config["av_config"]["products"] = []
        with pytest.raises(ValueError):
            antivirus_class_instance.start()

        antivirus_class_instance.config["av_config"]["products"] = [{"product": "blah", "hosts": []}]
        with pytest.raises(ValueError):
            antivirus_class_instance.start()

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, antivirus_class_instance, antivirushost_class, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from antivirus import AntiVirus

        antivirus_class_instance.start()

        service_task = ServiceTask(sample)
        task = Task(service_task)
        antivirus_class_instance._task = task
        service_request = ServiceRequest(task)

        # For coverage
        service_request.task.deep_scan = True
        mocker.patch.object(AntiVirus, "_thr_process_file")
        mocker.patch.object(AntiVirus, "_gather_results")

        # Actually executing the sample
        antivirus_class_instance.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())
        f.close()

        # Assert that the appropriate sections of the dict are equal

        # Avoiding unique items in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the service_completed and the output.json supplementary
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        correct_result_response.pop("supplementary")
        test_result_response.pop("supplementary")
        correct_result_response.pop("service_context")
        test_result_response.pop("service_context")
        assert test_result_response == correct_result_response

    @staticmethod
    def test_get_hosts():
        from antivirus import AntiVirus, AntiVirusHost
        products = [{"product": "blah", "hosts": [{"ip": "localhost", "port": 1344, "icap_scan_details": {"virus_name_header": "blah", "scan_endpoint": "resp"}, "method": "icap", "update_period": 100}]}]
        correct_hosts = [AntiVirusHost(product["product"], host["ip"], host["port"], host["method"], host["update_period"], icap_scan_details=host["icap_scan_details"])
                         for product in products for host in product["hosts"]]
        assert AntiVirus._get_hosts(products) == correct_hosts

        products = [{"product": "blah", "hosts": [{"ip": "localhost", "port": 1344, "icap_scan_details": {"version_endpoint": "version", "scan_endpoint": "resp"}, "method": "icap", "update_period": 100}]}, {"product": "blah", "hosts": [{"ip": "localhost", "port": 1344, "icap_scan_details": {"version_endpoint": "version", "scan_endpoint": "resp"}, "method": "icap", "update_period": 100}]}]
        with pytest.raises(ValueError):
            AntiVirus._get_hosts(products)

    @staticmethod
    def test_thr_process_file(antivirus_class_instance, mocker):
        from antivirus import AntiVirus, AntiVirusHost, av_hit_result_sections
        avhost = AntiVirusHost("blah", "blah", 1, "icap", 1)
        mocker.patch.object(AntiVirus, "_scan_file", return_value=(None, None, avhost))
        mocker.patch.object(AntiVirus, "_parse_version", return_value=None)
        mocker.patch.object(AntiVirus, "_parse_result", return_value=[])
        antivirus_class_instance._thr_process_file(avhost, "blah", b"blah")
        assert av_hit_result_sections == []

        mocker.patch.object(AntiVirus, "_scan_file", return_value=(True, True, avhost))
        mocker.patch.object(AntiVirus, "_parse_version", return_value="blah")
        mocker.patch.object(AntiVirus, "_parse_result", return_value=["blah"])
        antivirus_class_instance._thr_process_file(avhost, "blah", b"blah")
        assert av_hit_result_sections == ["blah"]

    @staticmethod
    def test_scan_file(antivirus_class_instance, antivirushost_class, dummy_requests_class_instance, mocker):
        from socket import timeout
        from time import sleep
        from requests.sessions import Session
        from assemblyline_v4_service.common.icap import IcapClient
        from antivirus import ERROR_RESULT
        mocker.patch.object(IcapClient, "scan_data", return_value="blah")
        mocker.patch.object(IcapClient, "options_respmod", return_value="blah")
        av_host_icap = antivirushost_class("blah", "blah", 1234, "icap", 100)
        assert antivirus_class_instance._scan_file(av_host_icap, "blah", b"blah") == ("blah", "blah", av_host_icap)

        av_host_icap = antivirushost_class("blah", "blah", 1234, "icap", 100, icap_scan_details={"no_version": True})
        assert antivirus_class_instance._scan_file(av_host_icap, "blah", b"blah") == ("blah", None, av_host_icap)

        mocker.patch.object(Session, "get", return_value=dummy_requests_class_instance("blah"))
        mocker.patch.object(Session, "post", return_value=dummy_requests_class_instance("blah"))
        av_host_http = antivirushost_class("blah", "blah", 1234, "http", 100)
        assert antivirus_class_instance._scan_file(av_host_http, "blah", b"blah") == ("blah", None, av_host_http)

        av_host_http = antivirushost_class("blah", "blah", 1234, "http", 100, http_scan_details={"base64_encode": True, "version_endpoint": "blah", "post_data_type": "json", "via_proxy": True, "result_in_headers": True})
        assert antivirus_class_instance._scan_file(av_host_http, "blah", b"blah") == ('{"Via": "(blah)"}', "blah", av_host_http)

        with mocker.patch.object(IcapClient, "scan_data", side_effect=timeout):
            av_host_icap = antivirushost_class("blah", "blah", 1234, "icap", 100)
            assert av_host_icap.sleeping is False
            antivirus_class_instance.retry_period = 2
            assert antivirus_class_instance._scan_file(av_host_icap, "blah", b"blah") == (ERROR_RESULT, "blah", av_host_icap)
            assert av_host_icap.sleeping is True
            sleep(3)
            assert av_host_icap.sleeping is False

    @staticmethod
    @pytest.mark.parametrize(
        "version_result, method, correct_result",
        [
            ("", "icap", None),
            ("blah", "icap", None),
            ("Server:blah", "icap", "blah"),
            ("Service:blah", "icap", "blah"),
            ("blah", "http", "blah"),
        ]
    )
    def test_parse_version(version_result, method, correct_result, antivirus_class_instance):
        from antivirus import AntiVirus
        assert AntiVirus._parse_version(version_result, method) == correct_result

    @staticmethod
    def test_parse_result(antivirus_class_instance, mocker):
        from antivirus import AntiVirus, AntiVirusHost
        mocker.patch.object(AntiVirus, "_parse_icap_results", return_value=["blah"])
        mocker.patch.object(AntiVirus, "_parse_http_results", return_value=["blah"])
        avhost_icap = AntiVirusHost("blah", "blah", 1, "icap", 1)
        avhost_http = AntiVirusHost("blah", "blah", 1, "http", 1)
        assert AntiVirus._parse_result("blah", avhost_icap, "blah", {}, {}, []) == ["blah"]
        assert AntiVirus._parse_result("blah", avhost_http, "http", {}, {}, []) == ["blah"]
        avhost_http.method = "blah"
        assert AntiVirus._parse_result("blah", avhost_http, "http", {}, {}, []) == []

    @staticmethod
    @pytest.mark.parametrize(
        "icap_result, version, virus_name, expected_section_title, expected_tags, expected_heuristic, expected_body",
        [
            ("", "", "", "", {}, 0, {}),
            ("blah\nblah\nblah\nblah", "", "", "", {}, 0, {}),
            ("blah\nX-Virus-ID: virus_name\nblah\nblah", "blah", "virus_name", "blah identified the file as virus_name",
             {"av.virus_name": ["virus_name"]}, 1, '{"av_name": "blah", "virus_name": "virus_name", "scan_result": '
                                                   '"infected", "av_version": "blah"}'),
            ("blah\nX-Virus-ID: HEUR:virus_heur\nblah\nblah", "blah", "virus_heur", "blah identified the file as virus_heur",
             {"av.virus_name": ["virus_heur"], "av.heuristic": ["virus_heur"]}, 2,
             '{"av_name": "blah", "virus_name": "virus_heur", "scan_result": "suspicious", "av_version": "blah"}'),
        ]
    )
    def test_parse_icap_results(icap_result, version, virus_name, expected_section_title, expected_tags, expected_heuristic,
                                expected_body, antivirus_class_instance):
        from assemblyline_v4_service.common.result import ResultSection, Heuristic, BODY_FORMAT
        av_name = "blah"
        if not icap_result:
            with pytest.raises(Exception):
                antivirus_class_instance._parse_icap_results(icap_result, av_name, "X-Virus-ID:", [], version, {}, {}, [])
            return

        if not expected_section_title:
            assert antivirus_class_instance._parse_icap_results(icap_result, av_name, "X-Virus-ID:", [], version, {}, {}, []) == []
        else:
            correct_result_section = ResultSection(expected_section_title)
            correct_result_section.heuristic = Heuristic(expected_heuristic) if expected_heuristic else None
            correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}")
            correct_result_section.tags = expected_tags
            correct_result_section.body = expected_body
            correct_result_section.body_format = BODY_FORMAT.KEY_VALUE
            test_result_section = antivirus_class_instance._parse_icap_results(icap_result, av_name, "X-Virus-ID:", ["HEUR:"], version, {}, {}, [])
            assert check_section_equality(test_result_section[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "http_result, version, virus_name, expected_section_title, expected_tags, expected_heuristic, expected_body",
        [
            ("{}", "", "", "", {}, 0, {}),
            ("{\"not_detectionName\":\"blah\"}", "", "", "", {}, 0, {}),
            ("{\"detectionName\":\"virus_name\"}", "blah", "virus_name", "blah identified the file as virus_name",
             {"av.virus_name": ["virus_name"]}, 1, '{"av_name": "blah", "virus_name": "virus_name", "scan_result": '
                                                   '"infected", "av_version": "blah"}'),
            ("{\"detectionName\": \"HEUR:virus_heur\"}", "blah", "virus_heur",
             "blah identified the file as virus_heur",
             {"av.virus_name": ["virus_heur"], "av.heuristic": ["virus_heur"]}, 2,
             '{"av_name": "blah", "virus_name": "virus_heur", "scan_result": "suspicious", "av_version": "blah"}'),
        ]
    )
    def test_parse_http_results(http_result, version, virus_name, expected_section_title, expected_tags, expected_heuristic, expected_body, antivirus_class_instance):
        from assemblyline_v4_service.common.result import ResultSection, Heuristic, BODY_FORMAT
        av_name = "blah"
        if not expected_section_title:
            assert antivirus_class_instance._parse_http_results(http_result, av_name, "detectionName", [], version, {}, {}, []) == []
        else:
            correct_result_section = ResultSection(expected_section_title)
            correct_result_section.heuristic = Heuristic(expected_heuristic) if expected_heuristic else None
            correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}")
            correct_result_section.tags = expected_tags
            correct_result_section.body = expected_body
            correct_result_section.body_format = BODY_FORMAT.KEY_VALUE
            test_result_section = antivirus_class_instance._parse_http_results(http_result, av_name, "detectionName", ["HEUR:"], version, {}, {}, [])
            assert check_section_equality(test_result_section[0], correct_result_section)

    @staticmethod
    def test_gather_results(dummy_result_class_instance):
        from antivirus import AntiVirus, AntiVirusHost, AvHitSection
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        hosts = [AntiVirusHost("blah1", "blah", 1234, "icap", 1), AntiVirusHost("blah2", "blah", 1234, "icap", 1)]
        AntiVirus._gather_results(hosts, [], [], dummy_result_class_instance)
        assert dummy_result_class_instance.sections == []

        AntiVirus._gather_results(hosts, [], ["blah1", "blah2"], dummy_result_class_instance)
        no_result_section = ResultSection(
            "Failed to Scan or No Threat Detected by AV Engine(s)",
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(dict(errors_during_scanning=[host.group for host in hosts]))
        )
        assert check_section_equality(dummy_result_class_instance.sections[0], no_result_section)

        correct_av_result_section = AvHitSection("blah2", "blah", "blah", {}, 1, {}, {}, [])
        AntiVirus._gather_results(hosts, [correct_av_result_section], [], dummy_result_class_instance)
        no_result_section2 = ResultSection(
            "Failed to Scan or No Threat Detected by AV Engine(s)",
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(dict(no_threat_detected=[host.group for host in hosts[:1]]))
        )
        assert check_section_equality(dummy_result_class_instance.sections[1], correct_av_result_section)
        assert check_section_equality(dummy_result_class_instance.sections[2], no_result_section2)

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_determine_service_context(sample, antivirus_class_instance):
        from assemblyline_v4_service.common.request import ServiceRequest
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline.common.isotime import epoch_to_local
        from antivirus import AntiVirus, AntiVirusHost
        from time import time
        from math import floor
        from datetime import datetime
        service_task = ServiceTask(sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        av_host1 = AntiVirusHost("blah", "blah", 1, "icap", 30)
        av_host2 = AntiVirusHost("blah", "blah", 1, "icap", 60)
        AntiVirus._determine_service_context(service_request, [av_host1, av_host2])
        epoch_time = int(time())
        floor_of_epoch_multiples = floor(epoch_time/(30*60))
        lower_range = floor_of_epoch_multiples * 30 * 60
        upper_range = lower_range + 30 * 60
        lower_range_date = epoch_to_local(lower_range)
        upper_range_date = epoch_to_local(upper_range)
        assert service_request.task.service_context == f"Engine Update Range: {lower_range_date} - {upper_range_date}"

    @staticmethod
    def test_determine_hosts_to_use(antivirus_class_instance):
        from antivirus import AntiVirus, AntiVirusHost
        different_group_av_host = AntiVirusHost("blah1", "blah", 1, "icap", 1)
        sleeping_av_host = AntiVirusHost("blah2", "blah", 1, "icap", 1)
        sleeping_av_host.sleeping = True
        correct_av_host = AntiVirusHost("blah3", "blah", 1, "icap", 1)
        additional_av_host = AntiVirusHost("blah3", "blah", 1, "icap", 1)
        av_host_with_file_size_limit = AntiVirusHost("blah3", "blah", 1, "icap", 1, file_size_limit=30000000)
        hosts = [different_group_av_host, sleeping_av_host, correct_av_host, additional_av_host, av_host_with_file_size_limit]
        file_size = 50000000
        actual_hosts = AntiVirus._determine_hosts_to_use(hosts, file_size)
        assert different_group_av_host in actual_hosts
        assert any(host in actual_hosts for host in [correct_av_host, additional_av_host])

    @staticmethod
    @pytest.mark.parametrize(
        "max_service_timeout, file_size, expected_result",
        [
            (1, 1, 30),
            (300, 1, 30),
            (600, 1, 30),
            (300, 100000000, 290),
            (600, 100000000, 590),
            (300, 50000000, 235),
            (600, 50000000, 385),
            (300, 16000000, 123),
            (600, 16000000, 171),
            (300, 6000000, 90),
            (600, 6000000, 108),
        ]
    )
    def test_determine_scan_timeout_by_size(max_service_timeout, file_size, expected_result):
        from antivirus import AntiVirus
        assert AntiVirus._determine_scan_timeout_by_size(max_service_timeout, file_size) == expected_result
