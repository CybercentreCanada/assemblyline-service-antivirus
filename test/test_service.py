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
def antivirus_class_instance():
    create_tmp_manifest()
    try:
        from antivirus import AntiVirus
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
    return DummyRequests


class TestAntiVirusHost:
    @staticmethod
    def test_init(antivirushost_class):
        from requests import Session
        from assemblyline_v4_service.common.icap import IcapClient
        with pytest.raises(ValueError):
            antivirushost_class("blah", "blah", 8008, "blah", 100)

        avhost_icap = antivirushost_class("blah", "blah", 8008, "icap", 100)
        assert avhost_icap.group == "blah"
        assert avhost_icap.ip == "blah"
        assert avhost_icap.port == 8008
        assert avhost_icap.method == "icap"
        assert avhost_icap.version_endpoint is None
        assert avhost_icap.scan_endpoint is None
        assert avhost_icap.update_period == 100
        assert type(avhost_icap.client) == IcapClient
        assert avhost_icap.sleeping is False

        avhost_http = antivirushost_class("blah", "blah", 8008, "http", 100, "blah", "blah")
        assert avhost_http.group == "blah"
        assert avhost_http.ip == "blah"
        assert avhost_http.port == 8008
        assert avhost_http.method == "http"
        assert avhost_http.version_endpoint == "blah"
        assert avhost_http.scan_endpoint == "blah"
        assert avhost_http.update_period == 100
        assert type(avhost_http.client) == Session
        assert avhost_http.sleeping is False

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
            os.remove(temp_sample_path)

    @staticmethod
    def test_init(antivirus_class_instance):
        assert antivirus_class_instance.hosts == []
        assert antivirus_class_instance.retry_period == 0
        assert antivirus_class_instance.check_completion_interval == 0.0

    @staticmethod
    def test_start(antivirus_class_instance):
        from antivirus import AntiVirusHost
        products = antivirus_class_instance.config["av_config"]["products"]
        correct_hosts = [
            AntiVirusHost(product["product"], host["ip"], host["port"], host["method"], host["update_period"], host.get("version_endpoint"), host.get("scan_endpoint"))
            for product in products for host in product["hosts"]
        ]
        antivirus_class_instance.start()
        assert antivirus_class_instance.hosts == correct_hosts
        assert antivirus_class_instance.retry_period == 60
        assert antivirus_class_instance.check_completion_interval == 0.0

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
    def test_get_hosts(antivirus_class_instance):
        from antivirus import AntiVirus, AntiVirusHost
        products = [{"product": "blah", "hosts": [{"ip": "localhost", "port": 1344, "version_endpoint": "version", "scan_endpoint": "resp", "method": "icap", "name": "blah", "update_period": 100, "group": "blah"}]}]
        correct_hosts = [AntiVirusHost(host["group"], host["ip"], host["port"], host["method"], host["update_period"], host["version_endpoint"], host["scan_endpoint"])
                         for product in products for host in product["hosts"]]
        assert AntiVirus._get_hosts(products) == correct_hosts

    @staticmethod
    def test_thr_process_file(antivirus_class_instance, mocker):
        from antivirus import AntiVirus, AntiVirusHost, av_hit_result_sections
        avhost = AntiVirusHost("blah", "blah", 1, "icap", 1)
        mocker.patch.object(AntiVirus, "_scan_file", return_value=(None, None, None))
        mocker.patch.object(AntiVirus, "_parse_version", return_value=None)
        mocker.patch.object(AntiVirus, "_parse_result", return_value=None)
        antivirus_class_instance._thr_process_file(avhost, "blah", b"blah")
        assert av_hit_result_sections == []

        mocker.patch.object(AntiVirus, "_scan_file", return_value=(True, True, avhost))
        mocker.patch.object(AntiVirus, "_parse_version", return_value="blah")
        mocker.patch.object(AntiVirus, "_parse_result", return_value="blah")
        antivirus_class_instance._thr_process_file(avhost, "blah", b"blah")
        assert av_hit_result_sections == ["blah"]

    @staticmethod
    def test_scan_file(antivirus_class_instance, antivirushost_class, dummy_requests_class_instance, mocker):
        from socket import timeout
        from time import sleep
        from requests.sessions import Session
        from assemblyline_v4_service.common.icap import IcapClient
        mocker.patch.object(IcapClient, "scan_data", return_value="blah")
        mocker.patch.object(IcapClient, "options_respmod", return_value="blah")
        av_host_icap = antivirushost_class("blah", "blah", 1234, "icap", 100, "blah")
        assert antivirus_class_instance._scan_file(av_host_icap, "blah", b"blah") == ("blah", "blah", av_host_icap)

        mocker.patch.object(Session, "get", return_value=dummy_requests_class_instance("blah"))
        mocker.patch.object(Session, "post", return_value=dummy_requests_class_instance("blah"))
        av_host_http = antivirushost_class("blah", "blah", 1234, "http", 100, "blah")
        assert antivirus_class_instance._scan_file(av_host_http, "blah", b"blah") == ("blah", "blah", av_host_http)

        av_host_http = antivirushost_class("blah", "blah", 1234, "http", 100, "blah", "blah")
        assert antivirus_class_instance._scan_file(av_host_http, "blah", b"blah") == ("blah", "blah", av_host_http)

        with mocker.patch.object(IcapClient, "scan_data", side_effect=timeout):
            assert av_host_icap.sleeping is False
            antivirus_class_instance.retry_period = 2
            assert antivirus_class_instance._scan_file(av_host_icap, "blah", b"blah") == (None, "blah", av_host_icap)
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
    def test_parse_result(mocker):
        from antivirus import AntiVirus
        mocker.patch.object(AntiVirus, "_parse_icap_results")
        mocker.patch.object(AntiVirus, "_parse_http_results")
        AntiVirus._parse_result("blah", "ipap", "blah", "blah")
        AntiVirus._parse_result("blah", "http", "blah", "blah")

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
                antivirus_class_instance._parse_icap_results(icap_result, av_name, version)
            return

        if not expected_section_title:
            assert antivirus_class_instance._parse_icap_results(icap_result, av_name, version) is None
        else:
            correct_result_section = ResultSection(expected_section_title)
            correct_result_section.heuristic = Heuristic(expected_heuristic) if expected_heuristic else None
            correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}")
            correct_result_section.tags = expected_tags
            correct_result_section.body = expected_body
            correct_result_section.body_format = BODY_FORMAT.KEY_VALUE
            test_result_section = antivirus_class_instance._parse_icap_results(icap_result, av_name, version)
            assert check_section_equality(test_result_section, correct_result_section)

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
            assert antivirus_class_instance._parse_http_results(http_result, av_name, version) is None
        else:
            correct_result_section = ResultSection(expected_section_title)
            correct_result_section.heuristic = Heuristic(expected_heuristic) if expected_heuristic else None
            correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}")
            correct_result_section.tags = expected_tags
            correct_result_section.body = expected_body
            correct_result_section.body_format = BODY_FORMAT.KEY_VALUE
            test_result_section = antivirus_class_instance._parse_http_results(http_result, av_name, version)
            assert check_section_equality(test_result_section, correct_result_section)

    @staticmethod
    def test_gather_results(dummy_result_class_instance):
        from antivirus import AntiVirus, AntiVirusHost, AvHitSection
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        hosts = [AntiVirusHost("blah1", "blah", 1234, "icap", 1), AntiVirusHost("blah2", "blah", 1234, "icap", 1)]
        AntiVirus._gather_results(hosts, [], dummy_result_class_instance)
        assert dummy_result_class_instance.sections == []

        correct_av_result_section = AvHitSection("blah2", "blah", "blah", {}, 1)
        AntiVirus._gather_results(hosts, [correct_av_result_section], dummy_result_class_instance)
        no_result_section2 = ResultSection(
            "Failed to Scan or No Threat Detected by AV Engine(s)",
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(dict(no_threat_detected=[host.group for host in hosts[:1]]))
        )
        assert check_section_equality(dummy_result_class_instance.sections[0], correct_av_result_section)
        assert check_section_equality(dummy_result_class_instance.sections[1], no_result_section2)

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
        hosts = [different_group_av_host, sleeping_av_host, correct_av_host, additional_av_host]
        actual_hosts = AntiVirus._determine_hosts_to_use(hosts)
        assert actual_hosts[0] == different_group_av_host
        assert actual_hosts[1] == correct_av_host
