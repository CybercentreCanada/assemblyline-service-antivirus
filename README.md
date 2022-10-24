# AntiVirus Service
Provide integration of various anti-virus product with the Assemblyline platform. This service provide multi-engine capability by connecting to multiple product concurrently and can round robin between nodes of the same product to provide high availability and scale linearly for increased performance.

In theory, any antivirus product will work with this service as long as it is configured for ICAP or HTTP requests.
If you have a different antivirus product other than what we have tested with, please let us know any successes or
failures so that we can adapt the service!
If you are a vendor and would like to see your product added below please reach to us at: contact[_at_]cyber.gc.ca.

## What antivirus products have been tested?
- Kaspersky Scan Engine v2.0.0.1157 Linux x64, in ICAP mode and HTTP mode
  - https://www.kaspersky.com/scan-engine
- McAfee Web Gateway with ICAP and HTTP turned on: McAfee Web Gateway 9.2.2 build 33635
  - https://docs.mcafee.com/bundle/web-gateway-9.2.x-product-guide
- ESET File Security For Linux x64 v8.0.375.0, with "Remote scanning - ICAP" enabled
  - https://help.eset.com/efs/8/en-US/
- Bitdefender Security Server v6.2.4.11063, with ICAP scanning enabled
  - https://www.bitdefender.com/business/support/en/77212-96386-security-server.html
- F-Secure Atlant v2.0.230, in ICAP mode
  - https://help.f-secure.com/product.html#business/atlant/latest/en/concept_94067ECBA705473F9BC72F4282C2338D-latest-en
- Sophos Anti-Virus Dynamic Interface with Engine v3.85.1, in ICAP mode
  - https://www.sophos.com/en-us/medialibrary/PDFs/documentation/SAVDI-User-Manual.pdf

## Service Options
* **av_config**: Dictionary containing details that we will use for revising or omitting antivirus signature hits
  * **products**: A list of antivirus products. See below for an in-depth description of this parameter.
  * **kw_score_revision_map**: A dictionary where the keys are the keywords that could be found in signatures, and the value is the revised score
  * **sig_score_revision_map**: A dictionary where the keys are the signatures that you want to revise, and the values are the scores that the signatures will be revised to
* **sleep_time**: If an antivirus product is down for whatever reason, this is the number of seconds that the service will wait before it tries to send a file to that antivirus product again
* **connection_timeout**: The timeout for creating an ICAP connection
* **number_of_retries**: The number of attempts to create an ICAP connection
* **mercy_limit**: The number of files that are allowed to not be completed in time by an engine before the engine is put to sleep
* **sleep_on_version_error**: Put engine to sleep if an error is raised from querying the version of the engine.

## How to add an antivirus product?
### Things you need:
- The antivirus product must be setup and ready to accept files (via HTTP or ICAP). You are in charge of setting up the
  antivirus product, yay responsibility!
- `product`: A unique name for each antivirus product (Kaspersky, McAfee, ESET, etc.)
- `ip` & `port`: The IP address and port of at least one host that is serving each antivirus product.
- `update_period`: The period/interval (in minutes) in which the antivirus product host polls for updates.
- [OPTIONAL] `file_size_limit`: The limit of the file size, in bytes, that the host can process within the service timeout


Example of `av_config` from service_manifest.yaml in YAML form
```
av_config:
  products:
    - product: "Kasperksy"

      # A list of strings that are found in the antivirus product's signatures that indicate that
      # heuristic analysis caused the signature to be raised. This is considered "Suspicious" in the context of
      # Assemblyline, rather than "Malicious".
      heuristic_analysis_keys:
        - "HEUR:"
        - "not-a-virus"

      # A list of hosts
      hosts:

        # ICAP host
        - ip: "<ip>"
          port: 1344
          method: "icap"
          update_period: 240
          file_size_limit: 30000000
          scan_details:
            scan_endpoint: "resp"

        # HTTP host
        - ip: "<ip>"
          port: 8000
          method: "http"
          update_period: 240
          scan_details:
            post_data_type: "json"
            version_endpoint: "version"
            scan_endpoint: "api/v3.1/scanmemory"
            base64_encode: True
            json_key_for_post: "object"
            virus_name_header: "detectionName"

    - product: "McAfee"
      heuristic_analysis_keys:
        - "HEUR/"
        - "BehavesLike."
      hosts:
        - ip: "<ip>"
          port: 1344
          method: "icap"
          update_period: 240
        - ip: "<ip>"
          port: 9090
          method: "http"
          scan_details:
            post_data_type: "data"
            result_in_headers: True
            virus_name_header: "X-Virus-Name"
            scan_endpoint: "filescanner"
          update_period: 240

    - product: "ESET"
      hosts:
        - ip: "<ip>"
          port: 1344
          method: "icap"
          scan_details:
            no_version: true
            virus_name_header: "X-Infection-Found: Type=0; Resolution=0; Threat"
          update_period: 240

    - product: "Bitdefender"
      heuristic_analysis_keys:
        - "Gen:Heur"
      hosts:
        - ip: "<ip>"
          port: 1344
          method: "icap"
          update_period: 240

    - product: "F-Secure"
      heuristic_analysis_keys:
        - "Heuristic.HEUR/"
      hosts:
        - ip: "<ip>"
          port: 1344
          method: "icap"
          scan_details:
            virus_name_header: "X-FSecure-Infection-Name"
            version_header: "X-FSecure-Versions:"
          update_period: 240

    - product: "Sophos"
      hosts:
        - ip: "<ip>"
          port: 1344
          method: "icap"
          scan_details:
            scan_endpoint: "sophos"
            version_header: "X-EngineVersion: "
          update_period: 240
          file_size_limit: 29000000
```

### Explanations of ICAP and HTTP YAML details:
#### ICAP
- `virus_name_header`: The name of the header of the line in the results that contains the antivirus hit name. Example of a line in the results (either in the response headers or body): `X-Virus-ID: <some-signature-here>`. The `virus_name_header` would be `X-Virus-ID`.
- `scan_endpoint`: The URI endpoint at which the service is listening for file contents to be submitted or OPTIONS to be queried.
- `no_version`: A boolean indicating if a product version will be returned if you query OPTIONS.
- `version_header`: The name of the header of the line in the version results that contains the antivirus engine version.

#### HTTP
- `virus_name_header`: The name of the header of the line in the results that contains the antivirus hit name. Example of a line in the results (either in the response headers or body): `X-Virus-ID: <some-signature-here>`. The `virus_name_header` would be `X-Virus-ID`.
- `scan_endpoint`: The URI endpoint at which the service is listening for file contents to be submitted or OPTIONS to be queried.
- `post_data_type`: The format in which the file contents will be POSTed to the antivirus product server (value must be one of "json" or "data").
- `json_key_for_post`: If the file contents will be POSTed to the antivirus product as the value in a JSON key-value pair, this value is the key.
- `result_in_headers`: A boolean indicating if the antivirus signature will be found in the response headers.
- `base64_encode`: A boolean indicating if the file contents should be base64 encoded prior to being POSTed to the antivirus product server.
- `version_endpoint`: The URI endpoint at which the service is listening for a GET for the antivirus product service version.
