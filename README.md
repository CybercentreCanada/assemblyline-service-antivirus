# AntiVirus Service
This service facilitates the dispatching and result-parsing to any antivirus product.

## What antivirus products are supported?
So far, we have tested with the following:
- Kaspersky Scan Engine v2.0.0.1157 Linux x64, in ICAP Mode and HTTP Mode
  - https://www.kaspersky.com/scan-engine
- McAfee Web Gateway with ICAP and HTTP turned on: McAfee Web Gateway 9.2.2 build 33635
  - https://docs.mcafee.com/bundle/web-gateway-9.2.x-product-guide

In theory, any antivirus product will work with this service as long as it is configured for ICAP or HTTP requests. 

If you have a different antivirus product other than what we have tested with, please let us know any successes or 
failures so that we can adapt the service!

## How to add an antivirus product?
### Things you need:
- The antivirus product must be setup and ready to accept files (via HTTP or ICAP). You are in charge of setting up the 
  antivirus product, yay responsibility!
- `product`: A unique name for each antivirus product (Kaspersky, McAfee, etc.)
- `ip` & `port`: The IP address and port of at least one host that is serving each antivirus product.
- `update_period`: The period/interval (in minutes) in which the antivirus product host polls for updates.

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
    
    # A list of hosts
    hosts:
    
    # ICAP host
    - ip: "<ip>"
      port: 1344
      method: "icap"
      update_period: 240
      icap_scan_details:
        scan_endpoint: "resp"
   
    # HTTP host
    - ip: "<ip>"
      port: 8000
      method: "http"
      update_period: 240
      http_scan_details:
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
      http_scan_details:
        post_data_type: "data"
        result_in_headers: True
        via_proxy: True
        virus_name_header: "X-Virus-Name"
        scan_endpoint: "filescanner"
      update_period: 240
```

### Explanations of ICAP and HTTP YAML details:
#### ICAP
- `virus_name_header`: The name of the header of the line in the results that contains the antivirus hit name. Example of a line in the results (either in the response headers or body): `X-Virus-ID: <some-signature-here>`. The `virus_name_header` would be `X-Virus-ID`.
- `scan_endpoint`: The URI endpoint at which the service is listening for file contents to be submitted or OPTIONS to be queried.

#### HTTP
- `virus_name_header`: The name of the header of the line in the results that contains the antivirus hit name. Example of a line in the results (either in the response headers or body): `X-Virus-ID: <some-signature-here>`. The `virus_name_header` would be `X-Virus-ID`.
- `scan_endpoint`: The URI endpoint at which the service is listening for file contents to be submitted or OPTIONS to be queried.
- `post_data_type`: The format in which the file contents will be POSTed to the antivirus product server (value must be one of "json" or "data").
- `json_key_for_post`: If the file contents will be POSTed to the antivirus product as the value in a JSON key-value pair, this value is the key.
- `result_in_headers`: A boolean indicating if the antivirus signature will be found in the response headers.
- `base64_encode`: A boolean indicating if the file contents should be base64 encoded prior to being POSTed to the antivirus product server.
- `via_proxy`: A boolean indicating if the antivirus product service is a proxy. This is used to grab the antivirus product service version from the response headers.
- `version_endpoint`: The URI endpoint at which the service is listening for a GET for the antivirus product service version.
