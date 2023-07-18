# AntiVirus Service
Provide integration of various anti-virus product with the Assemblyline platform. This service provide multi-engine capability by connecting to multiple product concurrently and can round robin between nodes of the same product to provide high availability and scale linearly for increased performance.

In theory, any antivirus product will work with this service as long as it is configured for ICAP or HTTP requests.
If you have a different antivirus product other than what we have tested with, please let us know any successes or
failures so that we can adapt the service!
If you are a vendor and would like to see your product added below please reach to us at: contact[_at_]cyber.gc.ca.

## What antivirus products have been tested?
- Kaspersky Scan Engine v2.0.0.1157 Linux x64, in ICAP mode and HTTP mode
  - https://www.kaspersky.com/scan-engine
- Skyhigh Secure (formerly McAfee) Web Gateway with ICAP and HTTP turned on: Skyhigh Secure Web Gateway 9.2.2 build 33635
  - https://docs.mcafee.com/bundle/web-gateway-9.2.x-product-guide
- ESET File Security For Linux x64 v8.0.375.0, with "Remote scanning - ICAP" enabled
  - https://help.eset.com/efs/8/en-US/
- Bitdefender Security Server v6.2.4.11063, with ICAP scanning enabled
  - https://www.bitdefender.com/business/support/en/77212-96386-security-server.html
- WithSecure (formerly F-Secure) Atlant v2.0.230, in ICAP mode
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
- `product`: A unique name for each antivirus product (Kaspersky, Skyhigh, ESET, WithSecure, Sophos, Bitdefender, etc.)
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

    - product: "Skyhigh"
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
            check_body_for_headers: True
          update_period: 240

    - product: "ESET"
      hosts:
        - ip: "<ip>"
          port: 1344
          method: "icap"
          scan_details:
            no_version: True
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

    - product: "WithSecure"
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
- `check_body_for_headers`: A boolean indicating if the ICAP response body could contain important headers.

#### HTTP
- `virus_name_header`: The name of the header of the line in the results that contains the antivirus hit name. Example of a line in the results (either in the response headers or body): `X-Virus-ID: <some-signature-here>`. The `virus_name_header` would be `X-Virus-ID`.
- `scan_endpoint`: The URI endpoint at which the service is listening for file contents to be submitted or OPTIONS to be queried.
- `post_data_type`: The format in which the file contents will be POSTed to the antivirus product server (value must be one of "json" or "data").
- `json_key_for_post`: If the file contents will be POSTed to the antivirus product as the value in a JSON key-value pair, this value is the key.
- `result_in_headers`: A boolean indicating if the antivirus signature will be found in the response headers.
- `base64_encode`: A boolean indicating if the file contents should be base64 encoded prior to being POSTed to the antivirus product server.
- `version_endpoint`: The URI endpoint at which the service is listening for a GET for the antivirus product service version.

### An antivirus signature is raising too many false-positives, how can I remedy this from the Assemblyline side?

The solution here is that we still want to see if a signature is being raised for a submission for tracking purposes but we want to avoid false-positive verdicts/scores, so what we want to do is just revise the score that the signature receives by the AntiVirus service.

__N.B.:__ This process is available to system administrators only.

Revising a signature score in the user interface is done in a few easy steps...

**Step 1**: Head to the "Detailed View" of a submission that is raising the signature that you want to revise the score of. If the URL you have reached  follows `https://<IP or domain of Assemblyline instance>/submission/report/<sid>` then you have "Report View" as your default submission viewer. If this is the case, head to the "Detailed View" by clicking the far-right icon at the top of the page:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/show_detailed_view.png?raw=true)

If you are already on the "Detailed View" page, the URL you have reached should follow `https://<IP or domain of Assemblyline instance>/submission/detail/<sid>`.

The goal of **Step 1** is reach the "Detailed View" page for a submission containing the raised signature that is causing false-positives.

**Step 2**: Scroll down the page until you see the **Heuristic** section where that signature exists for the submission:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/heuristic_section.png?raw=true)

Open the **AntiVirus** heuristic drawer to view the heuristic details. The heuristic will either be named "File is infected (ANTIVIRUS.1)" or "File is suspicious (ANTIVIRUS.2)". As seen in the image above, this example features a heuristic drawer for "File is infected (ANTIVIRUS.1)". When the drawer is expanded, it looks like this:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/open_heuristic_drawer.png?raw=true)

__N.B.:__ This is just an example and we are arbitrarily choosing a signature to revise the score of for documentation purposes. This signature is actually very good and should not have the score revised.

Show the signature for that heuristic by clicking on the heuristic icon in that result section:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/heuristic_icon.png?raw=true)

Now you can see the heuristic and the signature that caused that heuristic to be raised:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/revealed_heuristic_and_signature.png?raw=true)

Right-click on the signature to view the "Right-click" menu and select the "Copy to Clipboard" option:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/right_click_menu.png?raw=true)

When copied, you will see a green popup:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/signature_copied.png?raw=true)

The goal of **Step 2** is to copy the signature name value as seen in the AntiVirus service to the clipboard, since this is what the AntiVirus service will use for revising the score.

**Step 3**: In the side bar, head to "Administration" -> "Services":

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/signature_copied.png?raw=true)

After doing so, your URL should look like this: `https://<IP or domain of Assemblyline instance>/admin/services`.

Select the "AntiVirus" service on this page, then click on the "PARAMETERS" tab:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/antivirus_parameters.png?raw=true)

Scroll to the **Service Variables** section and find the `av_config` value:

__N.B.:__ If the `sig_score_revision_map` key is not present, just add it at the root level of the `av_config` dictionary by hovering over the JSON, and clicking the (+) that appears.

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/av_config.png?raw=true)

Under the `sig_score_revision_map` key, hover over the key value and click the (+):

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/plus_key.png?raw=true)

This popup will appear to add a new key:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/add_key_popup.png?raw=true)

Paste the signature value to the key input box that was copied to your clipboard in **Step 2**. Click the blue checkmark that appears in the input box.

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/pasted_value_with_checkmark.png?raw=true)

So now you should have something similar to this:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/set_score.png?raw=true)

Click on the little "edit" icon to add a value for this key. Set the value to the desired score:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/pay_attention_to_which_checkmark.png?raw=true)

To ensure the value is saved as an integer, click on the lower checkmark next to the red 0.

You should have this now:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/score_set.png?raw=true)

The last thing to do for this step is to save your changes by clicking the "SAVE CHANGES" button on the bottom of your page:

![alt text](https://github.com/CybercentreCanada/assemblyline-service-antivirus/blob/main/readme_images/save_changes.png?raw=true)

The goal of **Step 3** is to actually add the signature and revised score to the service parameters so that it takes effect immediately for new submissions.

**Step 4**: Celebrate!
