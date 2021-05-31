# AntiVirus Service
This service facilitates the dispatching and result-parsing to any antivirus product.

## What antivirus products are supported?
So far, we have tested with the following:
- Kaspersky Scan Engine in ICAP Mode (Linux Version): KL ICAP Service v1.0 (KAV SDK v8.9.2.595)
  - https://www.kaspersky.com/scan-engine
- McAfee Web Gateway with ICAP turned on: McAfee Web Gateway 9.2.2 build 33635

But in theory any antivirus product will work with this service as long as it is configured for ICAP or HTTP (TODO) responses.

## How to add an antivirus product?
### Things you need:
- The antivirus product must be setup and ready to accept files (via HTTP or ICAP).
- A unique name for each antivirus product node
- The IP address, port, and possibly the endpoint where the antivirus product is listening.
- The period/interval (in minutes) in which the antivirus product polls for updates.
- The `group` parameter in the `service_manifest.yml` is relevant when you have multiple nodes of the same product: 
  - If you have this type of deployment, then make sure that the same product nodes all have the same `group` parameter.
  - If you do not have this type of deployment, then you do not need to use the `group` parameter.