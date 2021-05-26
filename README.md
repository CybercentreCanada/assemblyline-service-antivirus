# AntiVirus Service
This service facilitates the dispatching and result-parsing to any antivirus product.

## What antivirus products are supported?
So far, we have tested with the following:
- Kaspersky Scan Engine in ICAP Mode (Linux Version): KL ICAP Service v1.0 (KAV SDK v8.9.2.595)
- McAfee Web Gateway with ICAP turned on: McAfee Web Gateway 9.2.2 build 33635
But in theory any antivirus product will work with this service as long as it is configured for ICAP or HTTP (TODO) responses.

## How to add an antivirus product?
### Things you need:
- The antivirus product must be setup and ready to accept files (via HTTP or ICAP)
- The IP address, port, and possibly the endpoint where the antivirus product is listening 