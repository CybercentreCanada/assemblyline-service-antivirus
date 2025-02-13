[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_antivirus-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-antivirus)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-antivirus)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-antivirus)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-antivirus)](./LICENSE)
# AntiVirus Service

This service provides integration of various anti-virus products with the Assemblyline platform.

## Service Details
This service provide multi-engine capability by connecting to multiple product concurrently and can round robin between nodes of the same product to provide high availability and scale linearly for increased performance.

In theory, any antivirus product will work with this service as long as it is configured for ICAP or HTTP requests.
If you have a different antivirus product other than what we have tested with, please let us know any successes or
failures so that we can adapt the service!
If you are a vendor and would like to see your product added below please reach to us at: contact[_at_]cyber.gc.ca.

### What antivirus products have been tested?
- [Kaspersky Scan Engine v2.0.0.1157 Linux x64, in ICAP mode and HTTP mode](https://www.kaspersky.com/scan-engine)
- [Skyhigh Secure (formerly McAfee) Web Gateway with ICAP and HTTP turned on: Skyhigh Secure Web Gateway 9.2.2 build 33635](https://docs.mcafee.com/bundle/web-gateway-9.2.x-product-guide)
- [ESET File Security For Linux x64 v8.0.375.0, with "Remote scanning - ICAP" enabled](https://help.eset.com/efs/8/en-US/)
- [Bitdefender Security Server v6.2.4.11063, with ICAP scanning enabled](https://www.bitdefender.com/business/support/en/77212-96386-security-server.html)
- [WithSecure (formerly F-Secure) Atlant v2.0.230, in ICAP mode](https://help.f-secure.com/product.html#business/atlant/latest/en/concept_94067ECBA705473F9BC72F4282C2338D-latest-en)
- [Sophos Anti-Virus Dynamic Interface with Engine v3.85.1, in ICAP mode](https://www.sophos.com/en-us/medialibrary/PDFs/documentation/SAVDI-User-Manual.pdf)

For more information on how to configure this service, click [here](./configuration.md).

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name AntiVirus \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-antivirus

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

---

# Service AntiVirus

Ce service assure l'intégration de divers produits anti-virus à la plateforme Assemblyline.

## Détails du service
Ce service offre une capacité multi-moteur en se connectant à plusieurs produits simultanément et peut effectuer un round robin entre les nœuds du même produit afin d'assurer une haute disponibilité et de s'adapter linéairement pour augmenter les performances.

En théorie, n'importe quel produit antivirus fonctionnera avec ce service tant qu'il est configuré pour les requêtes ICAP ou HTTP.
Si vous utilisez un produit antivirus différent de ceux que nous avons testés, veuillez nous faire part de vos succès ou de vos échecs afin que nous puissions adapter le service à vos besoins.
afin que nous puissions adapter le service !
Si vous êtes un fournisseur et que vous souhaitez que votre produit soit ajouté à la liste ci-dessous, veuillez nous contacter à l'adresse suivante : contact[_at_]cyber.gc.ca.

### Quels produits antivirus ont été testés ?
- Kaspersky Scan Engine v2.0.0.1157 Linux x64, en mode ICAP et HTTP](https://www.kaspersky.com/scan-engine)
- Skyhigh Secure (anciennement McAfee) Web Gateway avec ICAP et HTTP activés : Skyhigh Secure Web Gateway 9.2.2 build 33635](https://docs.mcafee.com/bundle/web-gateway-9.2.x-product-guide)
- ESET File Security For Linux x64 v8.0.375.0, avec "Remote scanning - ICAP" activé](https://help.eset.com/efs/8/en-US/)
- Bitdefender Security Server v6.2.4.11063, avec l'analyse ICAP activée](https://www.bitdefender.com/business/support/en/77212-96386-security-server.html)
- WithSecure (anciennement F-Secure) Atlant v2.0.230, en mode ICAP](https://help.f-secure.com/product.html#business/atlant/latest/en/concept_94067ECBA705473F9BC72F4282C2338D-latest-en)
- Sophos Anti-Virus Dynamic Interface with Engine v3.85.1, en mode ICAP](https://www.sophos.com/en-us/medialibrary/PDFs/documentation/SAVDI-User-Manual.pdf)

Pour plus d'informations sur la configuration de ce service, cliquez [ici](./configuration.md).

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name AntiVirus \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-antivirus

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
