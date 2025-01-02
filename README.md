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

### Service Options
* `av_config`: Dictionary containing details that we will use for revising or omitting antivirus signature hits
  * `products`: A list of antivirus products. See below for an in-depth description of this parameter.
  * `kw_score_revision_map`: A dictionary where the keys are the keywords that could be found in signatures, and the value is the revised score
  * `sig_score_revision_map`: A dictionary where the keys are the signatures that you want to revise, and the values are the scores that the signatures will be revised to
* `sleep_time`: If an antivirus product is down for whatever reason, this is the number of seconds that the service will wait before it tries to send a file to that antivirus product again
* `connection_timeout`: The timeout for creating an ICAP connection
* `number_of_retries`: The number of attempts to create an ICAP connection
* `mercy_limit`: The number of files that are allowed to not be completed in time by an engine before the engine is put to sleep
* `sleep_on_version_error`: Put engine to sleep if an error is raised from querying the version of the engine.

### How to add an antivirus product?
The antivirus product must be setup and ready to accept files (via HTTP or ICAP). You are in charge of setting up the
  antivirus product, yay responsibility!

#### Things you need:
- `product`: A unique name for each antivirus product (Kaspersky, Skyhigh, ESET, WithSecure, Sophos, Bitdefender, etc.)
- `ip` & `port`: The IP address and port of at least one host that is serving each antivirus product.
- `update_period`: The period/interval (in minutes) in which the antivirus product host polls for updates.
- [OPTIONAL] `file_size_limit`: The limit of the file size, in bytes, that the host can process within the service timeout


Example of `av_config` from service_manifest.yaml in YAML form
```yaml
av_config:
  products:
    - product: "Kaspersky"

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
            no_status_line_in_headers: true

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
    ...
```

#### Explanations of ICAP and HTTP YAML details:
##### ICAP
- `virus_name_header`: The name of the header of the line in the results that contains the antivirus hit name. Example of a line in the results (either in the response headers or body): `X-Virus-ID: <some-signature-here>`. The `virus_name_header` would be `X-Virus-ID`.
- `scan_endpoint`: The URI endpoint at which the service is listening for file contents to be submitted or OPTIONS to be queried.
- `no_version`: A boolean indicating if a product version will be returned if you query OPTIONS.
- `version_header`: The name of the header of the line in the version results that contains the antivirus engine version.
- `check_body_for_headers`: A boolean indicating if the ICAP response body could contain important headers.
- `no_status_line_in_headers`: A boolean indicating if the ICAP response body does not contain the standard status header such as 'ICAP/1.0 200 BLOCKED'

##### HTTP
- `virus_name_header`: The name of the header of the line in the results that contains the antivirus hit name. Example of a line in the results (either in the response headers or body): `X-Virus-ID: <some-signature-here>`. The `virus_name_header` would be `X-Virus-ID`.
- `scan_endpoint`: The URI endpoint at which the service is listening for file contents to be submitted or OPTIONS to be queried.
- `post_data_type`: The format in which the file contents will be POSTed to the antivirus product server (value must be one of "json" or "data").
- `json_key_for_post`: If the file contents will be POSTed to the antivirus product as the value in a JSON key-value pair, this value is the key.
- `result_in_headers`: A boolean indicating if the antivirus signature will be found in the response headers.
- `base64_encode`: A boolean indicating if the file contents should be base64 encoded prior to being POSTed to the antivirus product server.
- `version_endpoint`: The URI endpoint at which the service is listening for a GET for the antivirus product service version.

#### An antivirus signature is raising too many false-positives, how can I remedy this from the Assemblyline side?

The solution here is that we still want to see if a signature is being raised for a submission for tracking purposes but we want to avoid false-positive verdicts/scores, so what we want to do is just revise the score that the signature receives by the AntiVirus service.

This can be done one of two ways:
  1. Adding the `av.virus_name` tag to the Safelist in the UI (this will map the score of the tag to `0`)
  2. Using the `kw_score_revision_map` or `sig_score_revision_map` configurations based on a `<av_vendor>.<av_verdict>` signature
      * `kw_score_revision_map`: This configuration is used to remap the score based on the presence of a keyword in the signature (ie. signature combination contains `adware`).
      * `sig_score_revision_map`: This configuration is used to remap the score of a specific signature (ie. signature combination matches `Kaspersky.adware`).

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

### Service Options
* `av_config` : Dictionnaire contenant les détails que nous utiliserons pour réviser ou omettre les signatures antivirus.
  * `produits` : Une liste de produits antivirus. Voir ci-dessous pour une description approfondie de ce paramètre.
  * `kw_score_revision_map` : Un dictionnaire dont les clés sont les mots-clés qui pourraient être trouvés dans les signatures, et la valeur est le score révisé.
  * `sig_score_revision_map` : Un dictionnaire où les clés sont les signatures que vous voulez réviser, et les valeurs sont les scores auxquels les signatures seront révisées.
* `sleep_time` : Si un produit antivirus est en panne pour une raison quelconque, c'est le nombre de secondes que le service attendra avant d'essayer d'envoyer à nouveau un fichier à ce produit antivirus
* `connection_timeout` : Le délai de création d'une connexion ICAP
* `number_of_retries` : Le nombre de tentatives pour créer une connexion ICAP.
* `mercy_limit` : Le nombre de fichiers qui sont autorisés à ne pas être complétés à temps par un moteur avant que le moteur ne soit mis en sommeil.
* `sleep_on_version_error` : Mettre le moteur en veille si une erreur est soulevée lors de l'interrogation de la version du moteur.

#### Comment ajouter un produit antivirus ?
Le produit antivirus doit être configuré et prêt à accepter des fichiers (via HTTP ou ICAP). Vous êtes responsable de la configuration de l'antivirus.
  de l'antivirus, bonne nouvelle, c'est votre responsabilité !

#### Ce dont vous avez besoin :
- `produit` : Un nom unique pour chaque produit antivirus (Kaspersky, Skyhigh, ESET, WithSecure, Sophos, Bitdefender, etc.)
- `ip` & `port` : L'adresse IP et le port d'au moins un hôte qui utilise chaque produit antivirus.
- `update_period` : La période/intervalle (en minutes) pendant laquelle l'hôte du produit antivirus interroge pour les mises à jour.
- [OPTIONNEL] `file_size_limit` : La limite de la taille du fichier, en octets, que l'hôte peut traiter dans le délai d'attente du service.

Exemple de `av_config` de service_manifest.yaml sous forme YAML
```yaml
av_config :
  products :
    - product : "Kaspersky"

      # Une liste de chaînes de caractères trouvées dans les signatures de l'antivirus qui indiquent qu'une # analyse heuristique a provoqué la levée de la signature.
      # qu'une analyse heuristique a entraîné la levée de la signature. Ceci est considéré comme "suspect" dans le contexte de
      # Assemblyline, plutôt que "Malveillant".
      heuristic_analysis_keys :
        - "HEUR :"
        - "not-a-virus"

      # Une liste d'hôtes
      hosts :

        # hôte ICAP
        - ip : "<ip>"
          port : 1344
          method : "icap"
          update_period : 240
          file_size_limit : 30000000
          scan_details :
            scan_endpoint : "resp"
            no_status_line_in_headers : true

        # HTTP host
        - ip : "<ip>"
          port : 8000
          method : "http"
          update_period : 240
          scan_details :
            post_data_type : "json"
            version_endpoint : "version"
            scan_endpoint : "api/v3.1/scanmemory"
            base64_encode : True
            json_key_for_post : "object"
            virus_name_header : "detectionName"
    ...
```

#### Explications des détails ICAP et HTTP YAML :
##### ICAP
- `virus_name_header` : Le nom de l'en-tête de la ligne dans les résultats qui contient le nom du hit antivirus. Exemple d'une ligne dans les résultats (dans les en-têtes ou le corps de la réponse) : `X-Virus-ID : <signature-ici>`. Le `virus_name_header` serait `X-Virus-ID`.
- `scan_endpoint` : Le point de terminaison URI auquel le service écoute les contenus de fichiers à soumettre ou les OPTIONS à interroger.
- `no_version` : Un booléen indiquant si une version du produit sera retournée si vous interrogez les OPTIONS.
- `version_header` : Le nom de l'en-tête de la ligne dans les résultats de la version qui contient la version du moteur antivirus.
- `check_body_for_headers` : Un booléen indiquant si le corps de la réponse ICAP peut contenir des en-têtes importants.
- `no_status_line_in_headers` : Un booléen indiquant si le corps de la réponse ICAP ne contient pas l'en-tête de statut standard tel que 'ICAP/1.0 200 BLOCKED'

##### HTTP
- `virus_name_header` : Le nom de l'en-tête de la ligne dans les résultats qui contient le nom du hit antivirus. Exemple de ligne dans les résultats (dans les en-têtes ou le corps de la réponse) : `X-Virus-ID : <signature-ici>`. Le `virus_name_header` serait `X-Virus-ID`.
- `scan_endpoint` : Le point de terminaison URI auquel le service écoute les contenus de fichiers à soumettre ou les OPTIONS à interroger.
- `post_data_type` : Le format dans lequel le contenu du fichier sera envoyé au serveur du produit antivirus (la valeur doit être « json » ou « data »).
- `json_key_for_post` : Si le contenu du fichier sera envoyé au produit antivirus en tant que valeur dans une paire clé-valeur JSON, cette valeur est la clé.
- `result_in_headers` : Un booléen indiquant si la signature de l'antivirus sera trouvée dans les en-têtes de la réponse.
- `base64_encode` : Un booléen indiquant si le contenu du fichier doit être encodé en base64 avant d'être envoyé au serveur du produit antivirus.
- `version_endpoint` : Le point de terminaison URI auquel le service écoute un GET pour la version du service de produit antivirus.

#### Une signature antivirus génère trop de faux positifs, comment puis-je y remédier du côté d'Assemblyline ?

La solution ici est que nous voulons toujours voir si une signature est soulevée pour une soumission à des fins de suivi, mais nous voulons éviter les verdicts/scores faussement positifs, donc ce que nous voulons faire est simplement de réviser le score que la signature reçoit par le service AntiVirus.

Cela peut se faire de deux manières :
  1. En ajoutant le tag `av.virus_name` à la Liste des Sécurités dans l'interface utilisateur (ce qui aura pour effet de faire correspondre le score du tag à `0`).
  2. En utilisant les configurations `kw_score_revision_map` ou `sig_score_revision_map` basées sur une signature `<av_vendor>.<av_verdict>`.
      * `kw_score_revision_map` : Cette configuration est utilisée pour modifier le score en fonction de la présence d'un mot-clé dans la signature (par exemple, la combinaison de signatures contient `adware`).
      * `sig_score_revision_map` : Cette configuration est utilisée pour remapper le score d'une signature spécifique (par exemple, la combinaison de signatures correspond à `Kaspersky.adware`).


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
