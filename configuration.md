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

---

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
