# secure-WAF-compiler

1. Compilation & Théorie des Langages
Le WAF n'utilise pas de simples expressions régulières codées en dur : il embarque un compilateur complet pour un langage dédié à la sécurité (Domain-Specific Language - DSL).

Analyse Lexicale (Lexer) : La classe SecurityRuleLexer découpe la chaîne de règles textuelles (ex: uri CONTAINS 'select' THEN BLOCK) en une séquence de jetons typés (Token).

Analyse Syntaxique & AST (Parser) : La classe RuleCompiler transforme les jetons en un Arbre de Syntaxe Abstraite (AST) composé de nœuds ASTNode.

Moteur d'Évaluation : L'AST est évalué dynamiquement à la volée sur le contexte de chaque requête HTTP entrante pour prendre des décisions d'autorisation ou de blocage instantanées.

🌐 2. Réseau & Protocoles
Socket & Couche Transport : Communication TCP bas niveau gérée par le module asyncio.

Analyse de Protocole Applicatif (HTTP RFC 7230) : Décodage et parsing des trames HTTP brutes (GET /uri HTTP/1.1, en-têtes, paramètres de requête).

Équilibrage de Charge (Round-Robin) : Distribution équitable des requêtes filtrées sur un pool de serveurs d'arrière-plan (backends).

💻 3. Systèmes d'Exploitation (OS)
E/S Asynchrones & Non-Bloquantes : Utilisation d'une boucle d'événements (Event Loop) basée sur epoll/kqueue/select selon la plateforme, permettant de traiter des milliers de connexions simultanées sur un seul thread sans surcoût de commutation de contexte.

Gestion des Signaux POSIX : Capture des signaux système SIGINT (Ctrl+C) et SIGTERM pour garantir une fermeture propre des sockets et la libération des descripteurs de fichiers (File Descriptors).

🛡️ 4. Cybersécurité & Protection Périmétrique
Pare-feu Applicatif (WAF) : Interception et neutralisation des attaques web courantes (Injections SQL, XSS, Traversée de répertoires) via le moteur de règles compilé.

Anti-DDoS / Rate Limiting : Algorithme de fenêtre glissante (Sliding Window) limitant le nombre de requêtes par adresse IP sur un intervalle de temps configurable.

Code de Réponse Défensif : Émission de réponses HTTP normalisées (403 Forbidden, 429 Too Many Requests, 502 Bad Gateway).

⚙️ 5. Développement & Ingénierie Logicielle
Conception Orientée Objet & Design Patterns : Implémentation des patrons de conception Interpreter/AST (pour le compilateur) et Proxy (pour la couche réseau).

Code Propre & Modulaire : Structuration sans dépendance tierce, favorisant la portabilité, la maintenabilité et la facilité de test unitaires.
