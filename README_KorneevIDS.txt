Korneev IDS Pro

Fichiers
- korneev_ids_pro.c : source C pour Windows
- build_msvc.bat : compilation avec le compilateur Microsoft Visual C

Compilation
1. Installe les Build Tools de Visual Studio avec le composant C++.
2. Ouvre « x64 Native Tools Command Prompt for Visual Studio ».
3. Place-toi dans le dossier contenant les fichiers.
4. Lance build_msvc.bat.

Lancement
Lance KorneevIDS.exe. Les controles sont affiches dans le tableau de bord :
- 1 : scan immediat
- L : ouvrir le journal
- Q : quitter

Le journal est ecrit dans %ProgramData%\KorneevIDS\alerts.log.

Surveillance des journaux Windows
Le programme examine les journaux System, Application et Security pour reperer certains ID d'evenements pertinents (demarrages/arrets, erreurs d'application, echecs d'authentification, creation de service, effacement du journal Security et changements de strategie d'audit). Les evenements recents sont consultes au premier scan. L'acces au journal Security peut necessiter une execution en administrateur. Pour les details complets, utilisez l'Observateur d'evenements avec la touche E. La couverture depend de la configuration d'audit Windows et des droits du compte.
Les alertes sur un nom de processus ou un port sont des indicateurs a verifier, pas une preuve de compromission.
Le programme n'arrete pas les processus et ne modifie pas les parametres de securite Windows.
