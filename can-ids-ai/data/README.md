# Données

Les fichiers `*.db`, `*.csv` et `*.log` sont ignorés par git.

## Jeux de données publics (vérifiez les licences et conditions d'utilisation)
- **Car-Hacking Dataset** (HCRL, Hacking and Countermeasure Research Lab, Corée) : DoS, fuzzing, usurpation (gear/RPM) — `canids import --format hcrl`.
- **ROAD** (Real ORNL Automotive Dynamometer) : captures réelles avec attaques d'usurpation et de masquerade.
- **CICIoV2024** : trafic CAN de véhicule avec attaques (Canadian Institute for Cybersecurity).
- **SynCAN** (ETAS/Bosch) : jeu synthétique pour la détection d'anomalies.

Rendez-vous sur les sites des organismes pour les liens de téléchargement à jour et le format exact des fichiers :
adaptez `src/canids/importers.py` si votre version diffère.
