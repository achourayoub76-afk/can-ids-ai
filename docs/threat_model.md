# Modèle de menace (simplifié)

## Contexte
Le bus CAN (ISO 11898) est un bus **à diffusion** : toute trame est reçue par tous les nœuds, sans
émetteur authentifié, sans chiffrement. L'arbitrage se fait par priorité d'identifiant (ID le plus bas = plus prioritaire).

## Points d'entrée typiques
Port OBD-II, unité multimédia/Bluetooth/Wi-Fi, module télématique (4G), clés/accessoires, ECU compromis.

## Attaques couvertes
| Attaque | Mécanisme | Effet | Signal exploité par l'IDS |
|---|---|---|---|
| DoS | trames d'ID très prioritaire en continu | saturation du bus, perte de messages légitimes | débit, entropie des ID, ID inconnu |
| Fuzzing | ID/payload aléatoires | comportements imprévisibles des ECU | ID inconnus, entropie, payload hors profil |
| Rejeu | ré-émission de trames légitimes capturées | actions passées rejouées (ex. déverrouillage) | rupture de cadence par ID |
| Usurpation | trames avec ID légitime et valeurs falsifiées | fausses mesures (régime, vitesse) | cadence doublée, payload hors profil |

## Hors périmètre (pour l'instant)
Suppression d'ECU (bus-off), attaques sur les couches supérieures (UDS, J1939), attaques « furtives »
qui imitent parfaitement cadence et valeurs, CAN FD.

## Limites d'un IDS comportemental
Sans authentification des messages (ex. SecOC), un IDS ne fait que **détecter** : il ne peut pas empêcher
l'injection. Il est complémentaire d'un filtrage par passerelle et de l'authentification.
