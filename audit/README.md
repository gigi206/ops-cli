# Audits de la branche `ops-v2`

Deux revues complètes du crate `sbx` ont été conduites contre le **même arbre**, `ops-v2` à
`d717a05`, indépendamment l'une de l'autre et à un jour d'intervalle. Ce ne sont pas deux passes
successives : ce sont deux lectures parallèles, qui ne se sont pas coordonnées et ne recouvrent pas
le même périmètre.

| | [`ops-v2/`](ops-v2/) | [`ops-v2-n8w5jx/`](ops-v2-n8w5jx/) |
| --- | --- | --- |
| Branche | `claude/ops-v2-analysis-bn6uc6` | `claude/ops-v2-analysis-n8w5jx` |
| Écrit le | 2026-08-28 | 2026-08-27 |
| Fusionné dans `ops-v2` | oui (`fcdc36c`, `55fbd2d`) | **non** |
| Forme | six documents thématiques | un rapport d'un seul tenant |
| Retenu | 138 défauts, 44 constats de structure | 92 constats sur 108 évalués, 10 familles de duplication |
| Méthode | trois vagues d'analystes, un vérificateur par défaut relevé | quatre vagues plus un audit direct, une passe de réfutation sur la totalité |

Le second est versé ici alors que sa branche n'a jamais été fusionnée : sans cela, supprimer la
branche aurait effacé ses constats titrés, ses réfutations et le détail de son tiers LOW. Le
rapport y est à l'octet près, précédé d'un seul bloc de provenance ; ce que ses constats valent dans
l'arbre courant est dans [`ops-v2-n8w5jx/etat.md`](ops-v2-n8w5jx/etat.md), une ligne par constat,
avec la provenance de chaque verdict.

Les deux se contredisent sur un point, tranché par la mesure et écrit dans `etat.md` : la
réconciliation des gcroots d'outils `nix:`. Le premier la corrige dans `nixhub.rs`, le second
objecte qu'elle supprimerait des roots vivants. L'objection est juste, mais elle vise `gc.rs` et
n'atteint pas le site que le premier corrige.

Ces documents décrivent l'arbre tel qu'il était à `d717a05`. Ils ne sont pas maintenus : un constat
qu'ils décrivent peut avoir été fermé depuis, et `etat.md` est le seul des trois à répondre de
l'arbre courant.
