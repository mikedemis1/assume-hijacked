"""The attack suite: probes that try every network edge the walls forbid (and the ones they must
allow), and the attack tickets replayed against the dispatcher contract.

Runtime code, standard library only (no YAML, no app imports): it runs in its own small image
(attacks/Dockerfile) as probe pods and as the chart's attack-suite test pods.
"""
