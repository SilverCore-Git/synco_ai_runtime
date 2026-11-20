#!/bin/sh
# Génère le profil seccomp Docker du Synco AI Runtime à partir du profil par défaut de moby
# (Apache-2.0, https://github.com/moby/moby, vendor/github.com/moby/profiles/seccomp/default.json) :
# le profil par défaut, plus UNE règle qui autorise, sans exiger CAP_SYS_ADMIN, les appels dont le
# bac à sable des workers a besoin (docs/plan/10-bac-a-sable.md §10) :
#   unshare, clone (drapeaux d'espaces de noms), mount, umount2, pivot_root, sethostname.
# `clone3` reste refusé en ENOSYS (repli de la glibc sur clone). Aucun autre appel n'est ajouté :
# ptrace, bpf, kexec, init_module… restent refusés. Le filtre propre du worker, bien plus strict,
# s'applique ensuite.
#
# Usage : make-seccomp.sh <default.json de moby> > seccomp-synco-ai-runtime.json
# (jq requis ; version de moby utilisée pour le fichier fourni : docker-v29.9.2.)
set -eu
jq '.syscalls += [{
  "names": ["unshare", "clone", "mount", "umount2", "pivot_root", "sethostname"],
  "action": "SCMP_ACT_ALLOW"
}]' "$1"
