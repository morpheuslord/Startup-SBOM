# Third-party data notices

The JSON files in this directory are compact derivatives built by
`tools/build_threat_data.py` from the public datasets below. They are shipped so
threat analysis works fully offline. Each dataset's required copyright and
license statement is reproduced here as a condition of that use.

## MITRE CWE™ — `cwe.json`

CWE™ is free to use by any organization or individual for any research,
development, and/or commercial purposes, per the CWE Terms of Use. The MITRE
Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to
use CWE for research, development, and commercial purposes. Any copy you make
for such purposes is authorized on the condition that you reproduce MITRE's
copyright designation and this license in any such copy.

CWE is a trademark of The MITRE Corporation.

Source: <https://cwe.mitre.org/> — Terms of Use:
<https://cwe.mitre.org/about/termsofuse.html>

## MITRE CAPEC™ — `capec_attack.json`

The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free
license to use Common Attack Pattern Enumeration and Classification (CAPEC™) for
research, development, and commercial purposes. Any copy you make for such
purposes is authorized provided that you reproduce MITRE's copyright designation
and this license in any such copy.

Copyright © 2007–2026, The MITRE Corporation. CAPEC and the CAPEC logo are
trademarks of The MITRE Corporation.

Source: <https://capec.mitre.org/> — Terms of Use:
<https://capec.mitre.org/about/termsofuse.html>

## MITRE ATT&CK® — `attack_techniques.json`

The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free
license to use ATT&CK® for research, development, and commercial purposes. Any
copy you make for such purposes is authorized provided that you reproduce
MITRE's copyright designation and this license in any such copy.

"© 2026 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation."

MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.

Source: <https://attack.mitre.org/> — Terms of Use:
<https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>

## Center for Threat-Informed Defense — `kev_attack.json`

`kev_attack.json` is derived from two projects of the Center for Threat-Informed
Defense (CTID), both licensed under the Apache License, Version 2.0:

- Mappings Explorer (CISA KEV → ATT&CK):
  <https://github.com/center-for-threat-informed-defense/mappings-explorer>
- ATT&CK to CVE methodology and mappings:
  <https://github.com/center-for-threat-informed-defense/attack_to_cve>

Copyright © The MITRE Corporation / Center for Threat-Informed Defense.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
these files except in compliance with the License. You may obtain a copy of the
License at <http://www.apache.org/licenses/LICENSE-2.0>. Unless required by
applicable law or agreed to in writing, software distributed under the License
is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. These works reproduce and build upon MITRE
ATT&CK® (see the ATT&CK notice above).

## CISA SSVC decision tables

The SSVC decision logic in `startup_sbom.threat.ssvc` reproduces the CISA
Coordinator decision table from the CERT/CC SSVC project (Apache License,
Version 2.0): <https://github.com/CERTCC/SSVC>.
