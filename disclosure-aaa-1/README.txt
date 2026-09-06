Merkl disclosure
================

Action:   aaa-1
Session:  sess-1
Scope:    session sess-1 is not sealed yet; level 1 only

Open verify.html in any browser. It works offline; nothing in it calls home.
Drop evidence.jsonl on the page to check the raw record against the hashes
committed in the tree.

Prefer a terminal? `pip install merkl-sdk && merkl verify verify.html` runs the
same checks in a second implementation, and bundle.json is the raw data both
of them read.
