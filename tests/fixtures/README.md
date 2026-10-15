# Test fixtures

Captured from real tool/API runs (unmodified):

- `subfinder_v2.17.0_all_sources_failed.stderr` — `subfinder -d example.com -oJ -nc -stats`
  in a network-restricted sandbox: every attempted source errored, exit code 0.
- `theharvester_5.0.0_sources_failed.{json,jsonl}` — `theHarvester -d example.com
  -b crtsh,hackertarget,rapiddns,otx,certspotter -f result`: 4 sources `failed`
  (transport-error), certspotter `partial`, exit code 0.
- `google_cse_invalid_key.json` — Google Programmable Search response to a fake
  API key (HTTP 400, ErrorInfo reason `API_KEY_INVALID`). Contains no key.

Success/partial variants used in `tests/test_upstream.py` are *synthetic*,
built in the same formats; they are labelled as such in the tests.
