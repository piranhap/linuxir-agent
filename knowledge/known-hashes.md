# Known-hash baseline

A small bundled baseline of file hashes the IR-expert flags during enrichment. This is a
starter set — extend it from your own threat intel. The machine-readable copy the code
loads lives in `linuxir/adapters/intel.py` (`KNOWN_BAD_HASHES`); keep the two in sync.

## Known-bad (illustrative)
| sha256 | label |
|---|---|
| e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | (empty file — placeholder, never malicious) |
| 44d88612fea8a8f36de82e1278abb02f… (EICAR md5) | EICAR test file |

> Real malware hashes belong here as you collect them; the empty-file/EICAR rows are only
> wiring examples so the lookup path is exercised without shipping live malware indicators.
