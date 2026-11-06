#!/usr/bin/env python3
"""Standalone fail-closed broker manifest/owner envelope verifier for main v2.

Candidate only. Production workflows remain unchanged until coordinated activation.
"""
from __future__ import annotations
import argparse
import base64
import json
import re
import sys
import time
from pathlib import Path
try:
    from .main_release_source import APP_COMMIT, APP_TREE
except ImportError:
    from main_release_source import APP_COMMIT, APP_TREE

OLD_COMMIT = "df195e6da70206bdd2e690507558a63eaa3705e5"
FIELDS = {
    "format","challenge","nonce","expires_at","preflight_run_id","broker_sha",
    "app_ref","old_commit","app_commit","app_tree","preflight_sha256",
    "content_sha256","archive_sha256"
}
SHA40=re.compile(r"[0-9a-f]{40}\Z")
SHA64=re.compile(r"[0-9a-f]{64}\Z")
RUN_ID=re.compile(r"[1-9][0-9]{0,19}\Z")
TOKEN=re.compile(r"[A-Za-z0-9_-]{32,128}\Z")

class Reject(ValueError):
    pass

def require(value:bool, reason:str)->None:
    if not value:raise Reject(reason)

def read_json(path:str)->dict:
    data=Path(path).read_bytes()
    require(len(data)<=16384,"input_too_large")
    def unique(pairs):
        d={}
        for k,v in pairs:
            require(k not in d,"duplicate_json_key")
            d[k]=v
        return d
    try: value=json.loads(data,object_pairs_hook=unique)
    except Reject:raise
    except (UnicodeError,ValueError):raise Reject("invalid_json") from None
    require(isinstance(value,dict),"json_object_required")
    return value

def canonical(value:dict)->bytes:
    return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()

def verify_manifest(m:dict,run_id:str,broker_sha:str, now:int|None=None)->bytes:
    require(set(m)==FIELDS and m.get("format")==2,"manifest_fields_or_version")
    require(isinstance(m["challenge"],str) and TOKEN.fullmatch(m["challenge"]) is not None,"challenge_invalid")
    require(isinstance(m["nonce"],str) and TOKEN.fullmatch(m["nonce"]) is not None,"nonce_invalid")
    current=int(time.time()) if now is None else now
    require(type(m["expires_at"]) is int and current<m["expires_at"]<=current+1800,"expired")
    require(isinstance(run_id,str) and RUN_ID.fullmatch(run_id) is not None and m["preflight_run_id"]==run_id,"run_id_mismatch")
    require(isinstance(broker_sha,str) and SHA40.fullmatch(broker_sha) is not None and m["broker_sha"]==broker_sha,"broker_sha_mismatch")
    require(m["app_ref"]=="main" and m["old_commit"]==OLD_COMMIT
            and m["app_commit"]==APP_COMMIT and m["app_tree"]==APP_TREE,"source_pin_invalid")
    for f in ("preflight_sha256","content_sha256","archive_sha256"):
        require(isinstance(m[f],str) and SHA64.fullmatch(m[f]) is not None,"digest_invalid")
    return canonical(m)

def verify_envelope(e:dict,m:dict,run_id:str,broker_sha:str)->None:
    require(set(e)=={"format","payload_b64","signature_b64"} and e.get("format")==2,"envelope_fields_invalid")
    try:
        payload=base64.b64decode(e["payload_b64"],validate=True)
        signature=base64.b64decode(e["signature_b64"],validate=True)
    except (ValueError,TypeError,KeyError):
        raise Reject("envelope_encoding_invalid") from None
    require(payload==verify_manifest(m,run_id,broker_sha),"envelope_payload_mismatch")
    require(64<=len(signature)<=16384,"signature_size_invalid")

def verify_run(run:dict,run_id:str,sha:str)->None:
    require(str(run.get("id"))==run_id,"run_id_invalid")
    require(run.get("event")=="workflow_dispatch","event_invalid")
    require(run.get("path")==".github/workflows/mmcrm-preflight.yml","workflow_invalid")
    require(run.get("head_branch")=="main" and run.get("head_sha")==sha,"broker_ref_invalid")
    require(run.get("conclusion")=="success","preflight_failed")
    require(isinstance(run.get("actor"),dict)
            and run["actor"].get("login")=="RogerPazzagliniCeo8earn","actor_invalid")

def main()->int:
    ap=argparse.ArgumentParser()
    mode=ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest",nargs=3,metavar=("PATH","RUN_ID","BROKER_SHA"))
    mode.add_argument("--envelope",nargs=4,metavar=("PATH","MANIFEST","RUN_ID","BROKER_SHA"))
    mode.add_argument("--run",nargs=3,metavar=("PATH","RUN_ID","BROKER_SHA"))
    args=ap.parse_args()
    try:
        if args.manifest:
            p,run_id,sha=args.manifest
            v=read_json(p)
            require(Path(p).read_bytes()==verify_manifest(v,run_id,sha),"manifest_not_canonical")
        elif args.envelope:
            p,manifest,run_id,sha=args.envelope
            v=read_json(manifest)
            require(Path(manifest).read_bytes()==verify_manifest(v,run_id,sha),"manifest_not_canonical")
            verify_envelope(read_json(p),v,run_id,sha)
        else:
            p,run_id,sha=args.run
            verify_run(read_json(p),run_id,sha)
        print("MMCRM_MAIN_V2_BROKER_GATE_OK")
        return 0
    except (Reject,OSError) as exc:
        print("MMCRM_MAIN_V2_REJECT reason="+str(exc),file=sys.stderr)
        return 1
if __name__=="__main__":
    raise SystemExit(main())
