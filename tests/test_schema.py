import json, os, glob
from jsonschema import Draft7Validator

def test_manifest_schema_if_samples():
    if not os.path.exists('schemas/manifest.schema.json'):
        return
    files = glob.glob('samples/*manifest*.json')
    if not files:
        return
    sch = json.load(open('schemas/manifest.schema.json', 'r', encoding='utf-8'))
    v = Draft7Validator(sch)
    for f in files:
        doc = json.load(open(f, 'r', encoding='utf-8'))
        errs = list(v.iter_errors(doc))
        assert not errs, f"Schema errors in {f}: " + "; ".join(e.message for e in errs)
