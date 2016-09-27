# pip install itsdangerous
# python gen.py > testdata.json

import sys
import itsdangerous
import hashlib
import json

secret = "super secret 1"
salt = 'cookie-session'
serializer = json
digest_method = hashlib.sha1
signer_kwargs = dict(
    key_derivation='hmac',
    digest_method=digest_method
)
signer = itsdangerous.URLSafeSerializer(secret, salt=salt, serializer=serializer, signer_kwargs=signer_kwargs)

cases = []


obj = {"some_number": 1, "some_words": "Some short payload"}
cases.append({
    "Before": json.dumps(obj),
    "After": signer.dumps(obj)
})

obj = {"some_number": 2, "some_words": "Some long payload that will activate the zlib feature: Mixed in with a regular serializer it will attempt to zlib compress the string to make it shorter if necessary.  It will also base64 encode the string so that it can safely be placed in a URL."}
cases.append({
    "Before": json.dumps(obj),
    "After": signer.dumps(obj)
})


signer = itsdangerous.URLSafeTimedSerializer(secret, salt=salt, serializer=serializer, signer_kwargs=signer_kwargs)
obj = {"some_number": 3, "some_words": "Some TIMED short payload"}
cases.append({
    "Before": json.dumps(obj),
    "After": signer.dumps(obj),
    "IsTimed": True
})

obj = {"some_number": 4, "some_words": "Some TIMED long payload that will activate the zlib feature: Mixed in with a regular serializer it will attempt to zlib compress the string to make it shorter if necessary.  It will also base64 encode the string so that it can safely be placed in a URL."}
cases.append({
    "Before": json.dumps(obj),
    "After": signer.dumps(obj),
    "IsTimed": True
})

print(json.dumps(cases, indent=4))
