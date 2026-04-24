from c2pa import Builder, Signer

manifest = {
    "claim_generator": "seacell/0.1",
    "assertions": [
        {
            "label": "c2pa.actions",
            "data": {
                "actions": [{"action": "c2pa.created"}]
            }
        }
    ]
}

builder = Builder.from_json(manifest)

signer = Signer.from_files(
    cert_path="certs/cert.pem",
    key_path="certs/key.pem",
    alg="es256"
)

builder.sign_file(
    "rawPhoto.jpg",
    "signed.jpg",
    signer
)
