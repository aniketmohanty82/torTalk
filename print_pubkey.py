import argparse, base64, msgpack

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('ascii')

ap = argparse.ArgumentParser()
ap.add_argument("--id-path", required=True, help="path to identity .bin")
args = ap.parse_args()

with open(args.id_path, "rb") as f:
    ident = msgpack.unpackb(f.read(), raw=False)

enc_pk = ident["enc_pk"]
sig_pk = ident["sig_pk"]
addr = f"mesh:{b64(enc_pk)}.{b64(sig_pk)}"

print("address:", addr)
print("enc_pk: ", b64(enc_pk))
print("sig_pk: ", b64(sig_pk))
