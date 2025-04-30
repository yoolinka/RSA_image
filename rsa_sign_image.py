import subprocess
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PIL import Image, PngImagePlugin
import argparse
import os
from io import BytesIO

KEY_SIZE = 4096

def generate_rsa_keys():
    subprocess.run([
        "openssl", "genpkey", "-algorithm", "RSA",
        "-out", "private.pem", "-pkeyopt", f"rsa_keygen_bits:{KEY_SIZE}"
    ])
    subprocess.run([
        "openssl", "rsa", "-in", "private.pem",
        "-outform", "PEM", "-pubout", "-out", "public.pem"
    ])
    print("RSA keys generated: private.pem, public.pem")

def sign_image(image_path, private_key_path):
    from io import BytesIO

    img = Image.open(image_path)
    pnginfo = PngImagePlugin.PngInfo()

    buffer = BytesIO()
    img.save(buffer, format="PNG", pnginfo=pnginfo)
    image_bytes = buffer.getvalue()

    hash_obj = SHA256.new(image_bytes)

    with open(private_key_path, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    signature = pkcs1_15.new(private_key).sign(hash_obj)
    sig_hex = signature.hex()

    img_signed = Image.open(image_path)
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Signature", sig_hex)

    signed_path = f"signed_{os.path.basename(image_path)}"
    img_signed.save(signed_path, "PNG", pnginfo=metadata)
    print(f"Image signed and saved as: {signed_path}")

def verify_image(image_path, public_key_path):
    img = Image.open(image_path)

    if "Signature" not in img.info:
        print("No signature found in image metadata.")
        return

    signature = bytes.fromhex(img.info["Signature"])

    raw_img = img.copy()
    pnginfo = PngImagePlugin.PngInfo()
    buffer = BytesIO()
    raw_img.save(buffer, format="PNG", pnginfo=pnginfo)
    image_bytes = buffer.getvalue()

    hash_obj = SHA256.new(image_bytes)

    with open(public_key_path, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())

    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature verification failed.")

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("gen-keys", help="Generate RSA key pair")

    sign_parser = subparsers.add_parser("sign", help="Sign an image")
    sign_parser.add_argument("image", help="Path to the image")
    sign_parser.add_argument("private_key", help="Path to private.pem")

    verify_parser = subparsers.add_parser("verify", help="Verify image signature")
    verify_parser.add_argument("image", help="Signed image file")
    verify_parser.add_argument("public_key", help="Path to public.pem")

    args = parser.parse_args()

    if args.command == "gen-keys":
        generate_rsa_keys()
    elif args.command == "sign":
        sign_image(args.image, args.private_key)
    elif args.command == "verify":
        verify_image(args.image, args.public_key)

if __name__ == "__main__":
    main()

