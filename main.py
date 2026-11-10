import io
import base64
import hashlib
import streamlit as st
import secrets
from PIL import ExifTags, Image
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#enc def
def make_key(password):
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def to_bits(data):
    return "".join(format(byte, "08b") for byte in data)

def to_bytes(bits):
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

#value & ~1 clears the last bit then | bit sets it to 0 or 1
def hide_bit(value, bit):
    return (value & ~1) | bit

def read_bits(pixels, start, count):
    return "".join(str(pixels[i] % 2) for i in range(start, start + count))

def encode_file(image_file, data_file, password):
    filename = data_file.name
    filecontent = data_file.getvalue()

    secret = filename.encode() + b"|" + filecontent

    if password:
        salt = secrets.token_bytes(16)
        token = Fernet(derive_key(password, salt)).encrypt(secret)
        body = b"SL2" + salt + token
        flag = "1"
    else:
        body = secret
        flag = "0"

    bits = flag + format(len(body), "032b") + to_bits(body)

    img = Image.open(image_file).convert("RGB")
    pixels = bytearray(img.tobytes())
    if len(bits) > len(pixels):
        raise ValueError("Sorry, the file is too big for this image. "
                         "Use a bigger image or a smaller file brochacho.")

    for i in range(len(bits)):
        pixels[i] = hide_bit(pixels[i], int(bits[i]))

    result = Image.frombytes("RGB", img.size, bytes(pixels))
    buffer = io.BytesIO()
    result.save(buffer, format="PNG")
    return buffer.getvalue()

#check if the image is encoded
def encodedimage(image_file):
    try:
        pixels = Image.open(image_file).convert("RGB").tobytes()
        flag = read_bits(pixels, 0, 1)
        length = int(read_bits(pixels, 1, 32), 2)
        if flag not in ("0", "1") or length == 0:
            raise ValueError
        if 33 + length * 8 > len(pixels):
            raise ValueError
        return flag == "1"
    except (OSError, ValueError):
        raise ValueError("No hidden data found in this image.")


def decode_file(image_file, password):
    img = Image.open(image_file).convert("RGB")
    pixels = img.tobytes()

    flag = read_bits(pixels, 0, 1)
    length = int(read_bits(pixels, 1, 32), 2)
    if 33 + length * 8 > len(pixels):
        raise ValueError("No hidden data found in this image.")

    body = to_bytes(read_bits(pixels, 33, length * 8))

    if flag == "1":
        if password == "":
            raise ValueError("This image is password protected. Enter the password.")
        try:
            if body.startswith(b"SL2"):
                salt = body[3:19]
                token = body[19:]
                payload = Fernet(derive_key(password, salt)).decrypt(token)
            else:
                payload = Fernet(make_key(password)).decrypt(body)
        except InvalidToken:
            raise ValueError("Yo wrong password, or no hidden data in this image.")
    else:
        payload = body

    if b"|" not in payload:
        raise ValueError("No hidden data found in this image.")

    name, data = payload.split(b"|", 1)
    return name.decode(errors="replace"), data

def comparelsb(originalfile, encodedfile):
    original = Image.open(originalfile).convert("RGB")
    encoded = Image.open(encodedfile).convert("RGB")
    if original.size != encoded.size:
        raise ValueError("Images must be the same size for comparison.")
    difference=Image.new("L", original.size)
    original_pixels=original.load()
    encoded_pixels=encoded.load()
    difference_pixels=difference.load()
    for y in range(original.height):
        for x in range(original.width):
            original_pixel=original_pixels[x, y]
            encoded_pixel=encoded_pixels[x, y]
            red_changed=(original_pixel[0]&1) != (encoded_pixel[0]&1)
            green_changed=(original_pixel[1]&1) != (encoded_pixel[1]&1)
            blue_changed=(original_pixel[2]&1) != (encoded_pixel[2]&1)
            if red_changed or green_changed or blue_changed:
                difference_pixels[x, y] = 255
            else:
                difference_pixels[x, y] = 0
    return difference

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)

st.set_page_config(
    page_title="Stego Image Tool",
    layout="wide",
    initial_sidebar_state="expanded",
)

#cpg=current page
if 'cpg' not in st.session_state:
    st.session_state.cpg = 'Encode & Decode'

#style for stMain & stSidebar
st.markdown(
    """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&family=Space+Mono:wght@400;700&display=swap');

        [data-testid="stMain"] { background: #0f1017; }
        [data-testid="stHeader"] { background: transparent; }

        [data-testid="stMain"] :is(p, label, li, input, textarea, button, small) {
            font-family: 'Space Mono', monospace !important;
            line-height: 1.6 !important;
        }
        [data-testid="stMain"] :is(p, label, li) { color: #f3f4f6 !important; }

        [data-testid="stMain"] :is(h1, h2, h3) {
            font-family: 'Press Start 2P', monospace !important;
            font-size: 0.95rem !important;
            line-height: 1.6 !important;
            text-transform: uppercase;
            color: #ffffff !important;
        }

        [data-testid="stCaptionContainer"] * { color: #9ca3af !important; }

        .hero { text-align: center; padding: 1.5rem 0 1rem; }
        .hero-label {
            font-family: 'Press Start 2P', monospace;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: #be185d;
        }
        .hero-title {
            font-family: 'Press Start 2P', monospace;
            font-size: 1.6rem;
            line-height: 1.5;
            text-transform: uppercase;
            color: #ffffff;
            margin: 1.2rem 0;
        }
        .hero-sub {
            font-family: 'Space Mono', monospace;
            font-size: 1rem;
            line-height: 1.8;
            color: #9ca3af;
            max-width: 620px;
            margin: 0 auto;
        }

        .st-key-enc_card, .st-key-dec_card {
            background: #171820;
            border: 1px solid #2f3140;
            border-radius: 8px;
            padding: 1.5rem;
        }

        [data-testid="stFileUploaderDropzone"] {
            background: #22232d;
            border: 1px dashed #4b4d60;
            border-radius: 8px;
        }
        [data-testid="stFileUploaderDropzone"] :is(span, small, p, div) { color: #d1d5db !important; }
        [data-testid="stFileUploaderDropzone"] button {
            background: #2f3140 !important;
            border: 1px solid #5b5e75 !important;
            border-radius: 8px !important;
        }
        [data-testid="stFileUploaderDropzone"] button:hover {
            background: #3a1428 !important;
            border-color: #be185d !important;
        }
        [data-testid="stFileUploaderDropzone"] button :is(p, span, svg) {
            color: #ffffff !important;
            fill: #ffffff !important;
        }

        [data-testid="stMain"] [data-baseweb="input"],
        [data-testid="stMain"] [data-baseweb="base-input"] {
            background: #22232d !important;
            border: 1px solid #4b4d60 !important;
            border-radius: 8px !important;
        }
        [data-testid="stMain"] [data-baseweb="input"]:hover,
        [data-testid="stMain"] [data-baseweb="input"]:focus-within {
            border-color: #be185d !important;
            background: #2b1a26 !important;
        }
        [data-testid="stMain"] [data-baseweb="input"] input {
            color: #ffffff !important;
            -webkit-text-fill-color: #ffffff !important;
            caret-color: #ffffff !important;
        }
        [data-testid="stMain"] [data-baseweb="input"] button { background: transparent !important; }
        [data-testid="stMain"] [data-baseweb="input"] button svg {
            color: #d1d5db !important;
            fill: #d1d5db !important;
        }

        [data-testid="stMain"] :is(.stButton, .stDownloadButton) button {
            background: #2f3140;
            border: 1px solid #5b5e75;
            border-radius: 6px;
        }
        [data-testid="stMain"] :is(.stButton, .stDownloadButton) button:hover {
            background: #be185d;
            border-color: #be185d;
        }
        [data-testid="stMain"] :is(.stButton, .stDownloadButton) button p { color: #ffffff !important; }

        [data-testid="stMainBlockContainer"], .block-container {
        padding-top: 1rem !important;
        padding-bottom: 0.5rem !important;
        }

        .hero { padding: 2.0rem; }
        .hero-label { font-size: 0.8rem; }
        .hero-title { font-size: 1.3rem; margin: 0.6rem 0; }
        .hero-sub { font-size: 0.85rem; line-height: 1.3; }

        .st-key-enc_card, .st-key-dec_card {
            padding: 1.3rem;
            gap: 1.5rem !important;
        }

        [data-testid="stMain"] :is(h1, h2, h3) { padding: 0 !important; margin: 0 !important; }

        [data-testid="stFileUploaderDropzone"] { padding: 0.8rem 0.75rem; }
        [data-testid="stMain"] [data-testid="stWidgetLabel"] { margin-bottom: 0 !important; }

        [data-testid="stSidebar"] {
            background: url("https://i.pinimg.com/736x/fd/b0/38/fdb038ec1ea7e57377f4e81b186aeb5c.jpg") center / cover;
        }
        [data-testid="stSidebar"] :is(h1, h2, h3, p, label, li) {
            font-family: 'Press Start 2P', monospace !important;
            line-height: 1.8 !important;
        }
        [data-testid="stSidebar"] :is(p, label, li) { font-size: 0.7rem !important; }
        [data-testid="stSidebar"] h1 { font-size: 1.3rem !important; }

        [data-testid="stMain"] [data-baseweb="input"],
        [data-testid="stMain"] [data-baseweb="base-input"] {
            background: #ffffff !important;
            border: 1px solid #d1d5db !important;
            border-radius: 8px !important;
        }
        [data-testid="stMain"] [data-baseweb="input"]:hover,
        [data-testid="stMain"] [data-baseweb="input"]:focus-within {
            border-color: #be185d !important;
            background: #fdf2f8 !important;
        }
        [data-testid="stMain"] [data-baseweb="input"] input {
            color: #1f2029 !important;
            -webkit-text-fill-color: #1f2029 !important;
        }
        [data-testid="stMain"] [data-baseweb="input"] button {
            background: transparent !important;
        }
        [data-testid="stMain"] [data-baseweb="input"] button svg {
            color: #6b7280 !important;
            fill: #6b7280 !important;
        }

        [data-testid="stFileUploaderDropzone"] button {
            background: #ffffff !important;
            border: 1px solid #d1d5db !important;
            border-radius: 8px !important;
        }
        [data-testid="stFileUploaderDropzone"] button:hover {
            background: #fdf2f8 !important;
            border-color: #be185d !important;
        }
        [data-testid="stFileUploaderDropzone"] button :is(p, span, svg) {
            color: #1f2029 !important;
            fill: #1f2029 !important;
        }
        
        /* image analysis card upload box space */
        .st-key-analysis_card [data-testid="stWidgetLabel"] {
        margin-bottom: 0.8rem !important;
        }
    </style>
    """,
    unsafe_allow_html=True
)

#sidebar
with st.sidebar:
    st.markdown(
        "<h1 style='color: white; -webkit-text-stroke: 0.5px black; "
        "font-weight: bold;'>Menu Selection</h1>",
        unsafe_allow_html=True
    )
    st.divider()
    if st.button("Image Stego", use_container_width=True):
        st.session_state.cpg = "Encode & Decode"
    if st.button("LSB Comparison", use_container_width=True):
        st.session_state.cpg = "LSB Comparison"
    if st.button("File Forensic", use_container_width=True):
        st.session_state.cpg = "File Forensic"

#page title
page_info = {
    "Encode & Decode": (
        "Image Stego",
        "Hide & Reveal Files",
        "Hide a secret file inside an image or extract decoded file."
    ),
    "LSB Comparison": (
        "LSB Comparison",
        "Compare LSB Changes",
        "Compare an original image with its encoded version. White marks pixels where at least one color-channel LSB changed."
    ),
    "File Forensic": (
        "File Forensic",
        "Inspect the File",
        "Inspect file headers & metadata"
    ),
}
label, title, subtitle = page_info[st.session_state.cpg]

st.markdown(
    f"""
    <div class="hero">
        <div class="hero-label">{label}</div>
        <div class="hero-title">{title}</div>
        <div class="hero-sub">{subtitle}</div>
    </div>
    """,
    unsafe_allow_html=True
)

if st.session_state.cpg == "Encode & Decode":
    col_encode, col_decode = st.columns(2, gap='medium')

#encode section
    with col_encode:
        with st.container(key="enc_card"):
            st.subheader('Encode')
            upimage = st.file_uploader("1. Upload Image to Encode",
                                       type=None,
                                       key="encode_image")
            upfile = st.file_uploader("2. Upload Secret File",
                                      type=None,
                                      key="encfile")
            usepwd = st.checkbox("Protect with a password", value=True, key="usepwd")
            encpwd = ""
            if usepwd:
                encpwd = st.text_input("3. Enter Password to Encode",
                                       type="password",
                                       key="encpwd")

            if st.button("Encode File", key="encbtn", use_container_width=True):
                st.session_state.enc_out=None
                if upimage is None:
                    st.error("Please upload an image file.")
                elif Path(upimage.name).suffix.lower()not in {".png", ".bmp", ".jpg", ".jpeg"}:
                    st.error("Sorry, format not supported. Use PNG, BMP, JPG, JPEG only.")
                elif upfile is None:
                    st.error("Please upload the secret file.")
                elif Path(upfile.name).suffix.lower() not in {".txt", ".pdf", ".docx", ".csv"}:
                    st.error("Sorry, that file format is not supported. Use TXT, PDF, DOCX, or CSV.")
                elif usepwd and not encpwd:#if pwd protection is on and the pwd box is empty, show error
                    st.error("Please enter a password or unchecked the password protection box.")
                else:
                    try:
                        st.session_state.enc_out=encode_file(upimage,upfile,encpwd)
                    except(OSError,ValueError) as error:
                        st.error(str(error))

            if st.session_state.get("enc_out"):
                st.success("Secret file successfully hidden inside the image.")
                st.image(st.session_state.enc_out, caption="encoded image")
                st.download_button(
                    label="Download encoded image",
                    data=st.session_state.enc_out,
                    file_name="encoded.png",
                    mime="image/png",
                    use_container_width=True
                )

#decode section
    with col_decode:
        with st.container(key="dec_card"):
            st.subheader('Decode')

            def reset_decode_state():
                st.session_state.decodepassfield = False
                st.session_state.pop("dec_out", None)

            dupimage = st.file_uploader(
                "1. Upload Image",
                type=['png', 'bmp', 'jpg', 'jpeg'],
                key="decimg",
                on_change=reset_decode_state
            )

            decpwd = ""
            if st.session_state.get("decodepassfield", False):
                decpwd = st.text_input(
                    "2. Enter File Password",
                    type="password",
                    key="decpwd"
                )

            if st.button("Decode File", key="decbtn", use_container_width=True):
                st.session_state.dec_out = None

                if dupimage is None:
                    st.error("Upload an image first")

                elif st.session_state.get("decodepassfield", False):
                    if decpwd == "":
                        st.error("Please enter the password")
                    else:
                        try:
                            st.session_state.dec_out = decode_file(dupimage, decpwd)
                            st.session_state.decodepassfield = False
                        except ValueError as error:
                            st.error(str(error))

                else:
                    try:
                        protected = encodedimage(dupimage)
                        if protected:
                            st.session_state.decodepassfield = True
                            st.rerun()
                        else:
                            st.session_state.dec_out = decode_file(dupimage, "")
                            st.session_state.decodepassfield = False
                    except ValueError as error:
                        st.session_state.decodepassfield = False
                        st.error(str(error))

            if st.session_state.get("dec_out"):
                name, data = st.session_state.dec_out

                st.success(f"Extracted successfully: {name}")

                st.download_button(
                    label="Download hidden file",
                    data=data,
                    file_name=name,
                    use_container_width=True
                )

#LSB section
elif st.session_state.cpg == "LSB Comparison":
    left, right = st.columns([1, 3], gap="large")

    with left:
        lsbclick = st.button("View LSB Changes", key="btnlsb", use_container_width=True)

    with right:
        alimage = st.file_uploader(
            "Upload Original Image",
            type=["png", "jpg", "jpeg"],
            key="lsb_original_image",
            width=500,
        )

        encoded_image = st.file_uploader(
            "Upload Encoded Image",
            type=["png", "jpg", "jpeg"],
            key="lsb_encoded_image",
            width=500,
        )

        if lsbclick:
            if alimage is None or encoded_image is None:
                st.error("Please upload both original and encoded images.")
            else:
                try:
                    difference = comparelsb(alimage, encoded_image)
                    st.image(
                        difference,
                        caption="White = Changed Pixels, Black = Unchanged Pixels",
                        width=500
                    )
                except ValueError as error:
                    st.error(str(error))

elif st.session_state.cpg == "File Forensic":
    uploaded_image = st.file_uploader(
        "Upload Image to inspect",
        type=["png", "jpg", "jpeg", "bmp"],
        key="forensic_img",
    )

    if uploaded_image is not None:
        image = Image.open(uploaded_image)

        st.write(f"File name: {uploaded_image.name}")
        st.write(f"Detected format: {image.format}")
        st.write(f"Dimensions: {image.width} x {image.height}")
        st.write(f"Color mode: {image.mode}")
        st.write(f"File size: {len(uploaded_image.getvalue())} bytes")

        extension=Path(uploaded_image.name).suffix.lower()
        expected_format = {
            ".png": "PNG",
            ".jpg": "JPEG",
            ".jpeg": "JPEG",
            ".bmp": "BMP"
        }.get(extension)

        if expected_format==image.format:
            st.success(f"File format matches the extension")
        else:
            st.warning(f"File format does not match the extension")

        st.markdown(
            "<span style='color: #FF9708;'>EXIF Metadata</span>",
            unsafe_allow_html=True
        )

        exif_data=image.getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name=ExifTags.TAGS.get(tag_id, str(tag_id))
                st.write(f"{tag_name}: {value}")
        else:
            st.info("No EXIF metadata found in this image.")

        header=uploaded_image.getvalue()[:8]
        st.write(f"First 8 bytes: {header.hex(' ')}")

        signatures = {
            "PNG": b"\x89PNG\r\n\x1a\n",
            "JPEG": b"\xff\xd8\xff",
            "BMP": b"BM",
        }

        signature = signatures.get(image.format)

        if signature and uploaded_image.getvalue().startswith(signature):
            st.success("The file header matches the detected format.")
        else:
            st.warning("The file header did not match a known signature.")
