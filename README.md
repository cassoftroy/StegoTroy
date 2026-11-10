# StegoTroy

StegoTroy is a web app that hides a secret file inside an image using least significant bit (LSB) steganography. 
It was built with Python and Streamlit as a small learning project.


## Features

- **Image Stego:** hide a file inside an image and extract it later
- **Password protection:** optional encryption using Fernet with a PBKDF2 key
- **LSB Comparison:** compare an original and an encoded image to see which pixels changed
- **File Forensic:** check an image's format, header, dimensions and EXIF metadata

## Supported files

| Type | Formats |
| --- | --- |
| Cover image | PNG, BMP, JPG, JPEG |
| Secret file | TXT, PDF, DOCX, CSV |
| Encoded output | PNG |

## Run it locally

```
git clone https://github.com/cassoftroy/StegoTroy.git
cd StegoTroy
pip install -r requirements.txt
streamlit run main.py
```

## Limitations

- The secret file must be small enough to fit in the image. Larger images can hold more data.
- LSB hiding is not hard to detect with analysis tools. Use a password if the content matters.

## Disclaimer

This project is for educational purposes only.

## Author

Made by cassoftroy.
