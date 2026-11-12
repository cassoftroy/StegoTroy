# StegoTroy

StegoTroy is a web app that hides a secret file inside an image using least significant bit (LSB) steganography. 
It was built with Python and Streamlit as a small learning project.

# Video Demo


https://github.com/user-attachments/assets/cbc04380-fabd-4789-8f77-94f7c62a2bc7



## Features

- **Image Stego:** hide a file inside an image and extract it later
- **Password protection:** optional encryption using Fernet with a PBKDF2 key
- **LSB Comparison:** compare an original and an encoded image to see which pixels changed
- **File Forensic:** check an image's format, header, dimensions and EXIF metadata

## Run it locally

```
git clone https://github.com/cassoftroy/StegoTroy.git
cd StegoTroy
pip install -r requirements.txt
streamlit run main.py
```

## Disclaimer

This project is for educational purposes only.

## Author

Made by cassoftroy.
