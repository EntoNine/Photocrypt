
![Logo](photo-crypt.png)

# Photocrypt

Encrypt file into images, made in python 

Here's how it works

![Diagram](photocrypt.svg)

How to compile on linux using pyinstaller:

1. Install pyinstaller
```bash
pip install pyinstaller

```

2. Compile using pyinstaller (Replace [APP] by the filename)
```bash
pyinstaller --noconfirm --onefile --windowed --strip     --exclude-module PyQt6.Qt3D     --exclude-module PyQt6.QtQuick     --exclude-module PyQt6.QtNetwork     --exclude-module PyQt6.QtQml     --exclude-module PyQt6.QtSql     --exclude-module PyQt6.QtTest     --exclude-module PyQt6.QtXml     --exclude-module PyQt6.QtWebEngineCore     [APP].py

```
