from setuptools import setup

APP = ['zzfw_mac.py']
DATA_FILES = []  #
OPTIONS = {
    'argv_emulation': True,
    'packages': ['flask','requests','gmssl','base64','re','json','urllib3','datetime']
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)