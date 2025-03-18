from setuptools import setup

APP = ['zzfw_mac.py']       # 入口文件
DATA_FILES = []         # 其他数据文件（如图片、配置文件）
OPTIONS = {
    'argv_emulation': True,
    'plist': {
        'CFBundleName': 'zzfw_mac',  # 应用名称
        'CFBundleVersion': '1.0',
        'CFBundleShortVersionString': '1.0',
    }
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)