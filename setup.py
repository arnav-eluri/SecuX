from setuptools import setup, find_packages

setup(
    name="secux",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click>=8.0.0",
        "python-dotenv>=1.0.0",
        "rich>=13.0.0",
        "watchdog>=3.0.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "evtx": ["py-evtx>=0.4.0"],
        "google": ["google-generativeai>=0.4.0"],
    },
    entry_points={
        "console_scripts": [
            "secux=secux.cli:main",
        ],
    },
    python_requires=">=3.10",
)
