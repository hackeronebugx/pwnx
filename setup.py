from setuptools import setup, find_packages

setup(
    name="pwnx",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.24.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "jinja2>=3.1.0",
    ],
    extras_require={
        "ai": ["torch>=2.0.0"],
        "headless": ["playwright>=1.35.0"],
        "dev": ["pytest>=7.0.0", "black>=23.0.0", "mypy>=1.0.0"],
        "all": ["torch>=2.0.0", "playwright>=1.35.0"],
    },
    entry_points={
        "console_scripts": [
            "pwnx=pwnx.cli:main",
        ],
    },
    python_requires=">=3.10",
    author="PwnX Team",
    description="AI-Augmented XSS Hunter",
    license="MIT",
)
