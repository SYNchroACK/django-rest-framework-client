from setuptools import setup

setup(
    name='django-rest-framework-client',
    version='0.1.1',
    description='Python client for a Django Rest Framework',
    url='https://github.com/synchroack/django-rest-framework-client',
    author='SYNchroACK',
    author_email="synchroack@protonmail.ch",
    license='MIT',
    packages=[
        'rest_framework_client',
    ],
    install_requires=[
        'requests',
    ],
    keywords=[
        "django",
        "djangorestframework",
        "REST",
        "API",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    zip_safe=False
)