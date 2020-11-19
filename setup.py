import setuptools

from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

requires = []
with open('requirements.txt') as requirementstxt:
    for line in requirementstxt:
        requires.append(line)

setuptools.setup(
  name = 'awstools',
  scripts=['awstools', 'awsh'],
  version = '2020.11.13',
  author = 'Jordi Prats',
  author_email = 'jprats@systemadmin.es',
  description = 'AWS ssh',
  long_description=long_description,
  long_description_content_type='text/markdown',
  url = 'https://github.com/jordiprats/python-awsh',
  install_requires=requires,
  license="Apache License 2.0",
  classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
  ],
)
