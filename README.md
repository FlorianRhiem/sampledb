# SampleDB
[![build status](https://iffgit.fz-juelich.de/Scientific-IT-Systems/SampleDB/badges/master/build.svg)](https://iffgit.fz-juelich.de/Scientific-IT-Systems/SampleDB/commits/master) [![coverage report](https://iffgit.fz-juelich.de/Scientific-IT-Systems/SampleDB/badges/master/coverage.svg)](https://iffgit.fz-juelich.de/Scientific-IT-Systems/SampleDB/commits/master)

SampleDB is a web-based sample and measurement metadata database developed at PGI and JCNS.

## Documentation

You can find the documentation for the current release at https://scientific-it-systems.iffgit.fz-juelich.de/SampleDB/.

## Getting Started

To use locally simply install the dependencies via

```
pip install -r requirements.txt
```

and then run

```
python -m sampledb run
```

This will start a server at [http://localhost:8000](http://localhost:8000). You can also run `python demo.py` for some pre-existing instruments, actions and samples.
