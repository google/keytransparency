Key Transparency
================
Key Transparency is a distributed implementation of
[CONIKS](https://eprint.iacr.org/2014/1004.pdf), written in Go.



Getting Started
===============

Getting Key Transparency
------------------------
This project uses [Google protocol buffers](https://github.com/golang/protobuf). 
The [instalation directions](https://github.com/golang/protobuf#installation) will get it setup. Alternativly, run the [prerequisites](./PREREQUISITES) script.

```sh
./prerequisites
```

Running a Key Transparency Cluster
----------------------------------
First install [goreman](https://github.com/mattn/goreman), which manages Procfile-based applications.

The [Procfile script](./Procfile) will set up a local cluster. Start it with:

```sh
goreman start
```


Projects Using Key Transparency
==================================
* [Google End-To-End](https://github.com/gdbelvin/end-to-end).

