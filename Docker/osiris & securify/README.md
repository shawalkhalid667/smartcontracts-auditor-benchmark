To access the container after building: docker run -it --entrypoint /bin/bash [image name]

To evaluate a contract while inside the container with Osiris, run:

python3.7 osiris/osiris.py -s [path to file]



To evaluate a contract while inside the container with Securify, run:

securify [path to file]
