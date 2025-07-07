To access the Docker container after building, run:

docker run -it --entrypoint /bin/bash [image name]

To use the tool, run:
smartcheck -p [path to contract]


NOTE: SmartCheck fails silently. If the contract fails to compile using SmartCheck's solidity compiler, you won't get any output (besides a bunch of dependency warnings). It does work with the provided contract.sol file.



