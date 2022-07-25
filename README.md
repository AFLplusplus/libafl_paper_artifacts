# LibAFL: A Framework for Modular and Reusable Fuzzers

The fuzzers/ folder contains the variants created for the paper and fuzzers/LibAFL contains the code of LibAFL.
The neodiff folder contains the NeoDiff code with the libafl-based implementation.
The fuzzbench/ folder contains a snapsot of the fuzzbench repository used in the evaluations with all the variants. Each dockerfile must be adapted by hand to point to a git repository serving the fuzzers/ folder as repository. The original links were removed for the double blind.

Individual experiments can then be runned using the local experiments https://google.github.io/fuzzbench/running-a-local-experiment.
