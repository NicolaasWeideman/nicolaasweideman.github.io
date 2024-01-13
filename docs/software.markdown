---
layout: page
title: Software
permalink: /software/
---

* TOC
{:toc}

## Projects

### Binalyzer
[Binalyzer](https://github.com/usc-isi-bass/binalyzer) is an implementation of a [thread-pool](https://en.wikipedia.org/wiki/Thread_pool).
Mainly, it was created to facilitate running a binary program analysis on multiple targets (binary executables) concurrently.
Here are its key features:
1. Per-task timeouts - A time limit may be set such that each task that exceeds this limit will timeout. Subsequent and parallel tasks are unaffected. This is in contrast to Python's [multiprocessing.pool](https://docs.python.org/3/library/multiprocessing.html#module-multiprocessing.pool) where the time limit applies to the whole thread pool.
2. Intermediate results saved to disk - The results returned by each completed task, are stored to disk as [json-pickled](https://github.com/jsonpickle/jsonpickle) Python objects.
3. Progress tracking - Print how many tasks have been completed and an expected time remaining.
4. Target discovery - Point it to a directory and it will automatically search all subdirectories for ELF files. You can also give it a file containing the paths to ELF files.
5. Argument parser - You can use the Binalyzer argument parser as a parent to your own so you don't have to respecify the command line arguments specific to Binalyzer (number of processes to use, timeout duration, target root directory, etc).

## Open Source Contributions

### angr
[angr](https://github.com/angr/angr) is a framework allowing for programmatic reverse engineering via binary program analysis.
My contributions to angr include bug fixes and refactoring.
Here are the links to [Pull Requests](https://github.com/angr/angr/pulls?q=author%3ANicolaasWeideman), [Issues](https://github.com/angr/angr/issues?q=is%3Aissue+author%3ANicolaasWeideman) and [Commits](https://github.com/angr/angr/commits?author=NicolaasWeideman) I contributed to angr.

### Ghidra
[Ghidra](https://ghidra-sre.org/) is a reverse-engineering framework developed by the National Security Agency (NSA).
I extended Ghidra to allow for checking equality between Varnode abstract syntax trees and fixed the translation of PIC assembly to the P-code intermediate representation.
Here are the links to [Pull Requests](https://github.com/NationalSecurityAgency/ghidra/pulls?q=author%3ANicolaasWeideman), [Issues](https://github.com/NationalSecurityAgency/ghidra/issues?q=author%3ANicolaasWeideman) and [Commits](https://github.com/NationalSecurityAgency/ghidra/commits?author=NicolaasWeideman) I contributed to Ghidra.

### Stem
[Stem](https://stem.torproject.org/) is a Python wrapper library for [TOR](https://www.torproject.org/) and its control protocol.
I extended Stem to enable providing multiple client authentication keys when creating version 3 onion services.
Here are the links to [Pull Requests](https://github.com/torproject/stem/pulls?q=author%3ANicolaasWeideman), [Issues](https://github.com/torproject/stem/issues/created_by/NicolaasWeideman) and [Commits](https://github.com/torproject/stem/commits?author=NicolaasWeideman) I contributed to Stem.
