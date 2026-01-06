# Projects

This folder contains the Python projects created with different package managers.

The projects have the same dependencies installed, which are:

| Name  | Version | Type | 
| ----- | ------- | ---- |
| numpy | Unversioned | Imported and used in the code |
| docopt | Pinned | Remote |
| black | Pinned | Remote from Git |
| seaborn | Pinned | Not used in the code |
| matplotlib | Constrained | Not used in the code |
| urllib3 | Unversioned | Not used in the code |
| nltk | Unversioned | Optional dependency |
| pytest | Unversioned | Development dependency |


The selected combination of front-end and back-end are:

| BE \ FE | Pip | Hatch | Pdm | Pipenv | Poetry |
| --- | --- | --- | --- | --- | --- |
| Hatchling | ✓ | ✓ | ✓ | - | - |
| Flit | - | - | ✓ | - | - |
| Pdm | ✓ | ✓ | ✓ | ✓ | - |
| Poetry | - | - | - | - | ✓ |
| Setuptools | ✓ | ✓ | ✓ | - | - |



## To reproduce it

1) Initialize the project according to the selected front-end.
2) Add the selected dependencies.
3) Add a main file with example code importing an installed
dependency, and using it.
4) Use the package manager to package the project in
a distributable wheel and a source tarball (to test the correctness of the project setup).

