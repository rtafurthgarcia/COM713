import sys
import os
import json
import requirements
from cyclonedx.model.bom import Bom
from dataclasses import dataclass
from sortedcontainers import SortedSet

DS1_PATH = os.path.join(".", "ds1")
DS2_PATH = os.path.join(".", "ds2")

class Package:
    __slots__ = 'name'

    def __init__(self, name: str):
        """Do not call constructor directly. Use Graph s insert vertex(x)."""
        self.name = name

    def hash (self) -> int: # will allow vertex to be a map/set key
        return hash(id(self))

class ImportStatement():
    __slots__ = '_depends', '_depended_on', '_element'

    def __init__(self, depends: Package, depended_on: Package):
        self._depends = depends
        self._depended_on = depended_on

    def endpoints(self) -> tuple[Package, Package]:
        return (self._depends, self._depended_on)

    def hash(self) -> int: # will allow edge to be a map/set key
        return hash((self._depends, self._depended_on))
    
class DependencyGraph():
    def __init__(self) -> None:
        self._depends_on = {}
        self._depended_on = {}
    
    def packages(self):
        return self._depends_on.keys()

    def importstatements(self):
        """Return a set of all edges of the graph."""
        result = set( ) # avoid double-reporting edges of undirected graph
        for secondary_map in self._depends_on.values():
            result.update(secondary_map.values()) # add edges to resulting set
        
        return result
    
    def get_importstatement(self, depends: Package, depended_on: Package) -> ImportStatement | None:
        return self._depends_on[depends].get(depended_on) 
    
    def insert_package(self, package_name: str) -> Package:
        new_package = Package(package_name)

        self._depends_on[new_package] = {}
        self._depended_on[new_package] = {}

        return new_package

    def insert_importstatement(self, depends: Package, depended_on: Package):
        new_importstatement = ImportStatement(depends, depended_on)

        self._depends_on[depends][depended_on] = new_importstatement
        self._depends_on[depends][depended_on] = new_importstatement

        return new_importstatement

@dataclass
class PackageAnalysis:
    name: str
    source_path: str | list[str]
    raw_packages_from_metadata: list[str]
    graphs: dict[str, DependencyGraph]

def generate_ds1():
    data = []

    packages = os.listdir(os.path.join(DS1_PATH, "packages"))

    for package in packages: 
        requirements_path = os.path.join(os.path.join(DS1_PATH, "packages", package, "requirements.txt"))
        if not os.path.exists(requirements_path):
            continue
        
        raw_requirements = list()

        with open(requirements_path) as requirements_file:
            for req in requirements.parse(requirements_file):
                raw_requirements.append(req)
        
        data.append(
            PackageAnalysis(
                name=package,
                source_path=os.path.join(DS1_PATH, "packages", package, "src", package, "main.py"),
                raw_packages_from_metadata=raw_requirements,
                graphs=import_ds1_sboms(os.path.join(DS1_PATH, "sbom"), package)
            )
        )

        with open("merged_ds1.json", "w") as json_file:
            json_file.write(json.dumps(data))

ds2_template = {
    "packages": [
        {
            "name": "apprise",
            "source": os.path.join(DS2_PATH, "packages", "apprise", "apprise", "apprise.py"),
            "deps_from_metadata": [],
            "deps_from_ast": []
        },
        {
            "name": "django",
            "source": os.path.join(DS2_PATH, "packages", "django-rest-framework", "rest_framework"),
            "deps_from_metadata": [],
            "deps_from_ast": []
        },
    ]
}

def import_ds1_sboms(path: str, package: str) -> dict[str, DependencyGraph]:
    def extract_dependencies(
            dependencies: SortedSet, 
            parent_package: ImportStatement | None, 
            graph: DependencyGraph
    ):
        for dependency in dependencies:
            if len(dependency.dependencies) > 0:
                extract_dependencies(dependency.dependencies, dependency, graph) # type: ignore
            
            start = str(dependency.ref.value).find("/") + 1
            end = str(dependency.ref.value).find("@")
            if end == -1: end = None

            new_package = dependency.ref.value[start:end]

            #if graph.get_importstatement(package, new_package)
            graph.insert_package(dependency.ref.value[start:end])
    results = {}

    tools = os.listdir(path)
    for tool in tools:
        package_path = os.path.join(path, tool, package + "-result.json")

        with open(package_path) as input_json:
            deserialized_bom = Bom.from_json(data=json.loads(input_json.read())) # type: ignore

            graph = DependencyGraph()
            extract_dependencies(deserialized_bom.dependencies, graph) # type: ignore
            results[tool] = graph

    return results                 
    
generate_ds1()