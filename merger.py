import sys
import os
import json
import requirements
from cyclonedx.model.bom import Bom
from dataclasses import dataclass, asdict, field
from sortedcontainers import SortedSet

DS1_PATH = os.path.join(".", "ds1")
DS2_PATH = os.path.join(".", "ds2")

@dataclass(eq=True, frozen=True)
class Package():
    name: str

@dataclass(eq=True, frozen=True)
class ImportStatement():
    depends: Package
    depended_on: Package

    def endpoints(self) -> tuple[Package, Package]:
        return (self.depends, self.depended_on)
    
class DependencyGraph():
    depends_on: dict[Package, dict[Package, ImportStatement]] = field(default_factory=dict)
    depended_on: dict[Package, dict[Package, ImportStatement]] = field(default_factory=dict)
    
    def packages(self):
        return self.depends_on.keys()

    def importstatements(self):
        """Return a set of all edges of the graph."""
        result = set( ) # avoid double-reporting edges of undirected graph
        for secondary_map in self.depends_on.values():
            result.update(secondary_map.values()) # add edges to resulting set
        
        return result
    
    def get_importstatement(self, depends: Package, depended_on: Package) -> ImportStatement | None:
        return self.depends_on[depends].get(depended_on) 
    
    def insert_package(self, package_name: str) -> Package:
        new_package = Package(package_name)

        self.depends_on[new_package] = {}
        self.depended_on[new_package] = {}

        return new_package

    def insert_importstatement(self, depends: Package, depended_on: Package):
        new_importstatement = ImportStatement(depends, depended_on)

        self.depends_on[depends][depended_on] = new_importstatement
        self.depended_on[depended_on][depends] = new_importstatement
        
        return new_importstatement
    
    def to_json(self):
        return {
            pkg.name: [dep.name for dep in deps.keys()]
            for pkg, deps in self.depends_on.values()
        }

@dataclass
class PackageAnalysis:
    name: str
    source_path: str | list[str]
    raw_packages_from_metadata: list[str]
    graphs: dict[str, DependencyGraph]

@dataclass
class Dataset:
    package_analyses: list[PackageAnalysis]

def generate_ds1():
    packages = os.listdir(os.path.join(DS1_PATH, "packages"))
    dataset = Dataset(list())

    for package in packages: 
        requirements_path = os.path.join(os.path.join(DS1_PATH, "packages", package, "requirements.txt"))
        if not os.path.exists(requirements_path):
            continue
        
        raw_requirements = list()

        with open(requirements_path) as requirements_file:
            for req in requirements.parse(requirements_file):
                if (req.name is None):
                    raw_requirements.append(req.line)
                else:
                    raw_requirements.append(req.name)
        
        dataset.package_analyses.append(PackageAnalysis(
            name=package,
            source_path=os.path.join(DS1_PATH, "packages", package, "src", package, "main.py"),
            raw_packages_from_metadata=raw_requirements,
            graphs=import_ds1_sboms(os.path.join(DS1_PATH, "sbom"), package)
        ))
        

    with open("merged_ds1.json", "w") as json_file:
        json_file.write(
           json.dumps({
                "package_analyses": [
                    {
                        "name": pa.name,
                        "source_path": pa.source_path,
                        "raw_packages_from_metadata": pa.raw_packages_from_metadata,
                        "graphs": {
                            k: v.to_json() for k, v in pa.graphs.items()
                        }
                    }
                    for pa in dataset.package_analyses
                ]
            })
        )

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
            child_packages: SortedSet, 
            parent_package: Package | None, 
            graph: DependencyGraph
    ):
        for child in child_packages:
            if len(child.dependencies) > 0:
                extract_dependencies(child.dependencies, parent_package, graph) # type: ignore
            
            start = str(child.ref.value).find("/") + 1
            end = str(child.ref.value).find("@")
            if end == -1: end = None

            child_package = graph.insert_package(child.ref.value[start:end])
            if (parent_package is not None):
                graph.insert_importstatement(child_package, parent_package)
    results = {}

    tools = os.listdir(path)
    for tool in tools:
        package_path = os.path.join(path, tool, package + "-result.json")

        with open(package_path) as input_json:
            deserialized_bom = Bom.from_json(data=json.loads(input_json.read())) # type: ignore

            graph = DependencyGraph()
            extract_dependencies(deserialized_bom.dependencies, None, graph) # type: ignore
            results[tool] = graph

    return results                 
    
generate_ds1()