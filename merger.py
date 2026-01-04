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
    imports: Package
    imported: Package
    
@dataclass(eq=True, frozen=True)
class DependencyGraph():
    packages: list[Package] = field(default_factory=list)
    import_statements: list[ImportStatement] = field(default_factory=list)

    def insert_package(self, package_name: str) -> Package:
        new_package = Package(package_name)
        self.packages.append(new_package)

        return new_package

    def insert_importstatement(self, imports: Package, imported: Package):
        new_importstatement = ImportStatement(imports, imported)
        self.import_statements.append(new_importstatement)

        return new_importstatement

@dataclass
class PackageAnalysis:
    source_path: str | list[str]
    graphs: dict[str, DependencyGraph]
    raw_packages_from_metadata: list[str]

@dataclass
class Dataset:
    package_analyses: dict[str, PackageAnalysis] = field(default_factory=dict)

def generate_ds1():
    packages = os.listdir(os.path.join(DS1_PATH, "packages"))
    dataset = Dataset()

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
        
        dataset.package_analyses[package] = PackageAnalysis(
            source_path=os.path.join(DS1_PATH, "packages", package, "src", package, "main.py"),
            raw_packages_from_metadata=raw_requirements,
            graphs=import_ds1_sboms(os.path.join(DS1_PATH, "sbom"), package)
        )
        

    with open("merged_ds1.json", "w") as json_file:
        json_file.write(
           json.dumps(asdict(dataset))
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
            start = str(child.ref.value).find("/") + 1
            end = str(child.ref.value).find("@")
            if end == -1: end = None

            child_package = graph.insert_package(child.ref.value[start:end])
            if len(child.dependencies) > 0:
                extract_dependencies(child.dependencies, child_package, graph)

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