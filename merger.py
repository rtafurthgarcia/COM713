import sys
import os
import json
from cyclonedx.model.bom import Bom
import tomllib

DS1_PATH = os.path.join(".", "ds1")
DS2_PATH = os.path.join(".", "ds2")

def generate_template_ds1():
    def read_metadata(src: str) -> list[str]:
        return []

    template = {
        "packages": [
        ]
    }

    packages = os.listdir(os.path.join(DS1_PATH, "packages"))

    for package in packages: 
        template["packages"].append({
            "name": package, 
            "source": os.path.join(DS1_PATH, "packages", package, "src", package, "main.py"),
            "deps_from_metadata": read_metadata(os.path.join(DS1_PATH, "packages", package)),
            "deps_from_ast": []
        })

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

def import_ds1_sboms(src: str):
    tools = os.listdir(src)
    for tool in tools:
        packages = os.listdir(os.path.join(src, tool))

        for package in packages:
            with open(os.path.join(src, tool, package)) as input_json:
                deserialized_bom = Bom.from_json(data=json.loads(input_json.read()))

                print(deserialized_bom)
    
generate_template_ds1()
import_ds1_sboms(src=os.path.join(DS1_PATH, "sbom"))